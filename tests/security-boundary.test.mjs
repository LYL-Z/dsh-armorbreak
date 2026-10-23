/**
 * Stage A security-boundary tests (v1.0.4).
 *
 * These prove the properties the review asked for, without contacting any
 * third-party network target: strict preset composition, request/activate
 * separation, path-form hardening, bounded pinned HTTP probes, container image
 * policy, and loopback-only state access.
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { link, mkdtemp, mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ScopePolicy, isUnsafePathForm } from '../lib/core/scope.js'
import { listDirectory, readFileBounded, searchFiles, statPath } from '../lib/core/files.js'
import liveManifest, { CONTAINER_IMAGE_ALLOWLIST, buildContainerArgs, validateContainerImage } from '../lib/analyzers/live/manifest.js'
import { createStateHandler } from '../index.js'

async function policy(options = {}) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-sec-policy-'))
  return new ScopePolicy({ stateRoot, ...options })
}

function fakeResponse() {
  const captured = { status: null, headers: null, body: '' }
  return {
    captured,
    writeHead(status, headers) {
      captured.status = status
      captured.headers = headers
    },
    end(body = '') {
      captured.body = String(body)
    },
  }
}

const HTTP_PROBE = liveManifest.capabilities.find((capability) => capability.id === 'live.http_probe')

test('strict preset does not mount generic fs/shell/web tools; files tool is registered', async () => {
  const preset = await readFile(join(import.meta.dirname, '..', 'cordis.patch.yml'), 'utf8')
  for (const forbidden of ['@deepseek-ai/dsh-tool-fs', '@deepseek-ai/dsh-tool-fs-search', '@deepseek-ai/dsh-tool-pwsh', '@deepseek-ai/dsh-tool-bash', '@deepseek-ai/dsh-tool-web', '@deepseek-ai/dsh-tool-jobs']) {
    assert.equal(preset.includes(forbidden), false, `strict preset must not mount ${forbidden}`)
  }
  assert.equal(preset.includes("name: 'dsh-armorbreak/tools'"), true)
  const tools = await readFile(join(import.meta.dirname, '..', 'tools.js'), 'utf8')
  assert.equal(tools.includes("name: 'armorbreak_files'"), true)
  assert.equal(tools.includes("action=authorize 已移除"), true)
})

test('authorization requests are inert until platform-approved activation', async () => {
  const scope = await policy()
  const request = await scope.requestAuthorization({ purpose: 'authorized lab validation', operator: 'alice', paths: [tmpdir()] })
  assert.match(request.id, /^authreq_/)
  assert.equal(request.status, 'pending')
  assert.equal((await scope.listAuthorizations()).length, 0, 'request must not create an active authorization')
  await assert.rejects(
    () => scope.activateAuthorization(request.id, { approvedBy: 'alice', approvalSource: 'chat-claim' }),
    /platform approval/,
    'model-provided text cannot activate an authorization',
  )
  const active = await scope.activateAuthorization(request.id, { approvedBy: 'platform-approval', approvalSource: 'platform-approval', approvalId: 'pa_test_1' })
  assert.match(active.id, /^authz_/)
  assert.equal(active.approvalSource, 'platform-approval')
  assert.equal((await scope.listAuthorizations()).filter((item) => item.active).length, 1)
  await scope.revoke(active.id)
  assert.equal((await scope.listAuthorizations()).filter((item) => item.active).length, 0)
})

test('scope rejects UNC, device and NUL path forms before touching the filesystem', async () => {
  assert.equal(isUnsafePathForm('\\\\server\\share\\sample.exe'), true)
  assert.equal(isUnsafePathForm('\\\\?\\C:\\Windows\\System32\\config\\SAM'), true)
  assert.equal(isUnsafePathForm(String.raw`\\.\pipe\name`), true)
  assert.equal(isUnsafePathForm('C:\\work\\sample.exe'), false)
  const scope = await policy()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-sec-ws-'))
  const check = await scope.checkFile({ taskId: 't', targetPath: '\\\\server\\share\\sample.exe', workspaceRoot: workspace })
  assert.equal(check.allowed, false)
  assert.equal(check.code, 'INVALID_PATH_FORM')
})

test('gated file reader stays inside the workspace and marks truncation/hash scope', async () => {
  const scope = await policy()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-sec-files-'))
  await mkdir(join(workspace, 'reports'), { recursive: true })
  await writeFile(join(workspace, 'reports', 'a.md'), '# report\nsecret token: [REDACTED]\n')
  const listed = await listDirectory(scope, { workspaceRoot: workspace, path: join(workspace, 'reports') })
  assert.equal(listed.allowed, true)
  assert.ok(listed.data.entries.some((entry) => entry.name === 'a.md'))
  const read = await readFileBounded(scope, { workspaceRoot: workspace, path: join(workspace, 'reports', 'a.md') })
  assert.equal(read.allowed, true)
  assert.match(read.data.text, /# report/)
  assert.equal(read.data.hashScope, 'full-file')
  const big = join(workspace, 'big.txt')
  await writeFile(big, 'x'.repeat(3000))
  const truncated = await readFileBounded(scope, { workspaceRoot: workspace, path: big, maxBytes: 1024 })
  assert.equal(truncated.data.truncated, true)
  assert.equal(truncated.data.hashScope, 'analyzed-range')
  assert.notEqual(truncated.data.fullFileSha256, truncated.data.analyzedRangeSha256)
  const outside = await mkdtemp(join(tmpdir(), 'abm-sec-outside-'))
  const outsideFile = join(outside, 'secret.txt')
  await writeFile(outsideFile, 'outside')
  const denied = await readFileBounded(scope, { workspaceRoot: workspace, path: outsideFile })
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, 'OUT_OF_SCOPE')
  const searched = await searchFiles(scope, { workspaceRoot: workspace, path: workspace, pattern: 'report' })
  assert.equal(searched.allowed, true)
  assert.ok(searched.data.matches.length >= 1)
  const stat = await statPath(scope, { workspaceRoot: workspace, path: big })
  assert.equal(stat.data.kind, 'file')
})

test('L0 file reader rejects a junction retargeted after the scope check', async () => {
  const base = await mkdtemp(join(tmpdir(), 'abm-sec-l0-race-'))
  const workspace = join(base, 'workspace')
  const inside = join(workspace, 'inside')
  const retained = join(workspace, 'inside-retained')
  const outside = join(base, 'outside')
  const target = join(inside, 'sample.txt')
  await mkdir(inside, { recursive: true })
  await mkdir(outside, { recursive: true })
  await writeFile(target, 'SAFE_IN_WORKSPACE')
  await writeFile(join(outside, 'sample.txt'), 'OUTSIDE_SYNTHETIC_SECRET')

  const scope = new ScopePolicy({ stateRoot: join(base, 'state') })
  let swapped = false
  const checkFile = scope.checkFile.bind(scope)
  scope.checkFile = async (input) => {
    const result = await checkFile(input)
    if (result.allowed && !swapped && input.targetPath === target) {
      await rename(inside, retained)
      await symlink(outside, inside, 'junction')
      swapped = true
    }
    return result
  }

  try {
    const result = await readFileBounded(scope, { workspaceRoot: workspace, path: target })
    assert.equal(swapped, true)
    assert.equal(result.allowed, false)
    assert.ok(['OUT_OF_SCOPE', 'PATH_CHANGED'].includes(result.code), `unexpected denial code: ${result.code}`)
    assert.notEqual(result.data?.text, 'OUTSIDE_SYNTHETIC_SECRET')
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('L0 file reader rejects multiply-linked files whose other path is unverified', async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'abm-sec-hardlink-'))
  const workspace = join(base, 'workspace')
  const target = join(workspace, 'linked.txt')
  const external = join(base, 'external.txt')
  await mkdir(workspace, { recursive: true })
  await writeFile(external, 'OUTSIDE_SYNTHETIC_SECRET')
  try {
    await link(external, target)
  } catch (error) {
    await rm(base, { recursive: true, force: true })
    if (['EPERM', 'EACCES', 'ENOSYS', 'EXDEV'].includes(error?.code)) {
      t.skip(`hard link creation unavailable on this filesystem: ${error.code}`)
      return
    }
    throw error
  }

  try {
    const scope = new ScopePolicy({ stateRoot: join(base, 'state') })
    const result = await readFileBounded(scope, { workspaceRoot: workspace, path: target })
    assert.equal(result.allowed, false)
    assert.equal(result.code, 'HARDLINK_NOT_ALLOWED')
    assert.notEqual(result.data?.text, 'OUTSIDE_SYNTHETIC_SECRET')
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('http probe pins the validated IP, never follows redirects, and truncates streamed bodies', async () => {
  const server = createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' })
      res.end('redirect')
      return
    }
    res.writeHead(200, { 'content-type': 'text/plain', 'set-cookie': 'session=secret' })
    res.end('y'.repeat(64 * 1024))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  try {
    const redirect = await HTTP_PROBE.run({
      targetPath: null,
      options: { url: `http://127.0.0.1:${port}/redirect` },
      limits: {},
      env: { signal: new AbortController().signal, networkPolicy: { resolvedIps: ['127.0.0.1'] } },
    })
    assert.equal(redirect.data.status, 302)
    assert.equal(redirect.data.redirectsFollowed, false)
    assert.match(redirect.data.redirectLocation, /169\.254\.169\.254/)
    assert.equal(redirect.data.pinnedIp, '127.0.0.1')

    const bounded = await HTTP_PROBE.run({
      targetPath: null,
      options: { url: `http://127.0.0.1:${port}/big`, maxBodyBytes: 4096 },
      limits: {},
      env: { signal: new AbortController().signal, networkPolicy: { resolvedIps: ['127.0.0.1'] } },
    })
    assert.equal(bounded.data.bodyTruncated, true)
    assert.ok(bounded.data.bodyBytes <= 4096)
    assert.equal(bounded.data.headers['set-cookie'], '[REDACTED]')
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
})

test('container execution requires a digest-pinned allowlisted image and hardened flags', () => {
  assert.deepEqual(CONTAINER_IMAGE_ALLOWLIST.includes('alpine'), true)
  assert.throws(() => validateContainerImage('alpine:3.20'), /digest-pinned/)
  assert.throws(() => validateContainerImage(`evil/image@sha256:${'a'.repeat(64)}`), /allowlist/)
  const pinned = `alpine@sha256:${'b'.repeat(64)}`
  assert.equal(validateContainerImage(pinned).name, 'alpine')
  const args = buildContainerArgs({ image: pinned, command: ['sh', '-c', 'id'], sampleDir: 'C:\\samples', runId: 'run123' })
  for (const flag of ['--pull', 'never', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--user', '65534:65534', 'no-new-privileges', '--name', 'armorbreak-run123']) {
    assert.ok(args.includes(flag), `missing hardened flag ${flag}`)
  }
  assert.ok(args.includes('--security-opt'))
})

test('state route is loopback-only and rejects workspace enumeration', async () => {
  const runtime = { stateSummary: async () => ({ version: 'test', registry: { capabilities: 39 } }) }
  const handler = createStateHandler(runtime)
  const ok = fakeResponse()
  await handler({ method: 'GET', url: '/armorbreak/state', socket: { remoteAddress: '127.0.0.1' } }, ok)
  assert.equal(ok.captured.status, 200)
  const remote = fakeResponse()
  await handler({ method: 'GET', url: '/armorbreak/state', socket: { remoteAddress: '10.0.0.5' } }, remote)
  assert.equal(remote.captured.status, 403)
  const enumeration = fakeResponse()
  await handler({ method: 'GET', url: '/armorbreak/state?workspace=C%3A%5CWindows', socket: { remoteAddress: '::1' } }, enumeration)
  assert.equal(enumeration.captured.status, 403)
  const post = fakeResponse()
  await handler({ method: 'POST', url: '/armorbreak/state', socket: { remoteAddress: '127.0.0.1' } }, post)
  assert.equal(post.captured.status, 405)
})
