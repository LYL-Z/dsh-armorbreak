/**
 * Behavior contracts for installed ArmorBreak L0 analyzers.
 *
 * Each case calls createEngine and engine.analyze on a synthetic file or
 * directory inside a temporary workspace. A completed run must expose an
 * evidence id or a report path. An error is accepted only when the case lists
 * its code as a documented honest failure. These fixtures are valid inputs, so
 * none of the cases list a failure code.
 *
 * The planted secret lives outside the analyzed file or directory. Output from
 * a completed run must not contain it. A target outside the workspace must be
 * rejected. This file does not assert equivalence with any upstream implementation.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, relative, sep } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { createEngine } from '../packages/engine-node/index.js'

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'l0-contract')
const SECRET_FILE = 'planted-outside-target.txt'
const SECRET_BYTES = await readFile(join(FIXTURES, SECRET_FILE))
const SECRET = SECRET_BYTES.toString('utf8').trim()

function containsSecret(value) {
  if (typeof value === 'string') return value.includes(SECRET)
  return JSON.stringify(value).includes(SECRET)
}

async function filesUnder(path) {
  const info = await stat(path)
  if (info.isFile()) return [path]
  const files = []
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const child = join(path, entry.name)
    if (entry.isDirectory()) files.push(...await filesUnder(child))
    else if (entry.isFile()) files.push(child)
  }
  return files
}

async function stage(workspace, relativePath) {
  const dest = join(workspace, relativePath)
  await cp(join(FIXTURES, relativePath), dest, { recursive: true })
  return dest
}

async function openLab(t) {
  const root = await mkdtemp(join(tmpdir(), 'abm-l0-contract-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside')
  await mkdir(workspace)
  await mkdir(outside)
  const principal = { id: 'l0-contract', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot: join(root, 'state'), principals: [principal] })
  t.after(() => engine.close())
  let request = 0
  const ctx = () => ({
    principal,
    workspaceId: workspace,
    requestId: `l0-${++request}`,
    traceId: `l0-trace-${request}`,
  })
  return { workspace, outside, engine, ctx }
}

async function rejectOutside(lab, id) {
  const outsideTarget = join(lab.outside, SECRET_FILE)
  await writeFile(outsideTarget, SECRET_BYTES)
  await assert.rejects(
    () => lab.engine.analyze(lab.ctx(), { capability: id, target: outsideTarget }),
    (error) => {
      assert.equal(error.code, 'TARGET_OUT_OF_SCOPE')
      assert.equal(containsSecret(error.message), false)
      assert.equal(containsSecret(error), false)
      return true
    },
  )
  assert.equal((await readFile(outsideTarget)).equals(SECRET_BYTES), true)
}

const CASES = [
  {
    id: 'forensics.hash',
    async stage(workspace) { return stage(workspace, 'sample.txt') },
    expect(result, targetBytes) {
      assert.equal(result.data.digests.sha256, createHash('sha256').update(targetBytes).digest('hex'))
      assert.equal(result.data.complete, true)
    },
  },
  {
    id: 'forensics.filetype',
    async stage(workspace) { return stage(workspace, 'sample.txt') },
    expect(result, targetBytes) {
      assert.equal(result.data.type, 'text')
      assert.equal(result.data.mime, 'text/plain')
      assert.equal(result.data.size, targetBytes.length)
    },
  },
  {
    id: 'sast.scan',
    async stage(workspace) { return stage(workspace, 'project') },
    expect(result) {
      assert.ok(result.data.findingsCount >= 1)
      assert.ok(result.data.ruleHits.some((hit) => hit.id === 'js-eval' && hit.count >= 1))
    },
  },
  {
    id: 'sast.deps',
    async stage(workspace) { return stage(workspace, 'project') },
    expect(result) {
      const manifest = result.data.manifests.find((item) => item.ecosystem === 'npm')
      assert.ok(manifest)
      assert.equal(manifest.name, 'synthetic-l0')
      assert.ok(manifest.dependencyCount >= 1)
    },
  },
  {
    id: 'plugin.verify',
    async stage(workspace) { return stage(workspace, 'plugin') },
    expect(result) {
      assert.equal(result.data.verificationStatus, 'LOCAL_LISTED_FILES_VERIFIED')
      assert.equal(result.data.networkUsed, false)
      assert.equal(result.data.installationPerformed, false)
      assert.equal(result.data.plugins[0].localFilesVerified, true)
      assert.equal(result.data.plugins[0].executable, false)
      assert.equal(result.data.plugins[0].sourceAuthenticated, false)
    },
  },
  {
    id: 'configuration.preview',
    async stage(workspace) { return stage(workspace, 'overlay.json') },
    expect(result) {
      assert.equal(result.data.schema, 'armorbreak.config-preview/v2')
      assert.equal(result.data.mode, 'READ_ONLY')
      assert.equal(result.data.status, 'PREVIEW_READY')
      assert.equal(result.data.applied, false)
      assert.ok(result.data.changes.length >= 1)
    },
  },
  {
    id: 'host.health',
    async stage(workspace) {
      const resources = join(workspace, 'resources')
      const dest = join(resources, 'app', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host', 'package.json')
      await mkdir(dirname(dest), { recursive: true })
      await cp(join(FIXTURES, 'host-package.json'), dest)
      return resources
    },
    expect(result) {
      assert.equal(result.data.observation, 'DETECTED_ON_DISK')
      assert.equal(result.data.identity.version, '1.2.3')
      assert.equal(result.data.runtime, 'UNKNOWN')
      assert.equal(result.data.process, 'UNKNOWN')
    },
  },
  {
    id: 'assessment.assets',
    async stage(workspace) { return stage(workspace, 'assets.json') },
    expect(result) {
      assert.equal(result.data.schema, 'armorbreak.offline-asset-graph/v1')
      assert.equal(result.data.networkUsed, false)
      assert.equal(result.data.ownership, 'NOT_VERIFIED')
      assert.equal(result.data.certificateAuthentication, 'NOT_PERFORMED')
      assert.ok(result.data.edges.some((edge) => edge.type === 'contains' && edge.provenance?.rule === 'IPV4_CIDR_CONTAINMENT'))
    },
  },
]

for (const spec of CASES) {
  test(`L0 contract: ${spec.id}`, async (t) => {
    const lab = await openLab(t)
    const registered = await lab.engine.capabilities(lab.ctx())
    const capability = registered.find((item) => item.id === spec.id)
    if (!capability) {
      t.skip(`${spec.id} is not registered`)
      return
    }
    assert.equal(capability.riskLevel, 'L0')
    assert.ok(capability.targetKind === 'file' || capability.targetKind === 'directory')

    const target = await spec.stage(lab.workspace)
    const secretPath = join(lab.workspace, SECRET_FILE)
    await writeFile(secretPath, SECRET_BYTES)
    const fromTarget = relative(target, secretPath)
    assert.ok(fromTarget === '..' || fromTarget.startsWith(`..${sep}`), `${SECRET_FILE} must sit outside ${target}`)
    for (const file of await filesUnder(target)) {
      assert.equal((await readFile(file)).includes(SECRET_BYTES), false, file)
    }

    let result
    try {
      result = await lab.engine.analyze(lab.ctx(), { capability: spec.id, target })
    } catch (error) {
      if (spec.honestFailureCodes?.includes(error.code)) {
        assert.equal(containsSecret(error.message), false)
        assert.equal(containsSecret(error), false)
        await rejectOutside(lab, spec.id)
        return
      }
      throw error
    }

    assert.equal(result.state, 'COMPLETED', `${spec.id} did not complete and did not raise a documented honest failure`)
    assert.equal(result.capability, spec.id)
    assert.equal(result.riskLevel, 'L0')
    const proved = (Array.isArray(result.evidenceIds) && result.evidenceIds.length > 0) || (typeof result.reportPath === 'string' && result.reportPath.length > 0)
    assert.equal(proved, true, `${spec.id} completed without an evidence id or report path`)
    assert.equal(containsSecret(result), false)

    const evidence = await lab.engine.getEvidence(lab.ctx(), result.taskId)
    assert.ok(evidence.evidence.some((record) => result.evidenceIds.includes(record.id)))
    assert.equal(containsSecret(evidence), false)

    assert.equal(typeof result.reportPath, 'string')
    const report = await lab.engine.getReport(lab.ctx(), result.taskId)
    assert.equal(report.path, result.reportPath)
    assert.match(report.markdown, new RegExp(spec.id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    assert.equal(report.markdown.includes(SECRET), false)

    const targetBytes = (await stat(target)).isFile() ? await readFile(target) : null
    spec.expect(result, targetBytes)
    await rejectOutside(lab, spec.id)
  })
}
