import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createEngine } from '../packages/engine-node/index.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
import manifest from '../lib/analyzers/logs/manifest.js'
import { MAX_LOG_BYTES } from '../lib/analyzers/logs/summarize.js'

const repoRoot = fileURLToPath(new URL('..', import.meta.url))
const SECRET = 'supersecretvalue'
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
const TOKEN = 'tok_abcdefghijklmnopqrstuvwxyz'
const BEARER = 'abcdefghijklmnopqr'
const SECRETS = [SECRET, AWS_KEY, AWS_SECRET, TOKEN, BEARER]

function sampleLog() {
  return [
    `INFO started token=${TOKEN}`,
    'WARN disk',
    `ERROR password=${SECRET} failed`,
    `DEBUG trace ${AWS_KEY} Authorization: Bearer ${BEARER}`,
    `error aws_secret_access_key=${AWS_SECRET}`,
    'information not counted',
    'WARNING not counted',
    'preERROR not counted',
    'ERROR_CODE not counted',
    '',
  ].join('\n')
}

function assertRedacted(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  for (const secret of SECRETS) assert.equal(text.includes(secret), false)
  return text
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'abm-log-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace')
  await mkdir(workspace)
  const principal = { id: 'log-test', kind: 'local-user', workspaces: [workspace] }
  const stateRoot = join(root, 'state')
  const ctx = { principal, workspaceId: workspace, requestId: 'log', traceId: 'log' }
  return { root, workspace, principal, stateRoot, ctx }
}

async function engineFor(t, fixtureValue) {
  const engine = await createEngine({ stateRoot: fixtureValue.stateRoot, principals: [fixtureValue.principal] })
  t.after(() => engine.close())
  return engine
}

test('registry exposes diagnostics.log_summary and a synthetic log summarizes without secrets', async (t) => {
  const f = await fixture(t)
  const logFile = join(f.workspace, 'app.log')
  await writeFile(logFile, sampleLog(), 'utf8')
  const engine = await engineFor(t, f)
  const listed = await engine.capabilities(f.ctx)
  const capability = listed.find((item) => item.id === 'diagnostics.log_summary')
  assert.ok(capability)
  assert.equal(capability.riskLevel, 'L0')
  assert.equal(capability.targetKind, 'file')
  assert.equal(capability.domain, 'logs')
  assert.equal(engine.runtime.registry.diagnostics.length, 0)
  assert.equal(engine.runtime.registry.get('host.diagnostics').id, 'host.diagnostics')

  const result = await engine.analyze(f.ctx, { capability: 'diagnostics.log_summary', target: logFile })
  assert.equal(result.state, 'COMPLETED')
  assert.equal(result.riskLevel, 'L0')
  assert.equal(result.data.lineCount, 9)
  assert.deepEqual(result.data.levels, { ERROR: 2, WARN: 1, INFO: 1, DEBUG: 1 })
  assert.equal(result.data.redacted, true)
  assert.equal(result.targetSha256, null)
  const stored = assertRedacted(result.data)
  assert.match(stored, /\[REDACTED\]/)
  assert.match(stored, /ERROR/)
  const evidence = await engine.getEvidence(f.ctx, result.taskId)
  assertRedacted(evidence)
  const report = await engine.getReport(f.ctx, result.taskId)
  assertRedacted(report.markdown)
  assert.match(report.markdown, /Local log: 9 lines/)
})

test('armorbreak_analyze and the analyze CLI see the same redacted summary', async (t) => {
  const f = await fixture(t)
  const logFile = join(f.workspace, 'app.log')
  await writeFile(logFile, sampleLog(), 'utf8')
  const { server, engine } = await createMcpServer({ principal: f.principal, workspaceId: f.workspace, stateRoot: f.stateRoot })
  t.after(() => engine.close())
  const call = async (id, params) => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params })))
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const catalog = await call(2, { name: 'armorbreak_capabilities', arguments: {} })
  const ids = JSON.parse(catalog.result.content[0].text)
  assert.equal(catalog.result.isError, false)
  assert.ok(ids.some((item) => item.id === 'diagnostics.log_summary' && item.riskLevel === 'L0' && item.targetKind === 'file'))
  const analyzed = await call(3, { name: 'armorbreak_analyze', arguments: { capability: 'diagnostics.log_summary', target: logFile } })
  assert.equal(analyzed.result.isError, false)
  const payload = JSON.parse(analyzed.result.content[0].text)
  assert.deepEqual(payload.data.levels, { ERROR: 2, WARN: 1, INFO: 1, DEBUG: 1 })
  assertRedacted(payload)

  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'analyze', '--capability', 'diagnostics.log_summary', '--target', logFile, '--json'], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 30000,
    env: { ...process.env, ARMORBREAK_STATE_ROOT: join(f.root, 'cli-state'), ARMORBREAK_WORKSPACE: f.workspace },
  })
  assert.equal(cli.status, 0, cli.stderr)
  const cliResult = JSON.parse(cli.stdout)
  assert.equal(cliResult.capability, 'diagnostics.log_summary')
  assert.equal(cliResult.data.lineCount, 9)
  assert.deepEqual(cliResult.data.levels, { ERROR: 2, WARN: 1, INFO: 1, DEBUG: 1 })
  assertRedacted(cli.stdout)
})

test('log summary redacts tokens, passwords, and AWS-style keys before excerpts', async (t) => {
  const f = await fixture(t)
  const logFile = join(f.workspace, 'secrets.log')
  await writeFile(logFile, sampleLog(), 'utf8')
  const engine = await engineFor(t, f)
  const result = await engine.analyze(f.ctx, { capability: 'diagnostics.log_summary', target: logFile })
  const text = assertRedacted(result.data)
  assert.match(text, /password=\[REDACTED\]/)
  assert.match(text, /token=\[REDACTED\]/)
  assert.match(text, /aws_secret_access_key=\[REDACTED\]/)
  assert.match(text, /Authorization: \[REDACTED\]/)
  assert.equal(result.data.excerpts.some((line) => line.includes(AWS_KEY) || line.includes(BEARER)), false)
})

test('oversize and binary logs are refused without returning their bytes', async (t) => {
  const f = await fixture(t)
  const engine = await engineFor(t, f)
  const oversize = join(f.workspace, 'big.log')
  await writeFile(oversize, Buffer.alloc(MAX_LOG_BYTES + 1, 0x41))
  await assert.rejects(() => engine.analyze(f.ctx, { capability: 'diagnostics.log_summary', target: oversize }), (error) => {
    assert.match(error.message, /oversize/)
    assert.ok(error.message.length < 400)
    assert.doesNotMatch(error.message, /AAAA/)
    return true
  })
  const binary = join(f.workspace, 'binary.log')
  await writeFile(binary, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]))
  await assert.rejects(() => engine.analyze(f.ctx, { capability: 'diagnostics.log_summary', target: binary }), (error) => {
    assert.match(error.message, /binary/)
    assert.doesNotMatch(error.message, /PNG|\\x89/)
    return true
  })
})

test('paths outside the workspace are refused before the log is summarized', async (t) => {
  const f = await fixture(t)
  const outside = join(f.root, 'outside.log')
  const secretLine = `ERROR password=${SECRET} failed`
  await writeFile(outside, secretLine, 'utf8')
  const engine = await engineFor(t, f)
  await assert.rejects(() => engine.analyze(f.ctx, { capability: 'diagnostics.log_summary', target: outside }), (error) => {
    assert.match(error.message, /outside/)
    assert.equal(error.message.includes(SECRET), false)
    return true
  })
  await assert.rejects(() => manifest.capabilities[0].run({
    targetPath: outside,
    options: {},
    env: { workspaceRoot: f.workspace },
    buffer: Buffer.from(secretLine),
    text: secretLine,
  }), (error) => {
    assert.match(error.message, /outside the workspace/)
    assert.equal(error.message.includes(SECRET), false)
    return true
  })
})

test('live, network, and execute options are refused', async (t) => {
  const f = await fixture(t)
  const logFile = join(f.workspace, 'app.log')
  await writeFile(logFile, 'INFO ready\n', 'utf8')
  const engine = await engineFor(t, f)
  const analyze = (options) => engine.analyze(f.ctx, { capability: 'diagnostics.log_summary', target: logFile, options })
  await assert.rejects(() => analyze({ tail: true }), /tail a live process/)
  await assert.rejects(() => analyze({ follow: true }), /tail a live process/)
  await assert.rejects(() => analyze({ socket: '127.0.0.1:9' }), /network socket/)
  await assert.rejects(() => analyze({ network: true }), /network socket/)
  await assert.rejects(() => analyze({ execute: true }), /execute the file/)
  await assert.rejects(() => analyze({ command: 'more' }), /execute the file/)
})

test('log analyzer source does not import a shell or network client', async () => {
  const summarize = await readFile(new URL('../lib/analyzers/logs/summarize.js', import.meta.url), 'utf8')
  const source = summarize + await readFile(new URL('../lib/analyzers/logs/manifest.js', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /node:(?:child_process|net|http|https|dns|tls|dgram)/)
  assert.doesNotMatch(source, /\b(?:execFile|spawn|fetch)\s*\(/)
})
