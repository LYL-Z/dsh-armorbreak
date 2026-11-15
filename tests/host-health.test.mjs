import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createEngine } from '../packages/engine-node/index.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
import { inspectDshHostHealth } from '../lib/integrations/dshHostHealth.js'

async function fixture(t, version = '1.2.3') {
  const root = await mkdtemp(join(tmpdir(), 'abm-health-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace'), resources = join(workspace, 'resources')
  const dir = join(resources, 'app', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host')
  await mkdir(dir, { recursive: true })
  const file = join(dir, 'package.json')
  await writeFile(file, JSON.stringify({ name: '@deepseek-ai/dsh-desktop-host', version, token: 'SYNTHETIC_PRIVATE_VALUE' }))
  const principal = { id: 'local', kind: 'local-user', workspaces: [workspace] }
  const options = { stateRoot: join(root, 'state'), principals: [principal] }
  return { root, workspace, resources, file, principal, options, ctx: { principal, workspaceId: workspace, requestId: 'test', traceId: 'test' } }
}

test('health checks an exact version without claiming runtime compatibility', async t => {
  const f = await fixture(t)
  const before = await readFile(f.file)
  const result = await inspectDshHostHealth({ resources: f.resources, expectedVersion: '1.2.3' })
  assert.equal(result.observation, 'DETECTED_ON_DISK')
  assert.equal(result.compatibility.versionRequirement, 'MATCH')
  for (const key of ['process', 'runtime', 'feature']) assert.equal(result[key], 'UNKNOWN')
  assert.equal((await inspectDshHostHealth({ resources: f.resources, expectedVersion: '9.0.0' })).compatibility.versionRequirement, 'MISMATCH')
  assert.deepEqual(await readFile(f.file), before)
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE_VALUE/)
})

test('invalid/missing package version does not become verified compatibility', async t => {
  const f = await fixture(t, 'not-a-version')
  assert.equal((await inspectDshHostHealth({ resources: f.resources, expectedVersion: '1.2.3' })).compatibility.versionRequirement, 'UNKNOWN')
  await assert.rejects(() => inspectDshHostHealth({ resources: f.resources, expectedVersion: '*' }), /exact semantic/)
})

test('Core policy, audit, evidence, report and principal isolation apply to health', async t => {
  const f = await fixture(t), engine = await createEngine(f.options)
  t.after(() => engine.close())
  const result = await engine.analyze(f.ctx, { capability: 'host.health', target: f.resources })
  assert.equal(result.data.observation, 'DETECTED_ON_DISK')
  assert.ok(result.evidenceIds.length > 0)
  const report = await engine.getReport(f.ctx, result.taskId)
  assert.match(report.markdown, /DETECTED_ON_DISK/)
  assert.doesNotMatch(report.markdown, /SYNTHETIC_PRIVATE_VALUE/)
  const audit = await readFile(engine.runtime.workspace(f.workspace).audit.file, 'utf8')
  assert.match(audit, /capability.run.start/)
  await assert.rejects(() => engine.getReport({ ...f.ctx, principal: { id: 'forged', kind: 'local-user' } }, result.taskId), /principal/)
  await assert.rejects(() => engine.analyze(f.ctx, { capability: 'host.health', target: f.root }), /outside/)
})

test('MCP invokes the same Core health capability and rejects identity parameters', async t => {
  const f = await fixture(t)
  const { server, engine } = await createMcpServer({ ...f.options, principal: f.principal, workspaceId: f.workspace })
  t.after(() => engine.close())
  const request = async (id, method, params) => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id, method, params })))
  await request(1, 'initialize', {})
  const result = await request(2, 'tools/call', { name: 'armorbreak_host_health', arguments: { resources: f.resources } })
  assert.equal(result.result.isError, false)
  assert.equal(JSON.parse(result.result.content[0].text).data.observation, 'DETECTED_ON_DISK')
  const denied = await request(3, 'tools/call', { name: 'armorbreak_host_health', arguments: { resources: f.resources, principal: 'admin' } })
  assert.equal(denied.result.isError, true)
})

test('health CLI executes in a separate process with task and report output', async t => {
  const f = await fixture(t)
  const result = spawnSync(process.execPath, ['packages/cli/index.js', 'host', 'health', '--resources', f.resources, '--json'], {
    env: { ...process.env, ARMORBREAK_STATE_ROOT: f.options.stateRoot, ARMORBREAK_WORKSPACE: f.workspace }, encoding: 'utf8', timeout: 30000,
  })
  assert.equal(result.status, 0, result.stderr)
  const data = JSON.parse(result.stdout)
  assert.equal(data.data.observation, 'DETECTED_ON_DISK')
  assert.ok(data.taskId && data.reportPath)
})

test('Core health never reads metadata through an external junction', async t => {
  const f = await fixture(t), outside = join(f.root, 'external')
  await mkdir(outside)
  await writeFile(join(outside, 'package.json'), '{"name":"dsh-desktop-next","main":"x.js","version":"1.0.0"}')
  const alias = join(f.workspace, 'linked')
  await symlink(outside, alias, process.platform === 'win32' ? 'junction' : 'dir')
  const engine = await createEngine(f.options)
  t.after(() => engine.close())
  await assert.rejects(() => engine.analyze(f.ctx, { capability: 'host.health', target: alias }))
})
