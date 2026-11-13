import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { createMcpServer } from '../packages/mcp-server/index.js'
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'abm-diagnostics-')), workspace = join(root, 'workspace')
  t.after(() => rm(root, { recursive: true, force: true }))
  const packageRoot = join(workspace, 'resources', 'app', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host')
  await mkdir(packageRoot, { recursive: true }); await mkdir(join(workspace, 'profiles', 'web'), { recursive: true })
  await writeFile(join(packageRoot, 'package.json'), '{"name":"@deepseek-ai/dsh-desktop-host","version":"1.2.3","secret":"SYNTHETIC_SECRET"}')
  await writeFile(join(workspace, 'profiles', 'web', 'package.json'), '{"dependencies":{"dsh-purge":"https://SYNTHETIC_SECRET@registry.invalid"}}')
  await writeFile(join(workspace, 'profiles', 'web', 'cordis.patch.yml'), 'name: dsh-purge\nsecret: SYNTHETIC_SECRET\n')
  await writeFile(join(workspace, 'host.js'), '/* SYNTHETIC_SECRET */ const stableAnchor = true;')
  await writeFile(join(workspace, 'anchors.json'), JSON.stringify({ schemaVersion: 'armorbreak.anchor-spec/v1', anchors: [{ id: 'stable', literal: 'stableAnchor' }] }))
  await writeFile(join(workspace, 'config.json'), JSON.stringify({ schema: 'armorbreak.config-overlay/v1', base: { enabled: false, secret: 'SYNTHETIC_SECRET' } }))
  const request = { schema: 'armorbreak.host-diagnostics-request/v1', resources: 'resources', expectedVersion: '1.2.3', profile: 'web', anchors: { target: 'host.js', spec: 'anchors.json' }, configurationBundle: 'config.json' }
  const save = () => writeFile(join(workspace, 'armorbreak-host-diagnostics.json'), JSON.stringify(request))
  await save()
  const principal = { id: 'diagnostic-test', kind: 'local-user', workspaces: [workspace] }
  const { server, engine } = await createMcpServer({ principal, workspaceId: workspace, stateRoot: join(root, 'state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const call = async () => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'host.diagnostics', target: workspace } } })))
  return { root, workspace, request, save, call, engine, principal, server }
}
test('composite workflow persists one Core task across real disk/profile/anchor/config reads without leaking source content', async t => {
  const f = await fixture(t), response = await f.call()
  assert.equal(response.result.isError, false)
  const result = JSON.parse(response.result.content[0].text), data = result.data
  assert.equal(data.status, 'DISK_DIAGNOSTICS_COMPLETE')
  assert.equal(data.health.observation, 'DETECTED_ON_DISK')
  assert.equal(data.profile.manifest.declaredPackages[0].name, 'dsh-purge')
  assert.equal(data.anchors.status, 'MATCHES_EXPECTATIONS')
  assert.equal(data.configuration.status, 'PREVIEW_READY')
  assert.equal(data.plugins.status, 'NOT_REQUESTED')
  assert.equal(data.runtime, 'UNKNOWN')
  assert.equal(data.realHostVerified, false)
  assert.doesNotMatch(JSON.stringify(data), /SYNTHETIC_SECRET|stableAnchor|abm-diagnostics/)
  const ctx = { principal: f.principal, workspaceId: f.workspace, requestId: 'report', traceId: 'report', connectionId: f.server.connectionId }
  assert.match((await f.engine.getReport(ctx, result.taskId)).markdown, /DISK_DIAGNOSTICS_COMPLETE/)
  assert.match(await readFile(join(f.workspace, 'host.js'), 'utf8'), /stableAnchor/)
})
test('version, missing profile, anchor drift and config conflicts produce actionable review results, not runtime PASS', async t => {
  const f = await fixture(t)
  f.request.expectedVersion = '9.0.0'; f.request.profile = 'missing'
  await f.save(); await writeFile(join(f.workspace, 'host.js'), 'no stable literal')
  await writeFile(join(f.workspace, 'config.json'), JSON.stringify({ schema: 'armorbreak.config-overlay/v1', base: { enabled: false }, overlays: [{ id: 'one', values: { enabled: true } }] }))
  const response = await f.call(); assert.equal(response.result.isError, false)
  const data = JSON.parse(response.result.content[0].text).data
  assert.equal(data.status, 'REVIEW_REQUIRED')
  assert.deepEqual(data.issues.map(i => i.code), ['VERSION_REQUIREMENT_MISMATCH', 'PROFILE_INCOMPLETE', 'ANCHOR_DRIFT', 'CONFIGURATION_CONFLICT'])
  assert.equal(data.feature, 'UNKNOWN')
})
test('explicit relative paths, no execution hooks, bounded valid UTF-8 and Core junction boundaries are enforced', async t => {
  const f = await fixture(t)
  f.request.configurationBundle = '../outside.json'; await f.save()
  assert.equal((await f.call()).result.isError, true)
  f.request.configurationBundle = 'config.json'; f.request.command = 'shell'; await f.save()
  assert.equal((await f.call()).result.isError, true)
  delete f.request.command; await f.save()
  await writeFile(join(f.workspace, 'config.json'), Buffer.from([0xff, 0xfe]))
  assert.equal((await f.call()).result.isError, true)
  const outside = join(f.root, 'outside'); await mkdir(outside); await writeFile(join(outside, 'config.json'), '{}')
  await symlink(outside, join(f.workspace, 'link'), process.platform === 'win32' ? 'junction' : 'dir')
  f.request.configurationBundle = 'link/config.json'; await f.save()
  const escaped = await f.call(); assert.equal(escaped.result.isError, true)
  assert.match(escaped.result.content[0].text, /PATH_ESCAPE|escape|outside/)
})
test('independent diagnostic CLI agrees with MCP and never interprets disk metadata as a running instance', async t => {
  const f = await fixture(t), response = await f.call()
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'host', 'diagnostics', '--root', f.workspace, '--json'], { encoding: 'utf8', env: { ...process.env, ARMORBREAK_STATE_ROOT: join(f.root, 'cli-state'), ARMORBREAK_WORKSPACE: f.workspace }, timeout: 30000 })
  assert.equal(cli.status, 0, cli.stderr)
  assert.deepEqual(JSON.parse(cli.stdout).data, JSON.parse(response.result.content[0].text).data)
  assert.equal(JSON.parse(cli.stdout).data.process, 'UNKNOWN')
})
