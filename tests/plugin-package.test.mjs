import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { inspectPluginMetadata } from '../lib/catalog/pluginPackage.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const entry = (extra = {}) => ({ id: 'inert', version: '1.0.0', source: { repository: 'https://github.com/example/inert', commit: 'a'.repeat(40) }, license: 'MIT', dependencies: [], permissions: ['workspace.read'], platforms: ['win32', 'linux', 'darwin'], channel: 'stable', enabled: false, files: [{ path: 'inert.txt', sha256: hash('self-authored inert fixture') }], ...extra })
const bundle = (...plugins) => ({ schema: 'armorbreak.plugin-catalog/v1', plugins })

test('immutable metadata dedupes source identity without claiming plugin behavior equivalence or loading', () => {
  const result = inspectPluginMetadata(bundle(entry(), entry({ id: 'dependent', dependencies: [{ id: 'inert', version: '1.0.0' }], enabled: true })))
  assert.deepEqual(result.dependencyOrder, ['inert', 'dependent'])
  assert.equal(result.uniqueSources, 1)
  assert.equal(result.plugins.length, 2)
  assert.equal(result.plugins[1].requestedEnabled, true)
  assert.equal(result.plugins[1].loadedState, 'UNKNOWN')
  assert.equal(result.plugins[1].executable, false)
  assert.equal(result.plugins[1].rightsState, 'UNVERIFIED_NOT_IMPORTED')
})
test('missing dependencies, mismatched versions and cycles fail closed', () => {
  assert.throws(() => inspectPluginMetadata(bundle(entry({ dependencies: [{ id: 'missing', version: '1.0.0' }] }))), /missing dependency/)
  assert.throws(() => inspectPluginMetadata(bundle(entry(), entry({ id: 'two', dependencies: [{ id: 'inert', version: '2.0.0' }] }))), /version mismatch/)
  assert.throws(() => inspectPluginMetadata(bundle(entry({ dependencies: [{ id: 'two', version: '1.0.0' }] }), entry({ id: 'two', dependencies: [{ id: 'inert', version: '1.0.0' }] }))), /cycle/)
})
test('requested privileges never become Core grants; L3 stays denied and unknown permission is rejected', () => {
  const result = inspectPluginMetadata(bundle(entry({ permissions: ['host.modify', 'credential.attack'], enabled: true })))
  assert.equal(result.plugins[0].riskLevel, 'L3')
  assert.equal(result.plugins[0].executionState, 'DENIED')
  assert.equal(result.plugins[0].policyEligible, false)
  assert.throws(() => inspectPluginMetadata(bundle(entry({ permissions: ['arbitrary.shell'] }))), /unknown plugin permission/)
})
test('mutable, credential-bearing, local and query-bearing sources are refused without fetching', () => {
  for (const repository of ['file:///secret', 'http://github.com/e/r', 'https://token@github.com/e/r', 'https://github.com/e/r?key=SYNTHETIC', 'https://github.com/e/r/tree/main']) assert.throws(() => inspectPluginMetadata(bundle(entry({ source: { repository, commit: 'a'.repeat(40) } }))), /source required/)
  assert.throws(() => inspectPluginMetadata(bundle(entry({ source: { repository: 'https://github.com/e/r', commit: 'main' } }))), /source required/)
})
test('license claim is distinct from permission to redistribute; executable hooks and unsafe paths are rejected', () => {
  const result = inspectPluginMetadata(bundle(entry({ license: 'UNKNOWN' })))
  assert.equal(result.plugins[0].policyEligible, false)
  assert.equal(result.plugins[0].licenseClaim, 'UNKNOWN_LICENSE')
  assert.throws(() => inspectPluginMetadata(bundle(entry({ postinstall: 'shell' }))), /fields/)
  assert.throws(() => inspectPluginMetadata(bundle(entry({ files: [{ path: '../escape', sha256: hash('x') }] }))), /invalid maintenance relative path/)
})
test('duplicate IDs, case-colliding files and unsafe JSON keys are rejected', () => {
  assert.throws(() => inspectPluginMetadata(bundle(entry(), entry())), /duplicate plugin identity/)
  assert.throws(() => inspectPluginMetadata(bundle(entry({ files: [{ path: 'a', sha256: hash('x') }, { path: 'A', sha256: hash('x') }] }))), /duplicate package file/)
  assert.throws(() => inspectPluginMetadata(JSON.parse('{"schema":"armorbreak.plugin-catalog/v1","__proto__":{},"plugins":[]}')), /unsafe/)
})
test('actual Core, generic MCP and independent CLI verify local listed files and reject corruption/junctions', async t => {
  const root = await mkdtemp(join(tmpdir(), 'abm-plugin-')), workspace = join(root, 'workspace')
  t.after(() => rm(root, { recursive: true, force: true }))
  await mkdir(workspace)
  const data = 'self-authored inert fixture', manifest = bundle(entry())
  await writeFile(join(workspace, 'armorbreak-plugin.json'), JSON.stringify(manifest))
  await writeFile(join(workspace, 'inert.txt'), data)
  const principal = { id: 'plugin-test', kind: 'local-user', workspaces: [workspace] }
  const { server, engine } = await createMcpServer({ principal, workspaceId: workspace, stateRoot: join(root, 'state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const call = async options => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'plugin.verify', target: workspace, options } } })))
  const result = await call({})
  assert.equal(result.result.isError, false)
  const output = JSON.parse(result.result.content[0].text)
  assert.equal(output.data.verificationStatus, 'LOCAL_LISTED_FILES_VERIFIED')
  assert.ok(output.taskId && output.evidenceIds.length && output.reportPath)
  assert.equal((await call({ enable: true })).result.isError, true)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'plugin', 'verify', '--root', workspace, '--json'], { encoding: 'utf8', env: { ...process.env, ARMORBREAK_STATE_ROOT: join(root, 'cli-state'), ARMORBREAK_WORKSPACE: workspace }, timeout: 30000 })
  assert.equal(cli.status, 0, cli.stderr)
  assert.deepEqual(JSON.parse(cli.stdout).data, output.data)
  assert.equal(await readFile(join(workspace, 'inert.txt'), 'utf8'), data)
  await writeFile(join(workspace, 'inert.txt'), 'corrupt')
  const bad = await call({})
  assert.equal(bad.result.isError, true)
  assert.match(bad.result.content[0].text, /hash mismatch/)
  const outside = join(root, 'outside'); await mkdir(outside); await writeFile(join(outside, 'inert.txt'), data)
  await symlink(outside, join(workspace, 'link'), process.platform === 'win32' ? 'junction' : 'dir')
  manifest.plugins[0].files[0].path = 'link/inert.txt'
  await writeFile(join(workspace, 'armorbreak-plugin.json'), JSON.stringify(manifest))
  const escaped = await call({})
  assert.equal(escaped.result.isError, true)
  assert.match(escaped.result.content[0].text, /PATH_ESCAPE|escape|outside/)
})
