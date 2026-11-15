import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { resolveConfig, canonicalConfig } from '../lib/integrations/configOverlay.js'
import { inspectPluginMetadata } from '../lib/catalog/pluginPackage.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
import { createWorkbenchServer } from '../workbench/server.mjs'

const hash = value => createHash('sha256').update(value).digest('hex')
const secrets = ['1234', 'pass', 'enabled']
const bundle = secret => ({ schema: 'armorbreak.config-overlay/v1', base: { privatePin: secret }, overlays: [{ id: 'privateLabel', values: { privatePin: '5678' } }], conflictPolicy: 'last-wins' })
function assertNoDictionaryOracle(text, input) {
  for (const value of [...secrets, '5678', 'privatePin', '/privatePin', canonicalConfig(input.base), canonicalConfig(resolveConfig(input).config), JSON.stringify(input)]) {
    assert.ok(!text.includes(hash(value)), `export contains guessable digest of ${JSON.stringify(value)}`)
    assert.ok(!text.includes(hash(JSON.stringify(value))), 'export contains a scalar dictionary oracle')
  }
  assert.doesNotMatch(text, /privatePin|privateLabel|beforeSha256|afterSha256|sourceSha256|resultSha256/)
}
async function textTree(root) {
  const chunks = []
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name)
    if (entry.isDirectory()) chunks.push(await textTree(path))
    else chunks.push(await readFile(path, 'utf8'))
  }
  return chunks.join('\n')
}
test('F01 public preview has no PIN/password/enum dictionary oracle or secret-derived field identity', () => {
  const previews = secrets.map(secret => resolveConfig(bundle(secret)).preview)
  for (let i = 0; i < secrets.length; i++) assertNoDictionaryOracle(JSON.stringify(previews[i]), bundle(secrets[i]))
  assert.deepEqual(previews[0], previews[1])
  assert.deepEqual(previews[1], previews[2])
})
test('F01 actual CLI, MCP, HTTP Workbench and persisted reports/evidence omit secret digests', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ab-review-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace'); await mkdir(workspace)
  const input = bundle('1234'), target = join(workspace, 'bundle.json')
  await writeFile(target, JSON.stringify(input))
  const stateRoot = join(root, 'mcp-state')
  const { server, engine } = await createMcpServer({ principal: { id: 'privacy', kind: 'local-user', workspaces: [workspace] }, workspaceId: workspace, stateRoot })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const mcp = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_config_preview', arguments: { bundle: target } } })))
  assert.equal(mcp.result.isError, false)
  assertNoDictionaryOracle(JSON.stringify(mcp), input)
  assertNoDictionaryOracle(await textTree(stateRoot), input)
  const cliState = join(root, 'cli-state')
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'config', 'preview', '--bundle', target, '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, ARMORBREAK_STATE_ROOT: cliState, ARMORBREAK_WORKSPACE: workspace } })
  assert.equal(cli.status, 0, cli.stderr)
  assertNoDictionaryOracle(cli.stdout, input)
  assertNoDictionaryOracle(await textTree(cliState), input)
  const panelState = join(root, 'panel-state'), panel = await createWorkbenchServer({ native: { workspaceId: workspace, stateRoot: panelState } })
  t.after(() => panel.close())
  const session = await (await fetch(`${panel.url}/api/native/session`)).json()
  const response = await fetch(`${panel.url}/api/native/run`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-armorbreak-session': session.csrf }, body: JSON.stringify({ capability: 'configuration.preview', target }) })
  assert.equal(response.status, 200)
  assertNoDictionaryOracle(await response.text(), input)
  assertNoDictionaryOracle(await textTree(panelState), input)
  assert.equal(await readFile(target, 'utf8'), JSON.stringify(input))
})
test('F02 self-claimed MIT and L0 are neither rights clearance nor Core activation authorization', () => {
  const result = inspectPluginMetadata({ schema: 'armorbreak.plugin-catalog/v1', plugins: [{ id: 'inert', version: '1.0.0', source: { repository: 'https://github.com/example/inert', commit: 'a'.repeat(40) }, license: 'MIT', permissions: ['workspace.read'], dependencies: [], platforms: ['linux'], channel: 'stable', enabled: true, files: [{ path: 'inert.txt', sha256: hash('inert') }] }] })
  const row = result.plugins[0]
  assert.equal(row.policyEligible, false)
  assert.equal(row.metadataShapeValid, true)
  assert.equal(row.riskClassificationEligible, true)
  assert.equal(row.localFilesVerified, false)
  for (const key of ['sourceAuthenticated', 'rightsVerified', 'activationAuthorized', 'releaseEligible']) assert.equal(row[key], false, key)
  assert.equal(row.corePolicyState, 'NOT_EVALUATED')
})
