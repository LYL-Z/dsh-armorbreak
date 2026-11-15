import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { resolveConfig, snapshotConfig, restoreConfigSnapshot, canonicalConfig, CONFIG_SCHEMA } from '../lib/integrations/configOverlay.js'
import { createMcpServer } from '../packages/mcp-server/index.js'

const bundle = (extra = {}) => ({ schema: CONFIG_SCHEMA, base: { enabled: true, text: 'old', list: [1], nested: { future: { x: 1 }, retained: true } }, ...extra })

test('overlay preserves false, empty string/list, null, unknown nested fields and source input', () => {
  const source = bundle({ overlays: [{ id: 'custom', values: { enabled: false, text: '', list: [], nested: { retained: null } } }], conflictPolicy: 'last-wins' })
  const before = JSON.stringify(source), result = resolveConfig(source)
  assert.deepEqual(result.config, { enabled: false, text: '', list: [], nested: { future: { x: 1 }, retained: null } })
  assert.equal(result.preview.status, 'PREVIEW_READY')
  assert.equal(JSON.stringify(source), before)
  assert.equal(result.preview.applied, false)
})
test('profile selection is explicit; arrays replace and layers have deterministic precedence', () => {
  const result = resolveConfig(bundle({ profiles: [{ id: 'one', values: { list: [2] } }, { id: 'two', values: { list: [3] } }], selectedProfile: 'one', overlays: [{ id: 'final', values: { list: [] } }], conflictPolicy: 'last-wins' }))
  assert.deepEqual(result.config.list, [])
  assert.deepEqual(result.preview.layers, ['layer-1', 'layer-2'])
  assert.throws(() => resolveConfig(bundle({ selectedProfile: 'missing' })), /not found/)
})
test('conflicts default to reject and no automatic application exists', () => {
  const result = resolveConfig(bundle({ overlays: [{ id: 'x', values: { text: 'new' } }] }))
  assert.equal(result.preview.status, 'CONFLICT')
  assert.equal(result.preview.conflicts.length, 1)
  assert.equal(result.preview.applied, false)
})
test('unknown config data survives while executable envelope hooks and unsafe keys fail closed', () => {
  assert.deepEqual(resolveConfig(bundle({ overlays: [{ id: 'x', values: { futureField: { raw: '${do_not_execute()}' } } }] })).config.futureField, { raw: '${do_not_execute()}' })
  assert.throws(() => resolveConfig(bundle({ execute: 'shell' })), /unsupported/)
  assert.throws(() => resolveConfig(JSON.parse('{"schema":"armorbreak.config-overlay/v1","base":{"__proto__":{"polluted":true}}}')), /unsafe/)
  assert.equal({}.polluted, undefined)
  assert.throws(() => resolveConfig(bundle({ overlays: [{ id: 'x', values: {} }, { id: 'x', values: {} }] })), /duplicate/)
})
test('snapshot round-trip and tamper detection preserve all JSON values without file writes', () => {
  const config = { disabled: false, blank: '', empty: [], unknown: { x: null } }
  const snapshot = snapshotConfig(config)
  assert.deepEqual(restoreConfigSnapshot(snapshot), config)
  assert.throws(() => restoreConfigSnapshot({ ...snapshot, content: '{}' }), /integrity/)
  assert.deepEqual(snapshotConfig(restoreConfigSnapshot(snapshot)), snapshot)
})
test('canonical serialization ignores object insertion order and rejects non-JSON/oversized/deep values', () => {
  assert.equal(canonicalConfig({ b: 2, a: 1 }), canonicalConfig({ a: 1, b: 2 }))
  assert.throws(() => canonicalConfig({ x: undefined }), /JSON/)
  assert.throws(() => canonicalConfig({ x: () => true }), /JSON/)
  assert.throws(() => canonicalConfig({ text: 'x'.repeat(1024 * 1024) }), /1 MiB/)
  let deep = {}; for (let i = 0; i < 30; i++) deep = { next: deep }
  assert.throws(() => canonicalConfig(deep), /complexity/)
})
test('preview hides config values and secret field names', () => {
  const result = resolveConfig({ schema: CONFIG_SCHEMA, base: {}, overlays: [{ id: 'safe', values: { SYNTHETIC_SECRET_FIELD: 'SYNTHETIC_SECRET_VALUE' } }] })
  assert.doesNotMatch(JSON.stringify(result.preview), /SYNTHETIC_SECRET/)
  assert.equal(result.preview.resultSha256, undefined)
  assert.equal(result.preview.schema, 'armorbreak.config-preview/v2')
})
test('Core/MCP and independent CLI use the same preview with evidence and original-file integrity', async t => {
  const root = await mkdtemp(join(tmpdir(), 'abm-overlay-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const file = join(root, 'bundle.json'), input = JSON.stringify(bundle({ overlays: [{ id: 'custom', values: { enabled: false } }] }))
  await writeFile(file, input)
  const principal = { id: 'overlay-test', kind: 'local-user', workspaces: [root] }
  const stateRoot = join(root, 'state')
  const { server, engine } = await createMcpServer({ principal, workspaceId: root, stateRoot })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const invoke = async args => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_config_preview', arguments: args } })))
  const result = await invoke({ bundle: file })
  assert.equal(result.result.isError, false)
  const output = JSON.parse(result.result.content[0].text)
  assert.equal(output.data.status, 'CONFLICT')
  assert.ok(output.taskId && output.evidenceIds.length && output.reportPath)
  assert.equal((await invoke({ bundle: file, apply: true })).result.isError, true)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'config', 'preview', '--bundle', file, '--json'], { encoding: 'utf8', env: { ...process.env, ARMORBREAK_STATE_ROOT: join(root, 'cli-state'), ARMORBREAK_WORKSPACE: root }, timeout: 30000 })
  assert.equal(cli.status, 0, cli.stderr)
  assert.deepEqual(JSON.parse(cli.stdout).data, output.data)
  assert.equal(await readFile(file, 'utf8'), input)
  const ctx = { principal, workspaceId: root, requestId: 'report', traceId: 'report', connectionId: server.connectionId }
  assert.match((await engine.getReport(ctx, output.taskId)).markdown, /Configuration CONFLICT/)
})
