import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { importConfiguration, exportConfiguration, IMPORT_SCHEMA } from '../lib/integrations/configFormats.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
const input = (format, source) => ({ schema: IMPORT_SCHEMA, format, source })

test('JSON and YAML imports retain false, zero, null, empty values and unknown data without writes', () => {
  const expected = { enabled: false, zero: 0, empty: '', nil: null, array: [], future: { raw: '${neverExecute()}' } }
  for (const [format, source] of [['json', JSON.stringify(expected)], ['yaml', 'enabled: false\nzero: 0\nempty: ""\nnil: null\narray: []\nfuture:\n  raw: "${neverExecute()}"\n']]) {
    const original = input(format, source), before = JSON.stringify(original)
    const result = importConfiguration(original)
    assert.deepEqual(result.document.data, expected)
    assert.deepEqual(importConfiguration(input(format, exportConfiguration(result.document))).document, result.document)
    assert.equal(JSON.stringify(original), before)
    assert.equal(result.preview.applied, false)
  }
})
test('Cordis composition preserves nested groups, explicit disabled and literal/folded block semantics', () => {
  const source = '- id: group\n  group: true\n  disabled: false\n  config:\n    - id: inert\n      name: example/inert\n      config:\n        prefix: |\n          hello\n          {{model}}\n        other: >-\n          one\n          two\n'
  const result = importConfiguration(input('cordis', source))
  const config = result.document.data[0].config[0].config
  assert.equal(config.prefix, 'hello\n{{model}}\n')
  assert.equal(config.other, 'one two')
  assert.deepEqual(importConfiguration(input('cordis', exportConfiguration(result.document))).document, result.document)
  assert.equal(result.preview.pluginExecution, 'UNAVAILABLE')
})
test('Purge two-file preset converts metadata plus agent composition without installing or enabling it', () => {
  const result = importConfiguration(input('purge-preset', { preset: 'name: inert\norder: 0\nunknown: false\n', agent: '- id: inert\n  name: example/inert\n  disabled: true\n  config:\n    secret: "1234"\n' }))
  assert.equal(result.document.data.metadata.unknown, false)
  assert.equal(result.document.data.composition[0].disabled, true)
  assert.deepEqual(importConfiguration(input('purge-preset', exportConfiguration(result.document))).document, result.document)
  assert.doesNotMatch(JSON.stringify(result.preview), /1234|example\/inert|secret|unknown/)
})
for (const [name, source] of [
  ['duplicate block key', 'secret: 1\nsecret: 2'],
  ['duplicate flow key', '{secret: 1, secret: 2}'],
  ['aliases', 'a: &secret value\nb: *secret'],
  ['executable tag', 'a: !js/function "private-source"'],
  ['standard explicit tag', 'a: !!str "1234"'],
  ['prototype pollution', '__proto__: {bad: true}'],
  ['merge key', '<<: {a: 1}'],
  ['multiple documents', 'a: 1\n---\nb: 2'],
  ['YAML 1.1 directive', '%YAML 1.1\n---\na: yes'],
  ['unsafe integer', 'a: 9007199254740993'],
  ['non-finite', 'a: .inf'],
  ['non-string map key', 'false: data'],
]) test(`configuration import rejects ${name} without echoing sensitive source`, () => {
  assert.throws(() => importConfiguration(input('yaml', source)), error => error.message === 'configuration import rejected: invalid, ambiguous, unsupported or excessive data')
})
test('Cordis ambiguity, unsupported format/envelope and complexity fail closed', () => {
  for (const source of ['- id: x\n  name: p\n- id: x\n  name: q', '- id: x\n  name: p\n  disabled: "false"', '- id: x\n  group: true\n  config: {}']) assert.throws(() => importConfiguration(input('cordis', source)), /rejected/)
  assert.throws(() => importConfiguration({ ...input('yaml', 'a: 1'), execute: true }), /rejected/)
  assert.throws(() => importConfiguration(input('yaml', 'a: ' + 'x'.repeat(1024 * 1024))), /rejected/)
  assert.throws(() => importConfiguration(input('json', '{"private":1,"private":2}')), /rejected/)
  assert.throws(() => importConfiguration(input('yaml', Array.from({ length: 30 }, (_, i) => `${' '.repeat(i)}a:`).join('\n'))), /rejected/)
})
async function readTree(root) {
  const rows = []
  for (const row of await readdir(root, { withFileTypes: true })) rows.push(row.isDirectory() ? await readTree(join(root, row.name)) : await readFile(join(root, row.name), 'utf8'))
  return rows.join('\n')
}
test('actual CLI and MCP/Core convert, persist redacted evidence/report, reject writes and workspace escape', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ab-config-format-')); t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace'); await mkdir(workspace)
  const file = join(workspace, 'import.json'), outside = join(root, 'outside.json'), stateRoot = join(root, 'state')
  const source = JSON.stringify(input('yaml', 'privatePin: "1234"\nprivatePassword: "pass"\nprivateEnum: enabled\n'))
  await writeFile(file, source); await writeFile(outside, source)
  const principal = { id: 'config-format-test', kind: 'local-user', workspaces: [workspace] }
  const { server, engine } = await createMcpServer({ principal, workspaceId: workspace, stateRoot }); t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const call = async args => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: args } })))
  const result = await call({ capability: 'configuration.convert', target: file })
  assert.equal(result.result.isError, false)
  const output = JSON.parse(result.result.content[0].text)
  assert.equal(output.data.status, 'CONVERTED_DATA_ONLY')
  assert.ok(output.taskId && output.reportPath && output.evidenceIds.length)
  assert.equal((await call({ capability: 'configuration.convert', target: outside })).result.isError, true)
  assert.equal((await call({ capability: 'configuration.convert', target: file, options: { apply: true } })).result.isError, true)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'config', 'convert', '--bundle', file, '--json'], { timeout: 30000, encoding: 'utf8', env: { ...process.env, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_STATE_ROOT: join(root, 'cli-state') } })
  assert.equal(cli.status, 0, cli.stderr)
  assert.deepEqual(JSON.parse(cli.stdout).data, output.data)
  const publicText = JSON.stringify(result) + cli.stdout + await readTree(stateRoot) + await readTree(join(root, 'cli-state'))
  assert.doesNotMatch(publicText, /privatePin|privatePassword|privateEnum|"1234"/)
  for (const secret of ['1234', 'pass', 'enabled', source]) for (const guess of [secret, JSON.stringify(secret)]) assert.ok(!publicText.includes(createHash('sha256').update(guess).digest('hex')), 'dictionary oracle leaked')
  assert.equal(await readFile(file, 'utf8'), source)
})
