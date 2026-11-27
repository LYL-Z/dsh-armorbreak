// SPDX-FileCopyrightText: 2026 LYL-Z
// SPDX-License-Identifier: MIT
import test from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { CONFIG_EDIT_SCHEMA, parseConfigurationEdit, prepareConfigurationEdit } from '../lib/integrations/configEdit.js'
import { IMPORT_SCHEMA, importConfiguration } from '../lib/integrations/configFormats.js'
import { runCli } from '../packages/cli/index.js'
import { createMcpServer } from '../packages/mcp-server/index.js'

const input = (format, source, operations) => ({
  schema: CONFIG_EDIT_SCHEMA, configuration: { schema: IMPORT_SCHEMA, format, source }, operations,
})

test('configuration edits are ordered, type-aware and leave original copies untouched', () => {
  const request = input('json', '{"map":{"0":false,"a/b~c":"old"},"items":[0,null]}\r\n', [
    { op: 'replace', path: ['map', '0'], expected: false, value: null },
    { op: 'add', path: ['items', 1], value: false },
    { op: 'remove', path: ['items', 2], expected: null },
    { op: 'add', path: ['items', 2], value: {} },
    { op: 'remove', path: ['map', 'a/b~c'], expected: 'old' },
  ])
  const original = structuredClone(request)
  const { candidate, preview } = prepareConfigurationEdit(request)
  assert.deepEqual(JSON.parse(candidate), { map: { 0: null }, items: [0, false, {}] })
  assert.deepEqual(preview.operations, { add: 2, replace: 1, remove: 2 })
  assert.equal(preview.status, 'PREVIEW_READY')
  assert.deepEqual(request, original)
})

test('edit preconditions and bounds reject ambiguous, stale and invalid batches', () => {
  const source = '{"map":{"value":false},"items":[0]}'
  const valid = { op: 'add', path: ['map', 'new'], value: false }
  const failures = [
    [{ op: 'replace', path: ['map', 'value'], expected: 'false', value: 1 }, /VALUE_CONFLICT/],
    [{ op: 'remove', path: ['map', 'new'], expected: 1 }, /VALUE_CONFLICT/],
    [{ op: 'add', path: ['map', 'value'], value: 1 }, /PATH_CONFLICT/],
    [{ op: 'add', path: ['items', 2], value: 1 }, /PATH_CONFLICT/],
    [{ op: 'add', path: ['items', '0'], value: 1 }, /PATH_INVALID/],
    [{ op: 'add', path: ['map', 0], value: 1 }, /PATH_INVALID/],
    [{ op: 'add', path: ['map', 'value', 'inner'], value: 1 }, /PATH_INVALID/],
    [{ op: 'add', path: ['map', '__proto__'], value: { dangerous: true } }, /PATH_INVALID/],
    [{ op: 'remove', path: ['map', 'value'] }, /OPERATION_INVALID/],
    [{ op: 'replace', path: [], expected: {}, value: {} }, /PATH_INVALID/],
  ]
  for (const [operation, error] of failures) {
    assert.throws(() => prepareConfigurationEdit(input('json', source, [valid, operation])), error)
  }
  assert.throws(() => prepareConfigurationEdit(input('json', source, Array(129).fill(valid))), /REQUEST_INVALID/)
  assert.throws(() => prepareConfigurationEdit(input('json', source, [{ ...valid, value: Number.MAX_SAFE_INTEGER + 1 }])), /import rejected/)
  const duplicate = JSON.stringify(input('json', source, [valid])).replace('"op":"add"', '"op":"remove","op":"add"')
  assert.throws(() => parseConfigurationEdit(Buffer.from(duplicate)), /import rejected/)
  assert.throws(() => parseConfigurationEdit(Buffer.from([255])), /INVALID_JSON/)
  const unchanged = prepareConfigurationEdit(input('json', source, [valid, { op: 'remove', path: valid.path, expected: false }]))
  assert.equal(unchanged.preview.status, 'NO_CHANGES')
  assert.equal(unchanged.candidate, source)
})

test('YAML and Cordis edits preserve compatible comments, and an untouched preset part keeps exact bytes', () => {
  const agent = '- id: one # first component\r\n  name: example/inert\r\n- id: two # second component\r\n  name: example/inert\r\n'
  const change = [{ op: 'remove', path: [0], expected: { id: 'one', name: 'example/inert' } }]
  const cordis = prepareConfigurationEdit(input('cordis', agent, change))
  assert.match(cordis.candidate, /^- id: two # second component\r\n/)
  assert.doesNotMatch(cordis.candidate, /first component/)
  assert.throws(() => prepareConfigurationEdit(input('cordis', agent, [
    { op: 'replace', path: [1, 'id'], expected: 'two', value: 'one' },
  ])), /import rejected/)

  const yaml = 'secret: "old" # keep\r\nfuture: false\r\n'
  const update = { op: 'replace', path: ['secret'], expected: 'old', value: 'new' }
  assert.equal(prepareConfigurationEdit(input('yaml', yaml, [update])).candidate, 'secret: "new" # keep\r\nfuture: false\r\n')

  const source = { preset: '{name: "unchanged"   } # unusual formatting\r\n', agent }
  const operations = change.map(operation => ({ ...operation, path: ['composition', ...operation.path] }))
  const preset = prepareConfigurationEdit(input('purge-preset', source, operations)).candidate
  assert.equal(preset.preset, source.preset)
  assert.equal(preset.agent, cordis.candidate)
})

async function readTree(root) {
  const children = await readdir(root, { withFileTypes: true })
  return (await Promise.all(children.map(child => {
    const path = join(root, child.name)
    return child.isDirectory() ? readTree(path) : readFile(path, 'utf8')
  }))).join('\n')
}

test('CLI and MCP share redacted Core preview; trusted CLI applies and rolls back both files', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ab-config-edit-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace')
  await mkdir(workspace)
  const file = join(workspace, 'input.json'), outside = join(root, 'outside.json')
  const source = {
    preset: '# private-annotation\r\nname: private-preset-name\r\nfuture: false\r\n',
    agent: '- id: private-item\r\n  name: example/inert\r\n  config:\r\n    private-key: "old-private-value" # keep\r\n',
  }
  const request = input('purge-preset', source, [
    { op: 'replace', path: ['metadata', 'name'], expected: 'private-preset-name', value: 'next-private-name' },
    { op: 'replace', path: ['composition', 0, 'config', 'private-key'], expected: 'old-private-value', value: 'new-private-value' },
    { op: 'remove', path: ['metadata', 'future'], expected: false },
  ])
  await writeFile(file, JSON.stringify(request))
  await writeFile(outside, JSON.stringify(request))
  const env = { ...process.env, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_STATE_ROOT: join(root, 'cli-state'), ARMORBREAK_PRINCIPAL_ID: 'edit-test' }
  const cli = (...args) => execFileSync(process.execPath, ['packages/cli/index.js', 'config', ...args], { env, encoding: 'utf8', timeout: 30000 })
  const preview = JSON.parse(cli('edit', '--bundle', file, '--json'))
  assert.equal(preview.state, 'COMPLETED')
  assert.equal(preview.targetSha256, null)
  assert.match(cli('edit', '--bundle', file), /PREVIEW_READY \(0 add, 2 replace, 1 remove\)/)

  const stateRoot = join(root, 'mcp-state')
  const principal = { id: 'edit-test', kind: 'local-user', workspaces: [workspace] }
  const { server, engine } = await createMcpServer({ principal, workspaceId: workspace, stateRoot })
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const call = async target => JSON.parse(await server.handleLine(JSON.stringify({
    jsonrpc: '2.0', id: 2, method: 'tools/call',
    params: { name: 'armorbreak_analyze', arguments: { capability: 'configuration.preview', target, options: { mode: 'edit' } } },
  }))).result
  try {
    const response = await call(file)
    assert.equal(response.isError, false)
    assert.deepEqual(JSON.parse(response.content[0].text).data, preview.data)
    assert.equal((await call(outside)).isError, true)
    const publicText = JSON.stringify(response) + JSON.stringify(preview) + await readTree(stateRoot) + await readTree(env.ARMORBREAK_STATE_ROOT)
    for (const secret of ['private-key', 'private-preset-name', 'old-private-value', 'new-private-value', 'private-annotation', JSON.stringify(request)]) {
      assert.equal(publicText.includes(secret), false)
      assert.equal(publicText.includes(createHash('sha256').update(secret).digest('hex')), false)
    }
  } finally {
    await engine.close()
  }

  const calls = []
  const dependencies = { env, agent: 'test-agent', callId: 'test-call', sessionId: 'edit-session',
    approvalProvider: { request: async request => { calls.push(request.operation); return 'allowed-once' } } }
  const hostCli = async (...args) => {
    let output = ''
    const original = process.stdout.write
    process.stdout.write = chunk => { output += chunk; return true }
    try {
      await runCli(['config', ...args, '--json'], dependencies)
      return JSON.parse(output)
    } finally {
      process.stdout.write = original
    }
  }
  const stage = await hostCli('stage', '--bundle', file)
  t.after(() => rm(stage.lab, { recursive: true, force: true }))
  assert.equal(stage.preview.approvalRequired, true)
  assert.equal(stage.hostModified, false)
  const plan = ['--lab', stage.lab, '--plan', stage.planId]
  assert.throws(() => cli('apply', ...plan, '--json'), /TRUSTED_APPROVAL_PROVIDER_REQUIRED/)
  assert.equal((await hostCli('apply', ...plan)).state, 'COMMITTED')
  const revised = {
    preset: await readFile(join(stage.lab, 'data', 'preset.txt'), 'utf8'),
    agent: await readFile(join(stage.lab, 'data', 'agent.txt'), 'utf8'),
  }
  assert.match(revised.agent, /"new-private-value" # keep\r\n/)
  const privateData = importConfiguration({ ...request.configuration, source: revised }).document.data
  assert.deepEqual(privateData.metadata, { name: 'next-private-name' })
  assert.equal((await hostCli('revert', ...plan)).state, 'ROLLED_BACK')
  for (const part of ['preset', 'agent']) {
    assert.deepEqual(await readFile(join(stage.lab, 'data', part + '.txt')), Buffer.from(source[part]))
  }
  assert.deepEqual(calls, ['apply', 'rollback'])
  assert.equal(await readFile(file, 'utf8'), JSON.stringify(request))
})
