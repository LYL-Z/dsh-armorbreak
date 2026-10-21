import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createMcpServer } from '../packages/mcp-server/index.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-mcp-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-mcp-ws-'))
  const { server, engine } = await createMcpServer({
    stateRoot, workspaceId: workspace,
    principal: { id: 'mcp-local', kind: 'local-user', workspaces: [workspace] },
  })
  return { server, engine, workspace }
}

test('MCP initialize, tools/list and tools/call capabilities', async () => {
  const { server, engine } = await fixture()
  const init = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }))
  const initialized = JSON.parse(init)
  assert.equal(initialized.result.protocolVersion, '2025-06-18')
  assert.equal(initialized.result.serverInfo.name, 'armorbreak')
  const list = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })))
  assert.ok(list.result.tools.some((tool) => tool.name === 'armorbreak_health'))
  assert.ok(list.result.tools.some((tool) => tool.name === 'armorbreak_capabilities'))
  const call = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'armorbreak_capabilities', arguments: {} } })))
  assert.equal(call.result.isError, false)
  const payload = JSON.parse(call.result.content[0].text)
  assert.equal(payload.length, 46)
  await engine.close()
})

test('MCP fails closed before initialize, on unknown tools and parse errors', async () => {
  const { server, engine } = await fixture()
  const before = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })))
  assert.equal(before.error.code, -32002)
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize' }))
  const unknown = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'rm_rf', arguments: {} } })))
  assert.equal(unknown.error.code, -32602)
  const malformed = JSON.parse(await server.handleLine('{not json'))
  assert.equal(malformed.error.code, -32700)
  assert.equal(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })), null)
  await engine.close()
})


test('MCP armorbreak_analyze performs a real L0 task and report', async () => {
  const { server, engine, workspace } = await fixture()
  await writeFile(join(workspace, 'sample.txt'), 'armorbreak mcp l0 test\n')
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const response = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'forensics.hash', target: join(workspace, 'sample.txt') } } })))
  assert.equal(response.result.isError, false, response.result.content?.[0]?.text)
  const result = JSON.parse(response.result.content[0].text)
  assert.equal(result.state, 'COMPLETED')
  assert.equal(result.capability, 'forensics.hash')
  assert.match(result.targetSha256, /^[a-f0-9]{64}$/)
  assert.ok(result.evidenceIds.length >= 1)
  assert.ok(result.reportPath)
  const taskRaw = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'armorbreak_task_get', arguments: { taskId: result.taskId } } }))
  const task = JSON.parse(JSON.parse(taskRaw).result.content[0].text || '{}')
  assert.equal(task.id, result.taskId)
  const evidenceRaw = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'armorbreak_evidence', arguments: { taskId: result.taskId } } }))
  const evidence = JSON.parse(JSON.parse(evidenceRaw).result.content[0].text)
  assert.ok(evidence.evidence.length >= 1)
  const reportRaw = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'armorbreak_report', arguments: { taskId: result.taskId } } }))
  const report = JSON.parse(JSON.parse(reportRaw).result.content[0].text)
  assert.match(report.markdown, /完整性|哈希|ArmorBreak/)
  const resources = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'resources/list' })))
  assert.ok(resources.result.resources.some((resource) => resource.uri.endsWith(result.taskId)))
  const reportResource = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'resources/read', params: { uri: `armorbreak://report/${result.taskId}` } })))
  assert.match(reportResource.result.contents[0].text, /ArmorBreak/)
  const prompts = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'prompts/list' })))
  assert.ok(prompts.result.prompts.some((prompt) => prompt.name === 'armorbreak-triage'))
  const prompt = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'prompts/get', params: { name: 'armorbreak-triage' } })))
  assert.equal(prompt.result.messages[0].role, 'user')
  const outside = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'forensics.hash', target: 'C:\\Windows\\win.ini' } } })))
  assert.equal(outside.result.isError, true)
  await engine.close()
})
