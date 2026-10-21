import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
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
