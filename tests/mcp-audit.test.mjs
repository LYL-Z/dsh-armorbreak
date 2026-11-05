import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createMcpServer } from '../packages/mcp-server/index.js'

test('MCP audit log records host clientInfo and tool calls without arguments', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-mcp-audit-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-mcp-audit-ws-'))
  const auditLog = join(stateRoot, 'mcp-audit.jsonl')
  const { server, engine } = await createMcpServer({
    stateRoot,
    workspaceId: workspace,
    principal: { id: 'audit-host', kind: 'local-user', workspaces: [workspace] },
    auditLog,
  })
  await server.handleLine(JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', clientInfo: { name: 'cursor', version: '3.17.8' } },
  }))
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }))
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'armorbreak_health', arguments: { secret: 'must-not-be-logged' } } }))
  await engine.close()
  const lines = (await readFile(auditLog, 'utf8')).trim().split(/\r?\n/).map((line) => JSON.parse(line))
  assert.equal(lines[0].schemaVersion, 'armorbreak.mcp-audit/v1')
  assert.equal(lines[0].event, 'initialize')
  assert.deepEqual(lines[0].clientInfo, { name: 'cursor', version: '3.17.8' })
  assert.ok(lines.some((line) => line.event === 'tools/list' && line.tools === 8))
  const call = lines.find((line) => line.event === 'tools/call')
  assert.equal(call.tool, 'armorbreak_health')
  assert.equal(call.ok, true)
  assert.equal(JSON.stringify(lines).includes('must-not-be-logged'), false)
})
