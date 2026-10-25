import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ApprovalAuthority } from '../lib/control/approvalAuthority.js'
import { createEngine } from '../packages/engine-node/index.js'
import { createMcpHttpServer } from '../packages/mcp-server/http.js'

test('multi-client cross-workspace task read/cancel/approval are denied', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-xclient-state-'))
  const wsA = await mkdtemp(join(tmpdir(), 'abm-xclient-a-'))
  const wsB = await mkdtemp(join(tmpdir(), 'abm-xclient-b-'))
  const alice = { id: 'alice', kind: 'local-user', workspaces: [wsA] }
  const bob = { id: 'bob', kind: 'local-user', workspaces: [wsB] }
  const engineA = await createEngine({ stateRoot, principals: [alice, bob] })
  const engineB = await createEngine({ stateRoot, principals: [alice, bob] })
  const ctxA = { principal: { id: 'alice', kind: 'local-user' }, workspaceId: wsA, requestId: 'a1', traceId: 'a1' }
  const ctxB = { principal: { id: 'bob', kind: 'local-user' }, workspaceId: wsB, requestId: 'b1', traceId: 'b1' }
  const task = await engineA.createTask(ctxA, { title: 'alice task', targetKind: 'none' })
  await assert.rejects(() => engineB.getTask(ctxB, task.id), (error) => error.code === 'POLICY_DENIED')
  await assert.rejects(() => engineB.cancelTask(ctxB, task.id), (error) => error.code === 'POLICY_DENIED')
  assert.equal((await engineA.getTask(ctxA, task.id)).id, task.id)

  const authority = new ApprovalAuthority({ stateRoot })
  const token = authority.issue({ id: 'appr-x', riskLevel: 'L1', taskId: task.id, target: wsA, operator: 'alice' }).token
  await assert.rejects(() => engineB.verifyApproval(ctxB, { riskLevel: 'L1', taskId: task.id, target: wsA, approvalToken: token }), (error) => error.code === 'TOKEN_BINDING_MISMATCH')

  const server = await createMcpHttpServer({ engine: engineA, principal: alice, workspaceId: wsA, allowUnauthenticatedLoopback: true })
  try {
    const init = await fetch(server.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }) })
    assert.equal(init.status, 200)
    const sessionA = init.headers.get('mcp-session-id')
    const sessionTask = await engineA.createTask({ ...ctxA, connectionId: sessionA, requestId: 'mcp-session-task', traceId: 'mcp-session-task' }, { title: 'alice session task', targetKind: 'none' })
    const sessionHeaders = { 'content-type': 'application/json', 'mcp-session-id': sessionA }
    const call = await fetch(server.url, { method: 'POST', headers: sessionHeaders, body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_task_get', arguments: { taskId: sessionTask.id } } }) })
    const body = await call.json()
    assert.equal(body.result.isError, false)
    const secondInit = await fetch(server.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'initialize' }) })
    const sessionB = secondInit.headers.get('mcp-session-id')
    assert.notEqual(sessionB, sessionA)
    const denied = await fetch(server.url, { method: 'POST', headers: { 'content-type': 'application/json', 'mcp-session-id': sessionB }, body: JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'armorbreak_task_get', arguments: { taskId: sessionTask.id } } }) })
    const deniedBody = await denied.json()
    assert.equal(deniedBody.result.isError, true)
  } finally {
    await server.close()
    await engineA.close()
    await engineB.close()
  }
})
