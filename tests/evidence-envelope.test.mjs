import assert from 'node:assert/strict'
import test from 'node:test'

import { createEvidenceEnvelope, createEventEnvelope } from '../packages/core/index.js'
import dshAdapter from '../packages/adapter-dsh/index.js'

const ctx = { principal: { id: 'alice', kind: 'local-user' }, workspaceId: '/work', requestId: 'req-1', traceId: 'trace-1' }
const hash = 'a'.repeat(64)

test('evidence envelope pins identifiers and redacts secrets', () => {
  const envelope = createEvidenceEnvelope({
    ctx, taskId: 'task-1', origin: 'cli', targetHash: hash,
    payload: { apiKey: 'super-secret', nested: { authorization: 'Bearer xyz', safe: 'ok' } },
  })
  assert.equal(envelope.traceId, 'trace-1')
  assert.equal(envelope.principalId, 'alice')
  assert.equal(envelope.payload.apiKey, '[REDACTED]')
  assert.equal(envelope.payload.nested.authorization, '[REDACTED]')
  assert.equal(envelope.payload.nested.safe, 'ok')
  assert.equal(JSON.stringify(envelope).includes('super-secret'), false)
  assert.match(envelope.payloadSha256, /^[a-f0-9]{64}$/)
})

test('event envelope and invalid identifiers fail closed', () => {
  const event = createEventEnvelope({ ctx, taskId: 'task-1', origin: 'mcp', targetHash: hash, event: 'task.started', payload: {} })
  assert.equal(event.type, 'event')
  assert.equal(event.event, 'task.started')
  assert.throws(() => createEvidenceEnvelope({ ctx, taskId: 'task-1', origin: 'cli', targetHash: 'bad', payload: {} }), /targetHash/)
})

test('the DSH adapter is a thin shim over the legacy exports', () => {
  assert.equal(typeof dshAdapter.apply, 'function')
  assert.equal(typeof dshAdapter.inject, 'object')
})
