import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { normalizeError, normalizeFinishReason, normalizeMessage, normalizeStreamEvent, normalizeToolCall, normalizeToolResult, normalizeUsage } from '../packages/provider-contract/index.js'

test('normalized provider contract round-trips roles, IDs, finish reasons and usage', async () => {
  const message = normalizeMessage({ role: 'tool', content: 'result', toolCallId: 'call_1', name: 'armorbreak_health' })
  assert.deepEqual(message, { role: 'tool', content: 'result', toolCallId: 'call_1', name: 'armorbreak_health' })
  assert.deepEqual(normalizeToolCall({ id: 'call_1', name: 'armorbreak_health', arguments: { x: 1 } }), { id: 'call_1', name: 'armorbreak_health', arguments: { x: 1 } })
  assert.deepEqual(normalizeToolResult({ toolCallId: 'call_1', content: 'ok', isError: false }), { toolCallId: 'call_1', content: 'ok', isError: false })
  assert.deepEqual(normalizeUsage({ inputTokens: 10, outputTokens: 5 }), { inputTokens: 10, outputTokens: 5, totalTokens: 15 })
  assert.equal(normalizeFinishReason('tool_calls'), 'tool_calls')
  assert.deepEqual(normalizeStreamEvent({ type: 'tool_call_delta', index: 2, toolCallId: 'call_1' }), { type: 'tool_call_delta', index: 2, toolCallId: 'call_1' })
  assert.deepEqual(normalizeError({ code: '429', message: 'rate limit', retryable: true }), { code: '429', message: 'rate limit', retryable: true })
  const contract = JSON.parse(await readFile('packages/provider-contract/contract.json', 'utf8'))
  assert.ok(contract.roles.includes('tool'))
  assert.ok(contract.finishReasons.includes('tool_calls'))
})

test('provider contract rejects malformed roles, IDs, finish reasons and indexes', () => {
  assert.throws(() => normalizeMessage({ role: 'root', content: 'x' }), /invalid role/)
  assert.throws(() => normalizeToolCall({ id: '', name: 'x' }), /tool call id/)
  assert.throws(() => normalizeFinishReason('unknown'), /invalid finish reason/)
  assert.throws(() => normalizeStreamEvent({ type: 'content_delta', index: -1 }), /non-negative/)
  assert.throws(() => normalizeUsage({ inputTokens: 1.5 }), /non-negative integer/)
})
