import assert from 'node:assert/strict'
import test from 'node:test'

import { runToolLoop } from '../packages/provider-router/toolLoop.js'

const message = [{ role: 'user', content: 'do it' }]
const tool = { name: 'armorbreak_health', description: 'health', parameters: { type: 'object' } }

test('tool loop preserves tool IDs and returns final text', async () => {
  const calls = []
  const client = { async chat(input) {
    calls.push(input)
    if (calls.length === 1) return { text: 'calling', toolCalls: [{ id: 'call_1', name: 'armorbreak_health', arguments: {} }], usage: { inputTokens: 10, outputTokens: 2 } }
    return { text: 'done', toolCalls: [], usage: { inputTokens: 5, outputTokens: 1 } }
  } }
  const result = await runToolLoop({ client, model: 'test', messages: message, tools: [tool], executeTool: async (call) => `result:${call.id}` })
  assert.equal(result.final, 'done')
  assert.equal(result.turns, 2)
  assert.equal(result.usage.totalTokens, 18)
  const toolMessage = result.messages.find((item) => item.role === 'tool')
  assert.equal(toolMessage.toolCallId, 'call_1')
  assert.equal(toolMessage.content, 'result:call_1')
})

test('tool loop rejects duplicate and replayed tool call ids', async () => {
  const duplicate = { async chat() { return { text: '', toolCalls: [{ id: 'same', name: 'tool' }, { id: 'same', name: 'tool' }] } } }
  await assert.rejects(() => runToolLoop({ client: duplicate, model: 'm', messages: message, tools: [], executeTool: async () => 'x' }), (error) => error.code === 'TOOL_CALL_DUPLICATE')
  let turns = 0
  const replay = { async chat() {
    turns += 1
    return { text: '', toolCalls: [{ id: 'call_replay', name: 'tool' }] }
  } }
  await assert.rejects(() => runToolLoop({ client: replay, model: 'm', messages: message, tools: [], executeTool: async () => 'x', maxTurns: 3 }), (error) => error.code === 'TOOL_CALL_REPLAY')
})

test('tool loop consumes streamed tool calls and accumulates stream events', async () => {
  let turns = 0
  const client = { async chat() { throw new Error('non-stream chat must not be used') }, async chatStream() {
    turns += 1
    if (turns === 1) return { text: '', toolCalls: [{ id: 'stream_1', name: 'armorbreak_health', arguments: {} }], eventCount: 2, usage: { inputTokens: 5, outputTokens: 1, totalTokens: 6 } }
    return { text: 'done', toolCalls: [], eventCount: 3, usage: { inputTokens: 4, outputTokens: 1, totalTokens: 5 } }
  } }
  const result = await runToolLoop({ client, model: 'm', messages: message, tools: [tool], executeTool: async () => 'ok', stream: true })
  assert.equal(result.final, 'done')
  assert.equal(result.turns, 2)
  assert.equal(result.streamEvents, 5)
  assert.equal(result.usage.totalTokens, 11)
})
test('tool loop enforces max turns, budget, deadline and retries 429', async () => {
  const endless = { async chat() { return { text: '', toolCalls: [{ id: 'call_x', name: 'tool', arguments: {} }], usage: { inputTokens: 1, outputTokens: 1 } } } }
  await assert.rejects(() => runToolLoop({ client: endless, model: 'm', messages: message, tools: [], executeTool: async () => 'x', maxTurns: 1 }), (error) => error.code === 'TOOL_LOOP_LIMIT')
  await assert.rejects(() => runToolLoop({ client: endless, model: 'm', messages: message, tools: [], executeTool: async () => 'x', budgetTokens: 1 }), (error) => error.code === 'BUDGET_EXCEEDED')
  await assert.rejects(() => runToolLoop({ client: endless, model: 'm', messages: message, tools: [], executeTool: async () => 'x', deadline: new Date(Date.now() - 1000).toISOString() }), (error) => error.code === 'DEADLINE')
  let attempts = 0
  const flaky = { async chat() { attempts += 1; if (attempts === 1) { const error = new Error('rate'); error.status = 429; throw error } return { text: 'ok', toolCalls: [] } } }
  const result = await runToolLoop({ client: flaky, model: 'm', messages: message, tools: [], executeTool: async () => 'x', sleep: async () => {} })
  assert.equal(result.final, 'ok')
  assert.equal(attempts, 2)

  for (const failure of [
    Object.assign(new Error('rate limit'), { statusCode: 429 }),
    Object.assign(new Error('rate limit'), { code: 'PROVIDER_HTTP_429' }),
    Object.assign(new Error('upstream unavailable'), { code: 'PROVIDER_HTTP_503' }),
  ]) {
    let retries = 0
    const retrying = { async chat() { retries += 1; if (retries === 1) throw failure; return { text: 'recovered', toolCalls: [] } } }
    const retried = await runToolLoop({ client: retrying, model: 'm', messages: message, tools: [], executeTool: async () => 'x', sleep: async () => {} })
    assert.equal(retried.final, 'recovered')
    assert.equal(retries, 2)
  }

  let deniedRetries = 0
  const denied = { async chat() { deniedRetries += 1; throw Object.assign(new Error('unauthorized'), { code: 'PROVIDER_HTTP_401' }) } }
  await assert.rejects(() => runToolLoop({ client: denied, model: 'm', messages: message, tools: [], executeTool: async () => 'x', sleep: async () => {} }), /unauthorized/)
  assert.equal(deniedRetries, 1, 'non-retryable provider errors must not be retried')
})
