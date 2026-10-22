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
})
