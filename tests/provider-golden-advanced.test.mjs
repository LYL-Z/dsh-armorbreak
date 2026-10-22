import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import test from 'node:test'

import { createProviderClient } from '../packages/provider-router/client.js'
import { createProviderRouter } from '../packages/provider-router/index.js'
import { runToolLoop } from '../packages/provider-router/toolLoop.js'

const tool = { name: 'armorbreak_health', description: 'health', parameters: { type: 'object', properties: {} } }

function clientFor(baseUrl) {
  const env = { TEST_KEY: 'test-key' }
  const router = createProviderRouter({ providers: [{ id: 'test', kind: 'openai-compatible', baseUrl: `${baseUrl}/v1`, models: ['test-model'], apiKeyEnv: 'TEST_KEY', supportsTools: true }], env })
  return createProviderClient({ router, env })
}

test('golden invalid parameters fail before any provider request', async () => {
  const client = clientFor('http://127.0.0.1:1')
  await assert.rejects(() => client.chat({ model: 'test-model', messages: [{ role: 'user', content: 'x' }], maxTokens: 0 }), (error) => error.code === 'REQUEST_INVALID')
})

test('golden multi-turn tool loop executes and respects the token budget', async () => {
  let turn = 0
  const execute = []
  const fake = {
    async chat() {
      turn += 1
      if (turn === 1) return { text: '', toolCalls: [{ id: 'call_1', name: 'armorbreak_health', arguments: {} }], usage: { inputTokens: 10, outputTokens: 2, totalTokens: 12 } }
      return { text: 'DONE', toolCalls: [], usage: { inputTokens: 3, outputTokens: 1, totalTokens: 4 } }
    },
  }
  const result = await runToolLoop({
    client: fake, model: 'test-model', tools: [tool], maxTurns: 2, maxRetries: 0, budgetTokens: 100,
    messages: [{ role: 'user', content: 'call health' }],
    executeTool: async (call) => { execute.push(call.name); return JSON.stringify({ ok: true }) },
  })
  assert.equal(result.turns, 2)
  assert.equal(result.final, 'DONE')
  assert.deepEqual(execute, ['armorbreak_health'])

  const overBudget = {
    async chat() { return { text: '', toolCalls: [{ id: 'call_b', name: 'armorbreak_health', arguments: {} }], usage: { inputTokens: 80, outputTokens: 30, totalTokens: 110 } } },
  }
  await assert.rejects(() => runToolLoop({ client: overBudget, model: 'x', messages: [{ role: 'user', content: 'x' }], tools: [tool], executeTool: async () => '{}', budgetTokens: 50 }), (error) => error.code === 'BUDGET_EXCEEDED')
})

test('golden SSE ignores malformed events and tolerates a truncated stream', async () => {
  const server = createServer((req, res) => {
    req.resume()
    res.setHeader('content-type', 'text/event-stream')
    res.write('data: {not-json}\n\n')
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'partial' } }] })}\n\n`)
    res.end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    const reply = await clientFor(`http://127.0.0.1:${server.address().port}`).chatStream({ model: 'test-model', messages: [{ role: 'user', content: 'x' }], maxTokens: 32 })
    assert.equal(reply.text, 'partial')
    assert.equal(reply.eventCount, 1)
    assert.equal(reply.finishReason, null)
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
})
