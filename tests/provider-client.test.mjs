import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import test from 'node:test'

import { createProviderRouter } from '../packages/provider-router/index.js'
import { createProviderClient } from '../packages/provider-router/client.js'

async function mockServer(captured) {
  const server = createServer(async (req, res) => {
    let body = ''
    for await (const chunk of req) body += chunk
    captured.push({ url: req.url, headers: req.headers, body: JSON.parse(body || '{}') })
    if (req.url === '/slow/chat/completions') {
      await new Promise((resolve) => setTimeout(resolve, 500))
    }
    res.setHeader('content-type', 'application/json')
    if (req.url === '/v1/messages') {
      res.end(JSON.stringify({ content: [{ type: 'text', text: 'anthropic ok' }], usage: { input_tokens: 1, output_tokens: 2 } }))
    } else if (req.url === '/slow/chat/completions') {
      res.end(JSON.stringify({ choices: [{ message: { content: 'late' } }] }))
    } else {
      res.end(JSON.stringify({ choices: [{ message: { content: 'openai ok', tool_calls: [{ id: 't1', function: { name: 'armorbreak_health', arguments: '{}' } }] } }], usage: { total_tokens: 3 } }))
    }
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` }
}

test('OpenAI-compatible and Ollama requests carry correct auth/tool payloads', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  const router = createProviderRouter({ providers: [
    { id: 'openai', kind: 'openai-compatible', baseUrl, models: ['gpt-test'], apiKeyEnv: 'OPENAI_API_KEY', supportsTools: true },
    { id: 'ollama', kind: 'ollama', baseUrl, models: ['qwen-test'], supportsTools: false },
  ], env: { OPENAI_API_KEY: 'sk-secret' } })
  const client = createProviderClient({ router, env: { OPENAI_API_KEY: 'sk-secret' } })
  const reply = await client.chat({ model: 'gpt-test', messages: [{ role: 'user', content: 'hello' }], tools: [{ name: 'armorbreak_health', description: 'health', parameters: { type: 'object' } }] })
  assert.equal(reply.text, 'openai ok')
  assert.equal(reply.toolCalls[0].name, 'armorbreak_health')
  assert.deepEqual(reply.usage, { inputTokens: 0, outputTokens: 0, totalTokens: 3 })
  assert.equal(captured[0].headers.authorization, 'Bearer sk-secret')
  assert.equal(captured[0].body.tools[0].name, 'armorbreak_health')
  const local = await client.chat({ model: 'qwen-test', messages: [{ role: 'user', content: 'local' }] })
  assert.equal(local.text, 'openai ok')
  assert.equal(captured[1].headers.authorization, undefined)
  await new Promise((resolve) => server.close(resolve))
})

test('Anthropic request separates system and maps tool schema', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  const router = createProviderRouter({ providers: [{ id: 'anthropic', kind: 'anthropic', baseUrl, models: ['claude-test'], apiKeyEnv: 'ANTHROPIC_API_KEY', supportsTools: true }], env: { ANTHROPIC_API_KEY: 'ant-secret' } })
  const client = createProviderClient({ router, env: { ANTHROPIC_API_KEY: 'ant-secret' } })
  const reply = await client.chat({ model: 'claude-test', messages: [{ role: 'system', content: 'be exact' }, { role: 'user', content: 'hi' }], tools: [{ name: 'armorbreak_health', description: 'health', parameters: { type: 'object' } }] })
  assert.equal(reply.text, 'anthropic ok')
  assert.deepEqual(reply.usage, { inputTokens: 1, outputTokens: 2, totalTokens: 3 })
  assert.equal(captured[0].headers['x-api-key'], 'ant-secret')
  assert.equal(captured[0].headers['anthropic-version'], '2023-06-01')
  assert.equal(captured[0].body.system, 'be exact')
  assert.equal(captured[0].body.messages.length, 1)
  assert.equal(captured[0].body.tools[0].input_schema.type, 'object')
  await new Promise((resolve) => server.close(resolve))
})

test('timeouts fail closed without leaking credentials', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  const router = createProviderRouter({ providers: [{ id: 'slow', kind: 'openai-compatible', baseUrl: `${baseUrl}/slow`, models: ['slow-test'], apiKeyEnv: 'SLOW_KEY', supportsTools: false, timeoutMs: 100 }], env: { SLOW_KEY: 'sk-timeout-secret' } })
  const client = createProviderClient({ router, env: { SLOW_KEY: 'sk-timeout-secret' } })
  await assert.rejects(() => client.chat({ model: 'slow-test', messages: [{ role: 'user', content: 'wait' }] }), (error) => error.code === 'PROVIDER_TIMEOUT' && !error.message.includes('sk-timeout-secret'))
  await new Promise((resolve) => server.close(resolve))
})
