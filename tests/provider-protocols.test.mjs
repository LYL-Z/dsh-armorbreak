import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import test from 'node:test'

import { createProviderClient } from '../packages/provider-router/client.js'
import { createProviderRouter } from '../packages/provider-router/index.js'

async function mockServer(captured) {
  const server = createServer(async (req, res) => {
    let body = ''
    for await (const chunk of req) body += chunk
    const parsed = JSON.parse(body || '{}')
    captured.push({ url: req.url, headers: req.headers, body: parsed })
    const path = String(req.url).split('?')[0]
    if (path === '/v1/responses') {
      if (parsed.stream) {
        res.setHeader('content-type', 'text/event-stream')
        res.write(`data: ${JSON.stringify({ type: 'response.output_text.delta', delta: 'resp ' })}\n\n`)
        res.write(`data: ${JSON.stringify({ type: 'response.output_item.added', item: { id: 'item_1', type: 'function_call', call_id: 'call_r2', name: 'armorbreak_health' } })}\n\n`)
        res.write(`data: ${JSON.stringify({ type: 'response.function_call_arguments.delta', item_id: 'item_1', delta: '{}' })}\n\n`)
        res.write(`data: ${JSON.stringify({ type: 'response.completed', response: { usage: { input_tokens: 4, output_tokens: 1, total_tokens: 5 } } })}\n\n`)
        res.end()
        return
      }
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({
        status: 'completed',
        output: [
          { type: 'message', content: [{ type: 'output_text', text: 'responses ok' }] },
          { type: 'function_call', call_id: 'call_r1', name: 'armorbreak_health', arguments: '{}' },
        ],
        usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5 },
      }))
      return
    }
    if (path === '/v1/messages') {
      res.setHeader('content-type', 'text/event-stream')
      res.write(`event: message_start\ndata: ${JSON.stringify({ type: 'message_start', message: { usage: { input_tokens: 5 } } })}\n\n`)
      res.write(`event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: 'anthropic ' } })}\n\n`)
      res.write(`event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 'tool_1', name: 'armorbreak_health' } })}\n\n`)
      res.write(`event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: '{}' } })}\n\n`)
      res.write(`event: message_delta\ndata: ${JSON.stringify({ type: 'message_delta', delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 2 } })}\n\n`)
      res.end()
      return
    }
    if (path.startsWith('/v1beta/models/')) {
      const stream = path.endsWith(':streamGenerateContent')
      res.setHeader('content-type', stream ? 'text/event-stream' : 'application/json')
      if (stream) {
        res.write(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: 'gem ' }] } }] })}\n\n`)
        res.write(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ functionCall: { name: 'armorbreak_health', args: {} } }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 2, totalTokenCount: 5 } })}\n\n`)
        res.end()
        return
      }
      res.end(JSON.stringify({ candidates: [{ content: { parts: [{ text: 'gemini ok' }, { functionCall: { name: 'armorbreak_health', args: {} } }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 3, candidatesTokenCount: 2, totalTokenCount: 5 } }))
      return
    }
    res.statusCode = 404
    res.end('{}')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, baseUrl: `http://127.0.0.1:${server.address().port}` }
}

function clientFor(baseUrl) {
  const router = createProviderRouter({ providers: [
    { id: 'responses', kind: 'openai-responses', baseUrl: `${baseUrl}/v1`, models: ['resp-test'], apiKeyEnv: 'OPENAI_KEY', supportsTools: true },
    { id: 'anthropic', kind: 'anthropic', baseUrl, models: ['claude-test'], apiKeyEnv: 'ANTHROPIC_KEY', supportsTools: true },
    { id: 'gemini', kind: 'gemini', baseUrl: `${baseUrl}/v1beta`, models: ['gemini-test'], apiKeyEnv: 'GEMINI_KEY', supportsTools: true },
  ], env: { OPENAI_KEY: 'sk-test', ANTHROPIC_KEY: 'ant-test', GEMINI_KEY: 'gem-test' } })
  return createProviderClient({ router, env: { OPENAI_KEY: 'sk-test', ANTHROPIC_KEY: 'ant-test', GEMINI_KEY: 'gem-test' } })
}

const tools = [{ name: 'armorbreak_health', description: 'health', parameters: { type: 'object' } }]

test('OpenAI Responses native request/response maps text, function_call and usage', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  try {
    const reply = await clientFor(baseUrl).chat({ model: 'resp-test', messages: [{ role: 'system', content: 'be exact' }, { role: 'user', content: 'hi' }], tools })
    assert.equal(reply.text, 'responses ok')
    assert.equal(reply.toolCalls[0].name, 'armorbreak_health')
    assert.deepEqual(reply.usage, { inputTokens: 3, outputTokens: 2, totalTokens: 5 })
    assert.equal(captured[0].url, '/v1/responses')
    assert.ok(Array.isArray(captured[0].body.input))
    assert.equal(captured[0].body.tools[0].type, 'function')
  } finally { await new Promise((resolve) => server.close(resolve)) }
})

test('OpenAI Responses streaming accumulates output text, tool arguments and completion usage', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  try {
    const reply = await clientFor(baseUrl).chatStream({ model: 'resp-test', messages: [{ role: 'user', content: 'hi' }], tools })
    assert.equal(reply.text, 'resp ')
    assert.equal(reply.toolCalls[0].name, 'armorbreak_health')
    assert.deepEqual(reply.usage, { inputTokens: 4, outputTokens: 1, totalTokens: 5 })
    assert.equal(reply.finishReason, 'stop')
    assert.ok(reply.eventCount >= 3)
  } finally { await new Promise((resolve) => server.close(resolve)) }
})

test('Anthropic streaming maps text, tool_use lifecycle, stop reason and usage', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  try {
    const reply = await clientFor(baseUrl).chatStream({ model: 'claude-test', messages: [{ role: 'user', content: 'hi' }], tools })
    assert.equal(reply.text, 'anthropic ')
    assert.equal(reply.toolCalls[0].name, 'armorbreak_health')
    assert.equal(reply.finishReason, 'tool_calls')
    assert.deepEqual(reply.usage, { inputTokens: 5, outputTokens: 2, totalTokens: 7 })
    assert.equal(captured[0].body.stream, true)
  } finally { await new Promise((resolve) => server.close(resolve)) }
})

test('Gemini native request/response and streaming map contents, functionCall and usage', async () => {
  const captured = []
  const { server, baseUrl } = await mockServer(captured)
  try {
    const client = clientFor(baseUrl)
    const reply = await client.chat({ model: 'gemini-test', messages: [{ role: 'system', content: 'be exact' }, { role: 'user', content: 'hi' }], tools })
    assert.equal(reply.text, 'gemini ok')
    assert.equal(reply.toolCalls[0].name, 'armorbreak_health')
    assert.deepEqual(reply.usage, { inputTokens: 3, outputTokens: 2, totalTokens: 5 })
    assert.match(captured[0].url, /:generateContent$/)
    assert.equal(captured[0].headers['x-goog-api-key'], 'gem-test')
    assert.ok(Array.isArray(captured[0].body.contents))
    const streamed = await client.chatStream({ model: 'gemini-test', messages: [{ role: 'user', content: 'hi' }], tools })
    assert.equal(streamed.text, 'gem ')
    assert.equal(streamed.toolCalls[0].name, 'armorbreak_health')
    assert.equal(streamed.finishReason, 'stop')
    assert.deepEqual(streamed.usage, { inputTokens: 3, outputTokens: 2, totalTokens: 5 })
    assert.match(captured[1].url, /:streamGenerateContent\?alt=sse$/)
  } finally { await new Promise((resolve) => server.close(resolve)) }
})
