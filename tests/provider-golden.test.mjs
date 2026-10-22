import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { createProviderClient } from '../packages/provider-router/client.js'
import { createProviderRouter } from '../packages/provider-router/index.js'

async function runCase(family, item) {
  const captured = []
  const server = createServer(async (req, res) => {
    let body = ''
    for await (const chunk of req) body += chunk
    captured.push({ url: req.url, body: JSON.parse(body || '{}') })
    if (item.status) { res.statusCode = item.status; res.end(JSON.stringify({ error: { message: 'golden error' } })); return }
    if (item.stream) {
      res.setHeader('content-type', 'text/event-stream')
      for (const event of item.events) res.write(`data: ${JSON.stringify(event)}\n\n`)
      res.end()
      return
    }
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify(item.response))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const baseUrl = `http://127.0.0.1:${server.address().port}`
  const router = createProviderRouter({ providers: [{ id: family.id, kind: family.kind, baseUrl: `${baseUrl}${family.prefix}`, models: [family.model], apiKeyEnv: family.keyEnv, supportsTools: true }], env: { [family.keyEnv]: 'test-key' } })
  const client = createProviderClient({ router, env: { [family.keyEnv]: 'test-key' } })
  try {
    if (item.expectCode) {
      await assert.rejects(() => client.chat({ model: family.model, messages: [{ role: 'user', content: 'hi' }] }), (error) => error.code === item.expectCode)
      return
    }
    const reply = item.stream
      ? await client.chatStream({ model: family.model, messages: [{ role: 'user', content: 'hi' }] })
      : await client.chat({ model: family.model, messages: [{ role: 'user', content: 'hi' }] })
    if (item.expect.text !== undefined) assert.equal(reply.text, item.expect.text)
    if (item.expect.tool) assert.equal(reply.toolCalls[0]?.name, item.expect.tool)
    assert.equal(reply.usage.totalTokens, item.expect.totalTokens)
    assert.equal(reply.finishReason, item.expect.finishReason)
    if (item.expect.minEvents) assert.ok(reply.eventCount >= item.expect.minEvents)
    assert.equal(captured.length, 1)
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
}

test('golden fixtures cover text, tool, stream and error for four provider protocols', async () => {
  const manifest = JSON.parse(await readFile('fixtures/provider-protocols/manifest.json', 'utf8'))
  assert.equal(manifest.families.length, 4)
  for (const family of manifest.families) {
    for (const item of family.cases) {
      await runCase(family, item)
    }
  }
})
