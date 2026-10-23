import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import test from 'node:test'

import { createProviderClient } from '../packages/provider-router/client.js'
import { ProviderPolicy } from '../packages/provider-router/policy.js'
import { createProviderRouter } from '../packages/provider-router/index.js'

const message = [{ role: 'user', content: 'egress test' }]

function routerFor(baseUrl, kind = 'anthropic') {
  return createProviderRouter({
    providers: [{ id: 'provider', kind, baseUrl, models: ['provider-test'], apiKeyEnv: 'PROVIDER_KEY' }],
    env: { PROVIDER_KEY: 'egress-test-secret' },
  })
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return `http://127.0.0.1:${server.address().port}`
}

async function close(server) {
  if (server?.listening) await new Promise((resolve) => server.close(resolve))
}

test('default egress policy blocks an unapproved provider origin before chat or stream sends credentials', async () => {
  for (const method of ['chat', 'chatStream']) {
    let fetchCalls = 0
    const client = createProviderClient({
      router: routerFor('https://unapproved.example/v1'),
      env: { PROVIDER_KEY: 'egress-test-secret' },
      fetchImpl: async () => { fetchCalls += 1; throw new Error('fetch must not run') },
    })

    await assert.rejects(
      () => client[method]({ model: 'provider-test', messages: message }),
      (error) => error.code === 'EGRESS_DENIED',
    )
    assert.equal(fetchCalls, 0, `${method} must reject before sending the credential`)
  }
})

test('explicit policy allows a configured custom provider origin and fetch receives manual redirect mode', async () => {
  const requests = []
  const client = createProviderClient({
    router: routerFor('https://provider.example/v1', 'openai-compatible'),
    env: { PROVIDER_KEY: 'egress-test-secret' },
    policy: new ProviderPolicy({ allowedHosts: ['provider.example'] }),
    fetchImpl: async (url, options) => {
      requests.push({ url, options })
      return {
        ok: true,
        status: 200,
        json: async () => ({ choices: [{ message: { content: 'approved' } }] }),
      }
    },
  })

  const reply = await client.chat({ model: 'provider-test', messages: message })
  assert.equal(reply.text, 'approved')
  assert.equal(requests.length, 1)
  assert.equal(new URL(requests[0].url).hostname, 'provider.example')
  assert.equal(requests[0].options.redirect, 'manual')
})

test('host allowlisting cannot be bypassed with URL credentials or a non-standard HTTPS port', async () => {
  for (const baseUrl of ['https://user:password@provider.example/v1', 'https://provider.example:8443/v1']) {
    let fetchCalls = 0
    const client = createProviderClient({
      router: routerFor(baseUrl, 'openai-compatible'),
      env: { PROVIDER_KEY: 'egress-test-secret' },
      policy: new ProviderPolicy({ allowedHosts: ['provider.example'] }),
      fetchImpl: async () => { fetchCalls += 1; throw new Error('fetch must not run') },
    })
    await assert.rejects(
      () => client.chat({ model: 'provider-test', messages: message }),
      (error) => error.code === (baseUrl.includes('@') ? 'EGRESS_INVALID' : 'EGRESS_DENIED'),
    )
    assert.equal(fetchCalls, 0)
  }
})

test('chat and stream reject provider redirects without forwarding credentials to the redirect target', async () => {
  for (const method of ['chat', 'chatStream']) {
    let receivedCredential = null
    const destination = createServer((req, res) => {
      receivedCredential = req.headers['x-api-key'] ?? null
      res.end(JSON.stringify({ content: [{ type: 'text', text: 'redirected' }] }))
    })
    const destinationUrl = await listen(destination)
    const source = createServer((req, res) => {
      res.writeHead(302, { location: `${destinationUrl}/v1/messages` })
      res.end()
    })
    const sourceUrl = await listen(source)

    try {
      const client = createProviderClient({
        router: routerFor(sourceUrl),
        env: { PROVIDER_KEY: 'egress-test-secret' },
      })
      await assert.rejects(
        () => client[method]({ model: 'provider-test', messages: message }),
        (error) => error.code === 'PROVIDER_REDIRECT_DENIED',
      )
      assert.equal(receivedCredential, null, `${method} must not send credentials to a redirect target`)
    } finally {
      await close(source)
      await close(destination)
    }
  }
})
