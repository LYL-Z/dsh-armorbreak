import assert from 'node:assert/strict'
import test from 'node:test'

import { ProviderRouter, createProviderRouter } from '../packages/provider-router/index.js'

const providers = [
  { id: 'openai', kind: 'openai-compatible', baseUrl: 'https://api.example/v1', models: ['gpt-4.1'], apiKeyEnv: 'OPENAI_API_KEY', supportsTools: true },
  { id: 'anthropic', kind: 'anthropic', baseUrl: 'https://anthropic.example', models: ['claude-sonnet-4-5'], apiKeyEnv: 'ANTHROPIC_API_KEY', supportsTools: true },
  { id: 'ollama', kind: 'ollama', baseUrl: 'http://127.0.0.1:11434/v1', models: ['qwen-local'], supportsTools: false },
  { id: 'local', kind: 'local', baseUrl: 'http://127.0.0.1:8080/v1', models: ['local-tools'], supportsTools: true },
]

test('router resolves providers without exposing credentials', () => {
  const router = createProviderRouter({ providers, env: { OPENAI_API_KEY: 'sk-test', ANTHROPIC_API_KEY: 'sk-ant' } })
  const listed = router.list()
  assert.equal(listed.length, 4)
  assert.equal(JSON.stringify(listed).includes('sk-test'), false)
  const route = router.resolve({ model: 'gpt-4.1', requireTools: true })
  assert.equal(route.providerId, 'openai')
  assert.equal(route.modelIsAuthority, false)
  assert.equal(route.credentialEnv, 'OPENAI_API_KEY')
  assert.equal(JSON.stringify(route).includes('sk-test'), false)
  assert.equal(router.resolve({ model: 'local-tools' }).kind, 'local')
})

test('missing credentials, unknown models and tool mismatch fail closed', () => {
  const router = createProviderRouter({ providers, env: {} })
  assert.throws(() => router.resolve({ model: 'gpt-4.1' }), (error) => error.code === 'KEY_MISSING')
  assert.throws(() => router.resolve({ model: 'unknown' }), (error) => error.code === 'MODEL_NOT_FOUND')
  assert.throws(() => router.resolve({ model: 'qwen-local', requireTools: true }), (error) => error.code === 'MODEL_UNSUPPORTED')
  assert.throws(() => router.resolve({}), (error) => error.code === 'MODEL_REQUIRED')
})

test('plaintext keys and secret-like provider fields are rejected', () => {
  assert.throws(() => new ProviderRouter({ providers: [{ ...providers[0], apiKey: 'sk-live' }] , env: {} }), (error) => error.code === 'PROVIDER_INVALID')
  assert.throws(() => new ProviderRouter({ providers: [{ ...providers[0], token: 'x' }], env: {} }), (error) => error.code === 'PROVIDER_INVALID')
  assert.throws(() => new ProviderRouter({ providers: [{ ...providers[0], timeoutMs: 99 }], env: {} }), (error) => error.code === 'PROVIDER_INVALID')
  assert.throws(() => new ProviderRouter({ providers: [], env: {} }), (error) => error.code === 'PROVIDER_INVALID')
})

test('example provider file is secret-free and loadable', async () => {
  const { readFile } = await import('node:fs/promises')
  const example = JSON.parse(await readFile('packages/provider-router/providers.example.json', 'utf8'))
  assert.equal(example.providers.length, 6)
  assert.equal(JSON.stringify(example).includes('sk-'), false)
  const router = new ProviderRouter({ providers: example.providers, env: {} })
  assert.throws(() => router.resolve({ model: 'gpt-4.1' }), (error) => error.code === 'KEY_MISSING')
  assert.equal(router.resolve({ model: 'local-model' }).kind, 'local')
})
