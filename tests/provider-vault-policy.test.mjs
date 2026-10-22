import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { MemorySecretVault, WindowsDpapiVault, redactSecret } from '../packages/provider-router/vault.js'
import { ProviderPolicy } from '../packages/provider-router/policy.js'

test('memory vault and redaction never expose secret values', () => {
  const vault = new MemorySecretVault({ OPENAI_API_KEY: 'sk-live-secret-12345678' })
  assert.equal(vault.get('OPENAI_API_KEY'), 'sk-live-secret-12345678')
  assert.deepEqual(vault.list(), ['OPENAI_API_KEY'])
  assert.equal(redactSecret('authorization: Bearer sk-live-secret-12345678').includes('sk-live-secret'), false)
  assert.equal(redactSecret('api_key=sk-live-secret-12345678').includes('sk-live-secret'), false)
  vault.delete('OPENAI_API_KEY')
  assert.equal(vault.get('OPENAI_API_KEY'), null)
})

test('provider policy enforces egress, budget and approved fallback', () => {
  const policy = new ProviderPolicy({ budgetTokens: 10, budgetUsd: 0.01, approvedFallbacks: ['openai->ollama'] })
  assert.deepEqual(policy.checkEgress('https://api.openai.com/v1'), { host: 'api.openai.com', loopback: false })
  assert.deepEqual(policy.checkEgress('http://127.0.0.1:11434/v1'), { host: '127.0.0.1', loopback: true })
  assert.throws(() => policy.checkEgress('http://api.openai.com/v1'), (error) => error.code === 'EGRESS_HTTPS_REQUIRED')
  assert.throws(() => policy.checkEgress('https://evil.example/v1'), (error) => error.code === 'EGRESS_DENIED')
  assert.deepEqual(policy.checkBudget({ tokens: 4, costUsd: 0.004 }), { usedTokens: 4, usedUsd: 0.004 })
  assert.throws(() => policy.checkBudget({ tokens: 7 }), (error) => error.code === 'BUDGET_EXCEEDED')
  assert.deepEqual(policy.fallback({ from: 'openai', to: 'ollama' }), { from: 'openai', to: 'ollama', approved: true })
  assert.throws(() => policy.fallback({ from: 'openai', to: 'anthropic' }), (error) => error.code === 'FALLBACK_NOT_APPROVED')
})

test('Windows DPAPI vault persists ciphertext only and decrypts for the current user', async () => {
  if (process.platform !== 'win32') return
  const root = await mkdtemp(join(tmpdir(), 'abm-vault-'))
  const path = join(root, 'vault.json')
  const vault = new WindowsDpapiVault({ path })
  vault.set('GEMINI_API_KEY', 'gem-live-secret-abcdefgh')
  const stored = await readFile(path, 'utf8')
  assert.equal(stored.includes('gem-live-secret'), false)
  assert.deepEqual(vault.list(), ['GEMINI_API_KEY'])
  assert.equal(vault.get('GEMINI_API_KEY'), 'gem-live-secret-abcdefgh')
  assert.equal(vault.delete('GEMINI_API_KEY'), true)
  assert.deepEqual(vault.list(), [])
})
