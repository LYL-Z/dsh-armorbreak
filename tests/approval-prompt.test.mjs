import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import test from 'node:test'

import { confirmInteractiveApproval, requestTrustedHostApproval } from '../packages/cli/approvalPrompt.js'

test('a caller-controlled terminal cannot prove human approval even when it echoes the exact phrase', async () => {
  const input = new PassThrough()
  const output = new PassThrough()
  Object.defineProperty(input, 'isTTY', { value: true })
  Object.defineProperty(output, 'isTTY', { value: true })
  const expected = 'APPROVE INSTALL plan-0123456789abcdef ' + 'a'.repeat(64)

  await assert.rejects(
    () => confirmInteractiveApproval({ action: 'APPROVE INSTALLATION', expected, input, output }),
    (error) => error.code === 'TRUSTED_APPROVAL_PROVIDER_REQUIRED',
  )
  input.write(expected + '\n')
  input.destroy()
  output.destroy()
})

test('trusted approval provider receives host context and one-shot approval is required', async () => {
  const calls = []
  const request = {
    agent: 'host-agent-1',
    toolName: 'ignored-caller-value',
    callId: 'host-call-1',
    sessionId: 'host-session-1',
    reason: 'approve a scoped synthetic action',
  }
  const outcome = await requestTrustedHostApproval({
    async request(input) {
      calls.push(input)
      return 'allowed-once'
    },
  }, request)

  assert.equal(outcome, 'allowed-once')
  assert.deepEqual(calls, [{ ...request, toolName: 'armorbreak' }])
})

test('missing, unavailable, denied, and incomplete host approval fail closed', async () => {
  const request = { agent: 'host-agent-1', callId: 'host-call-2', sessionId: 'host-session-2', reason: 'synthetic' }

  await assert.rejects(
    () => requestTrustedHostApproval(null, request),
    (error) => error.code === 'TRUSTED_APPROVAL_PROVIDER_REQUIRED',
  )
  await assert.rejects(
    () => requestTrustedHostApproval({ request: async () => 'denied' }, request),
    (error) => error.code === 'TRUSTED_APPROVAL_DENIED',
  )
  await assert.rejects(
    () => requestTrustedHostApproval({ request: async () => { throw new Error('offline') } }, request),
    (error) => error.code === 'TRUSTED_APPROVAL_DENIED',
  )
  await assert.rejects(
    () => requestTrustedHostApproval({ request: async () => 'allowed-once' }, { agent: 'host-agent-1', callId: 'host-call-3' }),
    (error) => error.code === 'TRUSTED_APPROVAL_CONTEXT_REQUIRED',
  )
})
