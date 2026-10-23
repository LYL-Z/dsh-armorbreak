import assert from 'node:assert/strict'
import { PassThrough } from 'node:stream'
import test from 'node:test'

import { confirmInteractiveApproval } from '../packages/cli/approvalPrompt.js'

test('approval confirmation refuses non-terminal streams', async () => {
  await assert.rejects(
    () => confirmInteractiveApproval({ action: 'APPROVE L2', expected: 'APPROVE L2 task target', input: new PassThrough(), output: new PassThrough() }),
    (error) => error.code === 'INTERACTIVE_APPROVAL_REQUIRED',
  )
})

test('approval confirmation asks for the exact phrase on a terminal stream', async () => {
  const input = new PassThrough()
  const output = new PassThrough()
  Object.defineProperty(input, 'isTTY', { value: true })
  Object.defineProperty(output, 'isTTY', { value: true })
  const expected = 'APPROVE INSTALL plan-0123456789abcdef ' + 'a'.repeat(64)
  const pending = confirmInteractiveApproval({ action: 'APPROVE INSTALLATION', details: ['artifact sha256: ' + 'b'.repeat(64)], expected, input, output })
  input.write(expected + '\n')
  await pending
  input.destroy()
  output.destroy()
})

test('approval confirmation rejects a different phrase', async () => {
  const input = new PassThrough()
  const output = new PassThrough()
  Object.defineProperty(input, 'isTTY', { value: true })
  Object.defineProperty(output, 'isTTY', { value: true })
  const pending = confirmInteractiveApproval({ action: 'APPROVE L2', expected: 'APPROVE L2 exact-target', input, output })
  input.write('APPROVE L2 other-target\n')
  await assert.rejects(pending, (error) => error.code === 'APPROVAL_CONFIRMATION_MISMATCH')
  input.destroy()
  output.destroy()
})
