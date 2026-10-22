import assert from 'node:assert/strict'
import test from 'node:test'

import { decideGray } from '../lib/release/gray.js'

test('gray rollout continues only when every safety condition holds', () => {
  assert.equal(decideGray({ stage: 5, gatePass: true, evidenceValid: true, l3Denied: true }).decision, 'CONTINUE')
  for (const [name, input] of [
    ['gate', { gatePass: false }],
    ['evidence', { evidenceValid: false }],
    ['l3', { l3Denied: false }],
    ['rollback', { installRollbackFailed: true }],
    ['errors', { errorRate: 0.02 }],
  ]) {
    const result = decideGray({ stage: 25, gatePass: true, evidenceValid: true, l3Denied: true, ...input })
    assert.equal(result.decision, 'ROLLBACK', name)
    assert.ok(result.reasons.length > 0)
  }
})
