import assert from 'node:assert/strict'
import test from 'node:test'
import { RolloutController } from '../lib/release/rollout.js'

const passGates = { security: { status: 'PASS' }, offline: { status: 'PASS' }, supplyChain: { status: 'PASS' }, aiEvaluation: { status: 'PASS' }, compatibility: { status: 'PASS' }, performance: { status: 'PASS' } }

test('rollout requires all gates and ordered 1/10/50/100 promotion', () => {
  const blocked = new RolloutController({ gates: { ...passGates, aiEvaluation: { status: 'REVIEW' } } })
  assert.deepEqual(blocked.blockers(), ['aiEvaluation'])
  assert.throws(() => blocked.promote(1, 'alice'), /blocked/)

  const rollout = new RolloutController({ gates: passGates })
  assert.throws(() => rollout.promote(10, 'alice'), /next is 1/)
  assert.equal(rollout.promote(1, 'alice').currentStage, 1)
  assert.equal(rollout.promote(10, 'alice').currentStage, 10)
  assert.equal(rollout.promote(50, 'alice').currentStage, 50)
  assert.equal(rollout.promote(100, 'alice').currentStage, 100)
  assert.throws(() => rollout.promote(100, 'alice'), /already/)
})

test('rollback resets to zero and is audited', () => {
  const events = []
  const rollout = new RolloutController({ gates: passGates, audit: (event) => events.push(event) })
  rollout.promote(1, 'alice')
  const status = rollout.rollback('alice', 'P0 auth bypass')
  assert.equal(status.currentStage, 0)
  assert.equal(events.at(-1).action, 'rollback')
  assert.match(events.at(-1).reason, /auth/)
})
