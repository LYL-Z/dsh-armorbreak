import assert from 'node:assert/strict'
import test from 'node:test'
import { SCHEMA_VERSION, permissionsForRisk, toCapabilityV2, toTaskV2, validateCapabilityV2, validateTaskV2 } from '../lib/schemas/v2/index.js'

const v1Task = {
  id: 'task_1',
  title: 'sample',
  state: 'COMPLETED',
  steps: [{ id: 's1', capabilityId: 'binary.identify', status: 'DONE' }],
  approvals: [],
  stats: { evidence: 2, findings: 1 },
}

test('v1 tasks are readable, but writing adds schemaVersion and preserves fields', () => {
  assert.equal(validateTaskV2(v1Task, { allowV1: true }).valid, true)
  assert.equal(validateTaskV2(v1Task).valid, false)
  const migrated = toTaskV2(v1Task)
  assert.equal(migrated.schemaVersion, SCHEMA_VERSION)
  assert.equal(migrated.steps[0].capabilityId, 'binary.identify')
  assert.equal(validateTaskV2(migrated).valid, true)
})

test('invalid tasks are rejected rather than silently coerced', () => {
  const check = validateTaskV2({ id: '', title: '', state: 'NOPE', steps: [{}] })
  assert.equal(check.valid, false)
  assert.ok(check.errors.length >= 3)
  assert.throws(() => toTaskV2({ id: 'x', title: 'x', state: 'NOPE', steps: [] }), /cannot write task v2/)
})

test('capabilities get explicit v2 permission sets (L3 has none)', () => {
  assert.deepEqual(permissionsForRisk('L0'), ['READ', 'ANALYZE'])
  assert.deepEqual(permissionsForRisk('L1'), ['READ', 'ANALYZE', 'EXECUTE_ISOLATED'])
  assert.deepEqual(permissionsForRisk('L2'), ['READ', 'ANALYZE', 'NETWORK_L2'])
  assert.deepEqual(permissionsForRisk('L3'), [])
  const cap = toCapabilityV2({ id: 'x.y', domain: 'x', title: 't', riskLevel: 'L1' })
  assert.equal(validateCapabilityV2(cap).valid, true)
  assert.deepEqual(cap.permissions, permissionsForRisk('L1'))
})
