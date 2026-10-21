import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ApprovalAuthority, makeApprovalId } from '../lib/control/approvalAuthority.js'

async function authority(options = {}) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-appr-'))
  return new ApprovalAuthority({ stateRoot, clock: () => 1_700_000_000_000, ...options })
}

test('approval tokens are signed and bound to task/target/risk/operator', async () => {
  const manager = await authority()
  const { token, payload } = manager.issue({ id: 'appr_1', riskLevel: 'L2', taskId: 'task_1', target: 'lab.example.test:443', operator: 'operator-a' })
  assert.equal(payload.id, 'appr_1')
  assert.equal(manager.verify(token, { id: 'appr_1', taskId: 'task_1', target: 'lab.example.test:443', riskLevel: 'L2', operator: 'operator-a' }).valid, true)
  assert.equal(manager.verify(token, { taskId: 'task_2' }).valid, false)
  assert.equal(manager.verify(`${token}x`, { id: 'appr_1' }).valid, false)
  assert.equal(manager.verify(token, { operator: 'operator-b' }).valid, false)
})

test('tampering, expiry, revocation and replay are rejected', async () => {
  let now = 1_700_000_000_000
  const manager = await authority({ clock: () => now, ttlMs: 60_000 })
  const { token } = manager.issue({ id: 'appr_x', riskLevel: 'L1', taskId: 't', target: 'sample.bin', operator: 'op' })
  const [version, body, sig] = token.split('.')
  const forged = { ...JSON.parse(Buffer.from(body, 'base64url').toString('utf8')), target: 'other.bin' }
  const forgedToken = `${version}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${sig}`
  assert.equal(manager.verify(forgedToken, { id: 'appr_x' }).valid, false)
  now += 61_000
  assert.equal(manager.verify(token, { id: 'appr_x' }).code, 'TOKEN_EXPIRED')
  now -= 61_000
  manager.revoke('appr_x')
  assert.equal(manager.verify(token, { id: 'appr_x' }).code, 'TOKEN_REVOKED')
})

test('consumption is single-use and a second consume is replay', async () => {
  const manager = await authority()
  const { token } = manager.issue({ id: 'appr_once', riskLevel: 'L2', taskId: 't', target: 'lab.test', operator: 'op' })
  assert.equal(manager.consume(token, { id: 'appr_once', taskId: 't', target: 'lab.test' }).valid, true)
  assert.equal(manager.consume(token, { id: 'appr_once', taskId: 't', target: 'lab.test' }).code, 'TOKEN_REPLAYED')
})

test('approval ids are unique', () => {
  assert.notEqual(makeApprovalId(), makeApprovalId())
})
