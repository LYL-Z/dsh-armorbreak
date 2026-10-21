import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'

async function runtimeFor() {
  const root = await mkdtemp(join(tmpdir(), 'abm-appr-int-'))
  const runtime = new ArmorBreakRuntime({ stateRoot: root })
  await runtime.init()
  return runtime
}

test('platform approvals require a bound token when the authority is enabled', async () => {
  const runtime = await runtimeFor()
  await assert.rejects(
    () => runtime.scope.recordApproval({ kind: 'L2', taskId: 't1', target: 'lab.test:443', source: 'platform', outcome: 'allowed-once' }),
    /approval token/,
  )
  const id = 'appr_test_1'
  const issued = runtime.approvalAuthority.issue({ id, riskLevel: 'L2', taskId: 't1', target: 'lab.test:443', operator: 'platform' })
  const record = await runtime.scope.recordApproval({ kind: 'L2', taskId: 't1', target: 'lab.test:443', source: 'platform', outcome: 'allowed-once', approvalId: id, approvalToken: issued.token, operator: 'platform' })
  assert.equal(record.id, id)
  assert.equal(record.maxUses, 1)
  const active = (await runtime.scope.listApprovals()).find((item) => item.id === id)
  assert.equal(active.active, true)
  await runtime.scope.consumeApproval(id)
  const consumed = (await runtime.scope.listApprovals()).find((item) => item.id === id)
  assert.equal(consumed.active, false)
  await assert.rejects(() => runtime.scope.consumeApproval(id), /replay|rejected|already consumed/)
})

test('approval token cannot be replayed against another target or task', async () => {
  const runtime = await runtimeFor()
  const issued = runtime.approvalAuthority.issue({ id: 'appr_test_2', riskLevel: 'L1', taskId: 't1', target: 'sample.bin', operator: 'platform' })
  await assert.rejects(
    () => runtime.scope.recordApproval({ kind: 'L1', taskId: 't2', target: 'sample.bin', source: 'platform', outcome: 'allowed-once', approvalId: 'appr_test_2', approvalToken: issued.token, operator: 'platform' }),
    /binding|rejected/,
  )
  await assert.rejects(
    () => runtime.scope.recordApproval({ kind: 'L1', taskId: 't1', target: 'other.bin', source: 'platform', outcome: 'allowed-once', approvalId: 'appr_test_2', approvalToken: issued.token, operator: 'platform' }),
    /binding|rejected/,
  )
})
