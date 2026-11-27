import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../packages/core/index.js'
import { planSyntheticBackupRecovery } from '../packages/core/src/syntheticBackupRecovery.js'
import { reopenSyntheticMaintenance } from '../packages/core/src/syntheticMaintenance.js'

const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const snapshotId = '2026-11-26T120000Z-abcd'
const context = { operator: 'synthetic-test', sessionId: 'restore-rehearsal' }

function data() {
  const inline = { 'inline.txt': Buffer.from('original\r\n') }
  const object = Buffer.from([0x00, 0xff, 0x0d, 0x0a])
  const objects = { [digest(object)]: object }
  const manifest = { schema: 2, id: snapshotId, complete: true,
    sums: { 'inline.txt': digest(inline['inline.txt']) }, blobs: { 'restored.txt': digest(object) } }
  return { ...context, snapshotId, inline, objects,
    manifestJson: JSON.stringify(manifest), seeds: { 'inline.txt': 'before', 'restored.txt': 'also before' } }
}

async function runtime(t) {
  const root = await mkdtemp(join(tmpdir(), 'ab-recovery-state-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  return new ArmorBreakRuntime({ stateRoot: root })
}

test('trusted synthetic snapshot recovery uses one-time approvals and restores exact bytes', async t => {
  const core = await runtime(t)
  const input = data()
  const { lab, plan } = await planSyntheticBackupRecovery(core, input)
  t.after(() => rm(lab.root, { recursive: true, force: true }))
  assert.equal(plan.mode, 'SYNTHETIC_ONLY')
  assert.ok(plan.approvalRequired)
  assert.equal(plan.hostWrites, false)
  const target = join(lab.data, 'restored.txt')
  const refused = { request: async () => 'denied' }
  await assert.rejects(() => lab.apply(plan.planId, refused), /TRUSTED_APPROVAL_DENIED/)
  assert.equal(await readFile(target, 'utf8'), 'also before')
  const approvals = []
  const provider = { request: async request => {
    approvals.push([request.operation, request.taskId, request.sessionId, request.target])
    return 'allowed-once'
  } }
  const committed = await lab.apply(plan.planId, provider)
  assert.equal(committed.state, 'COMMITTED')
  assert.equal(committed.byteVerified, true)
  assert.deepEqual(await readFile(target), Object.values(input.objects)[0])
  assert.deepEqual(await readFile(join(lab.data, 'inline.txt')), input.inline['inline.txt'])
  await assert.rejects(() => reopenSyntheticMaintenance(core, lab.root, { ...context, sessionId: 'different' }), /LAB_CONTEXT_BINDING/)
  const reopened = await reopenSyntheticMaintenance(core, lab.root, context)
  await assert.rejects(() => reopened.rollback(plan.planId, refused), /TRUSTED_APPROVAL_DENIED/)
  assert.deepEqual(await readFile(target), Object.values(input.objects)[0])
  assert.equal((await reopened.rollback(plan.planId, provider)).state, 'ROLLED_BACK')
  assert.equal(await readFile(target, 'utf8'), 'also before')
  assert.equal(await readFile(join(lab.data, 'inline.txt'), 'utf8'), 'before')
  assert.deepEqual(approvals, [['apply', plan.planId, context.sessionId, lab.root], ['rollback', plan.planId, context.sessionId, lab.root]])
})

test('synthetic recovery refuses tampered, incomplete and out-of-scope declarations before planning', async t => {
  const core = await runtime(t)
  const input = data()
  const [objectHash] = Object.keys(input.objects)
  await assert.rejects(() => planSyntheticBackupRecovery(core, { ...input, objects: { [objectHash]: Buffer.from('different') } }), /object content does not match/)
  await assert.rejects(() => planSyntheticBackupRecovery(core, { ...input, objects: {} }), /object is missing/)
  await assert.rejects(() => planSyntheticBackupRecovery(core, { ...input, inline: { '../unsafe.txt': Buffer.from('no') } }), /FILE_INVALID/)
  await assert.rejects(() => planSyntheticBackupRecovery(core, { ...input, seeds: { 'inline.txt': 'before' } }), /FILE_SET_MISMATCH/)
})
