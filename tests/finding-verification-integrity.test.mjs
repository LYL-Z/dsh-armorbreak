import assert from 'node:assert/strict'
import { mkdtemp, rm, mkdir } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { EvidenceStore } from '../packages/core/src/evidence.js'

test('finding elevation requires existing task-local evidence and links the cited records', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-finding-integrity-'))
  const taskDir = join(root, 'task-a')
  const foreignDir = join(root, 'task-b')
  await mkdir(taskDir)
  await mkdir(foreignDir)
  try {
    const store = new EvidenceStore({ taskDir, taskId: 'task-a' })
    const other = new EvidenceStore({ taskDir: foreignDir, taskId: 'task-b' })
    const finding = (await store.addFinding({ title: 'synthetic', severity: 'medium', verification: 'unverified' })).finding
    const first = await store.addEvidence({ title: 'source one', excerpt: 'synthetic evidence one' })
    const second = await store.addEvidence({ title: 'source two', excerpt: 'synthetic evidence two' })
    const foreign = await other.addEvidence({ title: 'foreign source', excerpt: 'belongs to another task' })

    await assert.rejects(store.verifyFinding(finding.id, { verification: 'corroborated' }), /requires at least 2 task evidence id/)
    await assert.rejects(store.verifyFinding(finding.id, { verification: 'corroborated', evidenceIds: [first.id, foreign.id] }), /unknown task evidence/)
    await assert.rejects(store.verifyFinding(finding.id, { severity: 'critical' }), /requires at least 1 task evidence id/)

    const updated = await store.verifyFinding(finding.id, {
      verification: 'corroborated', severity: 'critical',
      evidenceIds: [first.id, second.id], note: 'two independent synthetic records',
    })
    assert.equal(updated.verification, 'corroborated')
    assert.equal(updated.severity, 'critical')
    assert.deepEqual(updated.evidenceIds, [first.id, second.id])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
