import assert from 'node:assert/strict'
import { mkdtemp, rm, mkdir, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { EvidenceStore } from '../packages/core/src/evidence.js'
import { AuditLog } from '../packages/core/src/audit.js'

test('finding elevation requires existing task-local evidence and links the cited records', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-finding-integrity-'))
  const taskDir = join(root, 'task-a')
  const foreignDir = join(root, 'task-b')
  await mkdir(taskDir)
  await mkdir(foreignDir)
  try {
    const audit = new AuditLog({ file: join(root, 'audit.jsonl') })
    const store = new EvidenceStore({ taskDir, taskId: 'task-a', audit })
    const other = new EvidenceStore({ taskDir: foreignDir, taskId: 'task-b', audit })
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

    const snapshot = JSON.parse(await readFile(store.findingsFile, 'utf8'))
    snapshot.findings[0].severity = 'critical'
    snapshot.findings[0].verification = 'corroborated'
    snapshot.findings[0].evidenceIds = []
    await writeFile(store.findingsFile, `${JSON.stringify(snapshot, null, 2)}\n`)
    await assert.rejects(store.readFindings(), { code: 'FINDING_INTEGRITY_MISMATCH' })
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('unanchored legacy finding snapshots are downgraded instead of trusted', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-finding-legacy-'))
  const taskDir = join(root, 'task-legacy')
  await mkdir(taskDir)
  try {
    const audit = new AuditLog({ file: join(root, 'legacy-audit.jsonl') })
    const store = new EvidenceStore({ taskDir, taskId: 'task-legacy', audit })
    await writeFile(store.findingsFile, `${JSON.stringify({ version: 1, taskId: 'task-legacy', findings: [{
      id: 'legacy-finding', severity: 'critical', severityScore: 9.5, verification: 'corroborated', evidenceIds: ['forged-evidence'],
    }] }, null, 2)}\n`)
    const result = await store.readFindings()
    assert.equal(result.integrityStatus, 'UNVERIFIED_LEGACY')
    assert.equal(result.findings[0].severity, 'info')
    assert.equal(result.findings[0].severityScore, 0)
    assert.equal(result.findings[0].verification, 'unverified')
    assert.deepEqual(result.findings[0].evidenceIds, [])
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
