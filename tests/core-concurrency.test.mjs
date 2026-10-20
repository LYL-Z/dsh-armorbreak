/**
 * Concurrency hardening tests: audit and evidence stores serialize their
 * read-tail → append cycles, so overlapping tool calls keep both hash chains
 * valid (the pre-1.0.2 stores could fork seq/prevHash under Promise.all).
 */
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'

async function tempDir(prefix = 'abm-conc-') {
  return mkdtemp(join(tmpdir(), prefix))
}

test('concurrent audit appends produce one continuous hash chain', async () => {
  const runtime = new ArmorBreakRuntime({ stateRoot: await tempDir('abm-conc-state-') })
  const workspace = await tempDir('abm-conc-ws-')
  await runtime.init()
  const ctx = runtime.workspace(workspace)
  const total = 30
  await Promise.all(
    Array.from({ length: total }, (_, index) => ctx.audit.append({ action: 'concurrent.test', taskId: 't1', index })),
  )
  const records = await ctx.audit.read({ limit: 100 })
  const seqs = records.map((record) => record.seq)
  assert.equal(records.length, total)
  assert.equal(new Set(seqs).size, total, 'seq values must be unique')
  assert.deepEqual(seqs, Array.from({ length: total }, (_, index) => index + 1))
  const chain = await ctx.audit.verify()
  assert.equal(chain.valid, true, `chain broken at ${chain.brokenAt}: ${chain.reason}`)
  assert.equal(chain.records, total)
})

test('concurrent evidence appends produce one continuous evidence chain', async () => {
  const runtime = new ArmorBreakRuntime({ stateRoot: await tempDir('abm-conc-state-') })
  const workspace = await tempDir('abm-conc-ws-')
  await runtime.init()
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({ title: 'concurrency', targetKind: 'none' })
  const evidenceStore = store.evidenceStore(task.id)
  const total = 20
  await Promise.all(
    Array.from({ length: total }, (_, index) => evidenceStore.addEvidence({ title: `evidence ${index}`, kind: 'test', excerpt: `record ${index}` })),
  )
  const records = await evidenceStore.readEvidence(100)
  assert.equal(records.length, total)
  assert.deepEqual(records.map((record) => record.index), Array.from({ length: total }, (_, index) => index + 1))
  const chain = await evidenceStore.verifyChain()
  assert.equal(chain.valid, true, `chain broken at ${chain.brokenAt}: ${chain.reason}`)
})

test('concurrent finding writes preserve every distinct finding', async () => {
  const runtime = new ArmorBreakRuntime({ stateRoot: await tempDir('abm-conc-state-') })
  const workspace = await tempDir('abm-conc-ws-')
  await runtime.init()
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({ title: 'concurrent findings', targetKind: 'none' })
  const evidenceStore = store.evidenceStore(task.id)
  await Promise.all(
    Array.from({ length: 12 }, (_, index) =>
      evidenceStore.addFinding({ title: `finding ${index}`, severity: 'low', description: 'concurrent', verification: 'hypothesis', method: 'test', cwe: null, cvss: null, remediation: 'none', target: `target-${index}` }, {}),
    ),
  )
  const { findings } = await evidenceStore.readFindings()
  assert.equal(findings.length, 12, 'no finding may be lost to a concurrent read-modify-write')
  const titles = findings.map((finding) => finding.title).sort()
  assert.deepEqual(titles, Array.from({ length: 12 }, (_, index) => `finding ${index}`).sort())
})
