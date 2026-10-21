import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'

test('new task/evidence/finding writes carry schemaVersion v2 while old tasks stay readable', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-v2state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-v2ws-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const ctx = runtime.workspace(workspace)
  const task = await ctx.taskStore.create({ title: 'v2 write path', targetKind: 'none', steps: [{ id: 's1', capabilityId: 'forensics.hash' }] })
  assert.equal(task.schemaVersion, 'armorbreak/v2')
  const store = ctx.taskStore.evidenceStore(task.id)
  const evidence = await store.addEvidence({ title: 'sample', kind: 'observation', excerpt: 'x' })
  assert.equal(evidence.schemaVersion, 'armorbreak/v2')
  const { finding } = await store.addFinding({ title: 'sample finding', severity: 'info', verification: 'observed', description: 'x' }, { capabilityId: 'forensics.hash', evidenceIds: [evidence.id] })
  assert.equal(finding.schemaVersion, 'armorbreak/v2')

  const legacy = { ...task }
  delete legacy.schemaVersion
  await ctx.taskStore.save(legacy)
  const reread = await ctx.taskStore.get(task.id)
  assert.equal(reread.schemaVersion, 'armorbreak/v2', 'legacy task is upgraded on next save')
})
