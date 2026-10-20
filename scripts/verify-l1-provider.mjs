/** Real L1 provider self-test + approved live.container_exec verification. */
import { mkdtemp, writeFile, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'

const stateRoot = await mkdtemp(join(tmpdir(), 'abm-l1-state-'))
const workspace = await mkdtemp(join(tmpdir(), 'abm-l1-ws-'))
const sample = join(workspace, 'sample.txt')
await writeFile(sample, 'armorbreak l1 verification sample\n')
const runtime = new ArmorBreakRuntime({ stateRoot })
await runtime.init()
const manager = runtime.isolationProviders
const diagnosis = await manager.diagnose({ fresh: true })
const selfTest = await manager.selfTest('docker')
console.log('diagnosis before:', JSON.stringify(diagnosis.providers.find((p) => p.id === 'docker')))
console.log('selfTest:', JSON.stringify(selfTest))
if (!selfTest.verified) throw new Error('L1 self-test failed: ' + selfTest.reason)

const store = runtime.workspace(workspace).taskStore
const image = 'busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
const task = await store.create({
  title: 'L1 provider verification',
  targetPath: sample,
  targetKind: 'file',
  riskMax: 'L1',
  steps: [{ id: 'exec', title: 'harmless busybox true', capabilityId: 'live.container_exec', options: { image, command: ['true'], timeoutMs: 30000 } }],
})
const updated = await runtime.runner.runWorkflow(task, { requestApproval: async () => 'allowed-once', generateReport: false })
const data = updated.steps[0]?.result?.data ?? updated.steps[0]?.data ?? null
const evidence = await store.evidenceStore(task.id).readEvidence(100)
const out = {
  generatedAt: new Date().toISOString(),
  provider: 'docker',
  selfTest,
  diagnosisAfter: (await manager.diagnose({ fresh: true })).providers.find((p) => p.id === 'docker'),
  task: { id: task.id, state: updated.state, step: updated.steps[0]?.status, error: updated.steps[0]?.error ?? null },
  evidenceCount: evidence.length,
  isolationMeta: updated.meta?.isolation ?? null,
  containerData: data,
}
await writeFile('docs/acceptance/l1-provider.json', JSON.stringify(out, null, 2))
console.log(JSON.stringify({ state: out.task.state, step: out.task.step, evidence: out.evidenceCount, error: out.task.error }, null, 2))
if (!['COMPLETED', 'PARTIAL_SUCCESS'].includes(out.task.state)) throw new Error('L1 task did not complete')
