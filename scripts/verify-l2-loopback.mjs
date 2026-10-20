/** Real L2 loopback verification: authorization + approval + live.http_probe. */
import { createServer } from 'node:http'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'

const server = createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json', 'x-armorbreak-test': 'loopback' })
  res.end(JSON.stringify({ authorized: true, path: req.url, marker: 'armorbreak-l2-proof' }))
})
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const port = server.address().port
const stateRoot = await mkdtemp(join(tmpdir(), 'abm-l2-state-'))
const workspace = await mkdtemp(join(tmpdir(), 'abm-l2-ws-'))
const runtime = new ArmorBreakRuntime({ stateRoot })
await runtime.init()
const ctx = runtime.workspace(workspace)
await ctx.scope.authorize({ purpose: 'loopback L2 verification', operator: 'armorbreak-selftest', networkTargets: [`127.0.0.1:${port}`], riskCeiling: 'L2', ttlMs: 120000 })
const task = await ctx.taskStore.create({
  title: 'L2 loopback verification',
  targetKind: 'network',
  steps: [{ id: 'probe', title: 'authorized loopback GET', capabilityId: 'live.http_probe', options: { url: `http://127.0.0.1:${port}/proof?x=1`, timeoutMs: 5000 } }],
})
const updated = await runtime.runner.runWorkflow(task, { requestApproval: async () => 'allowed-once', generateReport: false })
const evidence = await ctx.taskStore.evidenceStore(task.id).readEvidence(100)
const out = {
  generatedAt: new Date().toISOString(),
  target: `127.0.0.1:${port}`,
  task: { id: task.id, state: updated.state, step: updated.steps[0]?.status, error: updated.steps[0]?.error ?? null },
  evidenceCount: evidence.length,
  summary: updated.steps[0]?.summary ?? null,
}
await writeFile('docs/acceptance/l2-loopback.json', JSON.stringify(out, null, 2))
server.close()
console.log(JSON.stringify(out, null, 2))
if (!['COMPLETED', 'PARTIAL_SUCCESS'].includes(out.task.state)) throw new Error('L2 loopback task did not complete')
