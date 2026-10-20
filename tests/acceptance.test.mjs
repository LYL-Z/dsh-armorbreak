/**
 * Acceptance tests for the task-book criteria that are not already covered by
 * the core/tool suites: partial-success evidence preservation, cancellation,
 * audit redaction, traceability, and a real multi-step workflow driven through
 * the model-facing tool wiring.
 */
import assert from 'node:assert/strict'
import { copyFile, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { rm } from 'node:fs/promises'

async function tempDir(prefix = 'abm-acc-') {
  return mkdtemp(join(tmpdir(), prefix))
}

/** Load tools.js against a mock registry and a fresh runtime state root. */
async function loadTools() {
  const stateRoot = await tempDir('abm-acc-state-')
  process.env.ARMORBREAK_HOME = stateRoot
  /** @type {Map<string, any>} */
  const defs = new Map()
  const ctx = { tools: { register: (definition) => (defs.set(definition.name, definition), () => {}) }, get: () => undefined, logger: { warn() {} } }
  const module = await import('../tools.js')
  module.apply(ctx)
  return { defs, stateRoot }
}

function mockExec(signal) {
  return { agent: undefined, callId: 'call_accept_0001', signal: signal ?? new AbortController().signal }
}

test('real BinaryStaticAnalysis workflow runs through the tool layer and produces evidence + report', async (t) => {
  const { defs } = await loadTools()
  const workspace = await tempDir('abm-acc-ws-')
  const source = 'D:\\dsh-ABM\\fixtures\\notepad.exe'
  const target = join(workspace, 'notepad.exe')
  try {
    await copyFile(source, target)
  } catch {
    t.skip('notepad.exe fixture not available on this host')
    return
  }
  const health = await defs.get('armorbreak_health').execute({ workspace }, mockExec())
  const hasBinary = health.data.capabilities.some((capability) => capability.id === 'binary.identify')
  if (!hasBinary) {
    t.skip('binary.identify not registered')
    return
  }
  const started = await defs.get('armorbreak_workflow').execute(
    { action: 'start', workflow: 'BinaryStaticAnalysis', target, workspace, title: 'Acceptance PE workflow' },
    mockExec(),
  )
  const taskId = started.data.id
  assert.ok(taskId.startsWith('task_'))
  assert.equal(started.data.steps.length, 7)
  const run = await defs.get('armorbreak_workflow').execute({ action: 'run', taskId, workspace, maxSteps: 20 }, mockExec())
  assert.ok(['COMPLETED', 'PARTIAL_SUCCESS'].includes(run.data.state), `workflow ended ${run.data.state}`)
  assert.ok(run.data.stats.evidence >= 7, `expected evidence from each step, got ${run.data.stats.evidence}`)
  const steps = run.data.steps
  assert.ok(steps.every((step) => step.status === 'DONE'), `unexpected step statuses: ${JSON.stringify(steps.map((step) => [step.id, step.status]))}`)
  const report = await defs.get('armorbreak_report').execute({ taskId, workspace, format: 'markdown' }, mockExec())
  assert.ok(report.data.path.endsWith('.md'))
  const reportText = await readFile(report.data.path, 'utf8')
  assert.match(reportText, /notepad\.exe/i)
  assert.match(reportText, /证据附录|证据/)
  // Traceability: the report must reference target hashes and evidence ids.
  assert.match(reportText, /[0-9a-f]{64}/)
  assert.match(reportText, /ev_/)
})

test('partial success keeps successful-step evidence when a later step fails', async () => {
  const stateRoot = await tempDir('abm-acc-state-')
  const workspace = await tempDir('abm-acc-ws-')
  const { ArmorBreakRuntime } = await import('../lib/core/runtime.js')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  runtime.registry.registerManifest('acc', {
    domain: 'acc',
    capabilities: [
      {
        id: 'acc.ok',
        title: 'ok step',
        description: 'Succeeds and records evidence for the partial-success test.',
        riskLevel: 'L0',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run() {
          return { summary: 'ok step ran', data: { ok: true }, evidence: [{ title: 'ok evidence', kind: 'observation', excerpt: 'kept after later failure' }] }
        },
      },
      {
        id: 'acc.fail',
        title: 'failing step',
        description: 'Always throws to exercise failure isolation.',
        riskLevel: 'L0',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run() {
          throw new Error('intentional analyzer failure')
        },
      },
    ],
  })
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'partial-success')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'Partial success task',
    targetPath: sample,
    targetKind: 'file',
    steps: [
      { id: 'ok', title: 'ok', capabilityId: 'acc.ok', options: {} },
      { id: 'fail', title: 'fail', capabilityId: 'acc.fail', options: {} },
    ],
  })
  const updated = await runtime.runner.runWorkflow(task, { generateReport: true })
  assert.equal(updated.state, 'PARTIAL_SUCCESS')
  const ok = updated.steps.find((step) => step.id === 'ok')
  const failed = updated.steps.find((step) => step.id === 'fail')
  assert.equal(ok.status, 'DONE')
  assert.equal(failed.status, 'FAILED')
  assert.match(failed.error, /intentional analyzer failure/)
  assert.ok(updated.stats.evidence >= 2, 'evidence from the successful step must be kept')
  assert.ok(updated.report && updated.report.path.endsWith('.md'), 'partial success must still produce a report')
  const evidence = await store.evidenceStore(task.id).readEvidence(100)
  assert.ok(evidence.some((record) => (record.excerpt ?? '').includes('kept after later failure')))
})

test('running a workflow with an aborted signal cancels it durably', async () => {
  const stateRoot = await tempDir('abm-acc-state-')
  const workspace = await tempDir('abm-acc-ws-')
  const { ArmorBreakRuntime } = await import('../lib/core/runtime.js')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  runtime.registry.registerManifest('acc2', {
    domain: 'acc2',
    capabilities: [
      {
        id: 'acc2.slow',
        title: 'slow step',
        description: 'Cooperative slow step used by the cancellation test.',
        riskLevel: 'L0',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run(input) {
          await new Promise((resolve) => {
            const timer = setTimeout(resolve, 5000)
            input.env.signal.addEventListener('abort', () => { clearTimeout(timer); resolve() }, { once: true })
          })
          return { summary: 'slow step finished', data: {} }
        },
      },
    ],
  })
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'cancel-me')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({ title: 'cancel task', targetPath: sample, targetKind: 'file', steps: [{ id: 'slow', title: 'slow', capabilityId: 'acc2.slow', options: {} }] })
  await runtime.runner.prepareTask(task)
  const controller = new AbortController()
  setTimeout(() => controller.abort(), 50)
  const updated = await runtime.runner.runWorkflow(task, { generateReport: false, signal: controller.signal })
  assert.equal(updated.state, 'CANCELLED')
  const stored = await store.get(task.id)
  assert.equal(stored.state, 'CANCELLED')
  assert.equal(stored.steps[0].status, 'CANCELLED')
})

test('audit log redacts credentials and cannot be forgotten on capability failures', async () => {
  const stateRoot = await tempDir('abm-acc-state-')
  const workspace = await tempDir('abm-acc-ws-')
  const { ArmorBreakRuntime } = await import('../lib/core/runtime.js')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  runtime.registry.registerManifest('acc3', {
    domain: 'acc3',
    capabilities: [
      {
        id: 'acc3.leaky',
        title: 'leaky options step',
        description: 'Echoes options into evidence to prove audit/evidence redaction.',
        riskLevel: 'L0',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run(input) {
          return {
            summary: `token=${input.options.token ?? ''} authorization=${input.options.authorization ?? ''}`,
            data: { ran: true },
            evidence: [{ title: 'leaky evidence', kind: 'observation', excerpt: `Authorization: Bearer sk-abcdef0123456789 token=supersecretvalue1234` }],
          }
        },
      },
    ],
  })
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'redaction')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'redaction task',
    targetPath: sample,
    targetKind: 'file',
    steps: [{ id: 'leaky', title: 'leaky', capabilityId: 'acc3.leaky', options: { token: 'supersecretvalue1234', authorization: 'Bearer sk-abcdef0123456789' } }],
  })
  await runtime.runner.runWorkflow(task, { generateReport: false })
  const ctx = runtime.workspace(workspace)
  const auditRecords = await ctx.audit.read({ taskId: task.id, limit: 200 })
  assert.ok(auditRecords.length > 0)
  const auditText = JSON.stringify(auditRecords)
  assert.equal(auditText.includes('supersecretvalue1234'), false, 'audit must redact token values')
  assert.equal(auditText.includes('sk-abcdef0123456789'), false, 'audit must redact API keys')
  const evidenceText = JSON.stringify(await store.evidenceStore(task.id).readEvidence(100))
  assert.equal(evidenceText.includes('supersecretvalue1234'), false, 'evidence must redact secrets')
  assert.equal(evidenceText.includes('sk-abcdef0123456789'), false, 'evidence must redact API keys')
  // The audit chain stays valid even under redaction.
  const auditChain = await ctx.audit.verify()
  assert.equal(auditChain.valid, true)
})

test('unsupported report format and missing task produce actionable errors', async () => {
  const { defs } = await loadTools()
  const workspace = await tempDir('abm-acc-ws-')
  await assert.rejects(() => defs.get('armorbreak_report').execute({ taskId: 'task_nope', workspace, format: 'markdown' }, mockExec()), /task not found/)
  const created = await defs.get('armorbreak_task').execute({ action: 'create', workspace, title: 'format task' }, mockExec())
  await assert.rejects(
    () => defs.get('armorbreak_report').execute({ taskId: created.data.id, workspace, format: 'docx' }, mockExec()),
    /unsupported report format/,
  )
  void rm
})
