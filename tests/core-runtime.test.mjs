/**
 * Core runtime integration tests: task state machine, capability execution,
 * evidence/finding persistence, policy rejections, timeout handling, hash-chain
 * integrity, and report generation (markdown/html/json/sarif).
 */
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { PolicyDeniedError } from '../lib/core/runner.js'
import { escapeMarkdownTableCell, generateTaskReport } from '../lib/core/reports.js'

async function tempDir(prefix = 'abm-core-') {
  return mkdtemp(join(tmpdir(), prefix))
}

/** Build a runtime whose registry also knows a deterministic fixture capability. */
async function makeRuntime() {
  const stateRoot = await tempDir('abm-state-')
  const workspace = await tempDir('abm-ws-')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  runtime.registry.registerManifest('fixture', {
    domain: 'fixture',
    capabilities: [
      {
        id: 'fixture.echo',
        title: 'Fixture echo',
        description: 'Deterministic test capability that reports the target size and one finding.',
        riskLevel: 'L0',
        params: { type: 'object', properties: { note: { type: 'string' } }, additionalProperties: false },
        async run(input) {
          return {
            summary: `fixture analyzed ${input.buffer ? input.buffer.length : 0} bytes (note=${input.options.note ?? 'none'})`,
            data: { bytes: input.buffer ? input.buffer.length : 0, size: input.env.targetSize },
            evidence: [{ title: 'fixture evidence', kind: 'observation', excerpt: 'deterministic evidence excerpt' }],
            findings: [
              {
                title: 'Fixture finding',
                severity: 'medium',
                description: 'A deterministic finding used by core tests.',
                verification: 'observed',
                method: 'fixture.echo',
                cwe: 'CWE-200',
                cvss: 5.3,
                remediation: 'Nothing to fix in a fixture.',
                target: input.targetPath,
                evidence: [{ title: 'raw excerpt', excerpt: 'fixture raw evidence' }],
              },
            ],
          }
        },
      },
      {
        id: 'fixture.network',
        title: 'Fixture network capability',
        description: 'L2 fixture that must never execute without authorization and approval.',
        riskLevel: 'L2',
        targetKind: 'network',
        networkTarget: (options) => options.host ?? '',
        params: { type: 'object', properties: { host: { type: 'string' } }, required: ['host'], additionalProperties: false },
        async run() {
          throw new Error('L2 fixture must not run in tests')
        },
      },
      {
        id: 'fixture.danger',
        title: 'Fixture L3 capability',
        description: 'L3 fixture that the policy must always reject.',
        riskLevel: 'L3',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run() {
          throw new Error('L3 fixture must never run')
        },
      },
      {
        id: 'fixture.slow',
        title: 'Fixture slow capability',
        description: 'Cooperative long-running fixture for timeout tests.',
        riskLevel: 'L0',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run(input) {
          await new Promise((resolve) => {
            const timer = setTimeout(resolve, 30_000)
            input.env.signal.addEventListener(
              'abort',
              () => {
                clearTimeout(timer)
                resolve()
              },
              { once: true },
            )
          })
          throw new Error('slow fixture was cancelled')
        },
      },
    ],
  })
  return { runtime, workspace, stateRoot }
}

async function createTask(runtime, workspace, options = {}) {
  const store = runtime.workspace(workspace).taskStore
  const target = options.targetPath ?? join(workspace, 'sample.bin')
  if (!options.targetPath) await writeFile(target, 'ARMORBREAK-FIXTURE')
  const task = await store.create({
    title: options.title ?? 'Core fixture task',
    objective: 'exercise the core runtime',
    targetPath: target,
    targetKind: options.targetKind ?? 'file',
    steps: options.steps ?? [{ id: 'analyze', title: 'fixture', capabilityId: 'fixture.echo', options: { note: 'unit' } }],
  })
  return { store, task, target }
}

test('L0 capability runs, persists evidence/finding, finalizes with report and valid chains', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { store, task, target } = await createTask(runtime, workspace)
  await runtime.runner.prepareTask(task)
  assert.equal(task.state, 'EXECUTING')
  const result = await runtime.runner.runCapability({ task, capabilityId: 'fixture.echo', targetPath: target, options: { note: 'unit' }, stepId: 'analyze' })
  assert.equal(result.capability, 'fixture.echo')
  assert.match(result.summary, /fixture analyzed \d+ bytes/)
  assert.equal(result.findings.length, 1)
  assert.ok(result.targetSha256 && result.targetSha256.length === 64)
  const finalized = await runtime.runner.finalizeTask(task, { generateReport: true })
  assert.equal(finalized.state, 'COMPLETED')
  assert.ok(finalized.report && finalized.report.path.endsWith('.md'))
  const ctx = runtime.workspace(workspace)
  const evidenceStore = ctx.taskStore.evidenceStore(task.id)
  const evidence = await evidenceStore.readEvidence(100)
  assert.ok(evidence.length >= 3, `expected execution + evidence records, got ${evidence.length}`)
  const chain = await evidenceStore.verifyChain()
  assert.equal(chain.valid, true)
  const auditChain = await ctx.audit.verify()
  assert.equal(auditChain.valid, true)
  const report = await readFile(finalized.report.path, 'utf8')
  assert.match(report, /Fixture finding/)
  assert.match(report, /CWE-200/)
  assert.match(report, /observed/)
  assert.match(report, /证据/)
  void store
})

test('out-of-workspace target is rejected before execution', async () => {
  const { runtime, workspace } = await makeRuntime()
  const outside = await tempDir('abm-outside-')
  const outsideFile = join(outside, 'target.bin')
  await writeFile(outsideFile, 'outside')
  const { task } = await createTask(runtime, workspace, { targetPath: outsideFile })
  await assert.rejects(
    () => runtime.runner.prepareTask(task),
    (error) => error instanceof PolicyDeniedError && error.code === 'OUT_OF_SCOPE',
  )
  assert.equal(task.state, 'REJECTED')
})

test('L3 capability is rejected by policy and never runs', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { task } = await createTask(runtime, workspace, {
    steps: [{ id: 'danger', title: 'danger', capabilityId: 'fixture.danger', options: {} }],
  })
  await assert.rejects(
    () => runtime.runner.prepareTask(task),
    (error) => error instanceof PolicyDeniedError && error.code === 'L3_DENIED',
  )
  assert.equal(task.state, 'REJECTED')
})

test('L2 capability fails closed without a platform approval channel', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { task } = await createTask(runtime, workspace, {
    targetKind: 'network',
    steps: [{ id: 'net', title: 'network', capabilityId: 'fixture.network', options: { host: 'lab.example.test' } }],
  })
  await assert.rejects(
    () => runtime.runner.prepareTask(task, { approvalTarget: 'lab.example.test' }),
    (error) => error instanceof PolicyDeniedError && error.code === 'APPROVAL_REJECTED',
  )
  assert.equal(task.state, 'REJECTED')
})

test('L0 capability timeout becomes a structured TIMEOUT error', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { task } = await createTask(runtime, workspace, {
    steps: [{ id: 'slow', title: 'slow', capabilityId: 'fixture.slow', options: { timeoutMs: 150 } }],
  })
  await runtime.runner.prepareTask(task)
  await assert.rejects(
    () =>
      runtime.runner.runCapability({
        task,
        capabilityId: 'fixture.slow',
        targetPath: task.targetPath,
        options: { timeoutMs: 150 },
        stepId: 'slow',
      }),
    (error) => error.code === 'TIMEOUT' || /timeout/i.test(String(error.message)),
  )
})

test('missing capability fails the environment check durably', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { task } = await createTask(runtime, workspace, {
    steps: [
      { id: 'ok', title: 'ok', capabilityId: 'fixture.echo', options: {} },
      { id: 'bad', title: 'bad', capabilityId: 'fixture.missing', options: {} },
    ],
  })
  await assert.rejects(() => runtime.runner.runWorkflow(task, { generateReport: true }), /capabilities unavailable/)
  const stored = await runtime.workspace(workspace).taskStore.get(task.id)
  assert.equal(stored.state, 'FAILED')
  assert.equal(stored.steps.find((step) => step.id === 'bad').status, 'PENDING')
  assert.match(stored.stateHistory.at(-1).reason, /capabilities unavailable/)
})

test('illegal state transitions throw, legal cancellations are durable', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { store, task } = await createTask(runtime, workspace)
  await assert.rejects(() => store.transition(task, 'COMPLETED', 'illegal jump'), /illegal task transition/)
  await runtime.runner.prepareTask(task)
  await store.cancel(task, 'cancelled by test')
  assert.equal(task.state, 'CANCELLED')
  const reloaded = await store.get(task.id)
  assert.equal(reloaded.state, 'CANCELLED')
  await assert.rejects(() => runtime.runner.prepareTask(reloaded), /cannot run|TASK_TERMINAL/)
})

test('evidence hash chain detects tampering', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { store, task, target } = await createTask(runtime, workspace)
  await runtime.runner.prepareTask(task)
  await runtime.runner.runCapability({ task, capabilityId: 'fixture.echo', targetPath: target, options: {}, stepId: 'analyze' })
  const evidenceStore = store.evidenceStore(task.id)
  const before = await evidenceStore.verifyChain()
  assert.equal(before.valid, true)
  const file = join(store.taskDir(task.id), 'evidence.jsonl')
  const lines = (await readFile(file, 'utf8')).trim().split('\n')
  const record = JSON.parse(lines[0])
  record.excerpt = 'tampered excerpt'
  lines[0] = JSON.stringify(record)
  await writeFile(file, `${lines.join('\n')}\n`)
  const after = await evidenceStore.verifyChain()
  assert.equal(after.valid, false)
  assert.equal(after.brokenAt, 1)
})

test('report formats render findings, evidence and SARIF metadata', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { task, target } = await createTask(runtime, workspace)
  await runtime.runner.prepareTask(task)
  await runtime.runner.runCapability({ task, capabilityId: 'fixture.echo', targetPath: target, options: {}, stepId: 'analyze' })
  await runtime.runner.finalizeTask(task, { generateReport: false })
  const markdown = await generateTaskReport(runtime, task, { format: 'markdown' })
  assert.ok(markdown.path.endsWith('.md'))
  const markdownText = await readFile(markdown.path, 'utf8')
  assert.match(markdownText, /Fixture finding/)
  const html = await generateTaskReport(runtime, task, { format: 'html' })
  const htmlText = await readFile(html.path, 'utf8')
  assert.match(htmlText, /<html lang="zh-CN">/)
  assert.match(htmlText, /Fixture finding/)
  const json = await generateTaskReport(runtime, task, { format: 'json' })
  const parsed = JSON.parse(await readFile(json.path, 'utf8'))
  assert.equal(parsed.schema, 'armorbreak/report/v1')
  assert.equal(parsed.findings.length, 1)
  assert.equal(parsed.evidenceChain.valid, true)
  const sarif = await generateTaskReport(runtime, task, { format: 'sarif' })
  const sarifJson = JSON.parse(await readFile(sarif.path, 'utf8'))
  assert.equal(sarifJson.version, '2.1.0')
  assert.equal(sarifJson.runs[0].results.length, 1)
  assert.equal(sarifJson.runs[0].results[0].ruleId, 'CWE-200')
  assert.equal(sarifJson.runs[0].results[0].level, 'warning')
  // PDF must either produce a real file (LibreOffice present) or fail with install guidance.
  try {
    const pdf = await generateTaskReport(runtime, task, { format: 'pdf' })
    assert.ok(pdf.bytes > 1000)
  } catch (error) {
    assert.match(String(error.message), /LibreOffice|PDF/i)
  }
})

test('Markdown table cells neutralize backslash escapes and line breaks', () => {
  const escaped = escapeMarkdownTableCell('a\\|b|c\r\nd')
  assert.equal(escaped, ['a', '\\\\', '\\|', 'b', '\\|', 'c d'].join(''))
  assert.equal(escapeMarkdownTableCell(`${'x'.repeat(399)}\\|tail`), `${'x'.repeat(399)}\\\\`)
})

test('state summary exposes tasks, capabilities and secret-free policy', async () => {
  const { runtime, workspace } = await makeRuntime()
  const { task } = await createTask(runtime, workspace)
  void task
  const summary = await runtime.stateSummary(workspace)
  assert.equal(summary.workspace, workspace)
  assert.ok(summary.registry.capabilities >= 4)
  assert.equal(Array.isArray(summary.tasks), true)
  assert.equal(summary.tasks.length, 1)
  const serialized = JSON.stringify(summary)
  assert.equal(serialized.includes('PRIVATE KEY'), false, 'state summary must not contain private keys')
  assert.equal(Object.prototype.hasOwnProperty.call(summary, 'credentials'), false)
  assert.ok(summary.environment && typeof summary.environment.platform === 'string')
})
