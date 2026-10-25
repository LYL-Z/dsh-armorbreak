/**
 * Runner gate tests for the approval-granted branches: L2 authorized+approved
 * execution, L1 approved execution with an injected isolation provider, and
 * the approval-mismatch / rate-limit denials. These complement the
 * rejection-only tests in core-runtime.test.mjs and raise the policy branch
 * coverage of lib/core/runner.js.
 */
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { PolicyDeniedError } from '../lib/core/runner.js'

async function tempDir(prefix = 'abm-gate-') {
  return mkdtemp(join(tmpdir(), prefix))
}

/** @param {{isolationAvailable?: boolean}} [opts] */
async function gateRuntime(opts = {}) {
  const stateRoot = await tempDir('abm-gate-state-')
  const workspace = await tempDir('abm-gate-ws-')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  // The success branch needs a deterministic public DNS answer now that
  // hostname resolution errors and empty answers fail closed.
  runtime.scope.dnsLookup = async (host) => host === 'lab.example.test' ? ['8.8.8.8'] : []
  runtime.isolationProviders = {
    diagnose: async () => opts.isolationAvailable
      ? { providers: [{ id: 'test-container', state: 'DaemonReady' }], recommended: 'test-container', l1: { available: true, verified: false, provider: 'test-container', state: 'DaemonReady', reason: 'test provider daemon ready' } }
      : { providers: [], recommended: null, l1: { available: false, verified: false, provider: null, state: 'Unavailable', reason: 'no test provider' } },
    selfTest: async () => opts.selfTestOk === false
      ? { provider: 'test-container', verified: false, reason: 'injected self-test failure' }
      : { provider: 'test-container', verified: true, reason: 'injected self-test success' },
  }
  runtime.registry.registerManifest('gate', {
    domain: 'gate',
    capabilities: [
      {
        id: 'gate.network',
        title: 'Authorized network step',
        description: 'L2 capability that records when the approval gate actually allows execution.',
        riskLevel: 'L2',
        targetKind: 'network',
        networkTarget: (options) => options.host,
        params: { type: 'object', properties: { host: { type: 'string' } }, required: ['host'], additionalProperties: false },
        async run(input) {
          return { summary: `approved network step ran against ${input.options.host}`, data: { executed: true }, evidence: [{ title: 'network approval evidence', kind: 'authorization', excerpt: 'gate allowed execution' }] }
        },
      },
      {
        id: 'gate.exec',
        title: 'Authorized container step',
        description: 'L1 capability that records when isolation + approval allowed execution.',
        riskLevel: 'L1',
        targetKind: 'file',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run(input) {
          return { summary: 'approved container step ran', data: { executed: true, sample: input.targetPath }, evidence: [{ title: 'isolation evidence', kind: 'authorization', excerpt: 'L1 gate allowed execution' }] }
        },
      },
    ],
  })
  return { runtime, workspace }
}

function approvalGranting() {
  return async () => 'allowed-once'
}

test('L2 execution runs only after scope authorization + platform approval grant', async () => {
  const { runtime, workspace } = await gateRuntime()
  const scope = runtime.workspace(workspace).scope
  const store = runtime.workspace(workspace).taskStore
  // Without an authorization record, even an approval grant cannot open the gate.
  const target = join(workspace, 'sample.bin')
  await writeFile(target, 'gate')
  const deniedTask = await store.create({
    title: 'denied network task',
    targetPath: target,
    targetKind: 'none',
    steps: [{ id: 'net', title: 'net', capabilityId: 'gate.network', options: { host: 'lab.example.test' } }],
  })
  await runtime.runner.prepareTask(deniedTask, { requestApproval: approvalGranting(), approvalTarget: 'lab.example.test' })
  const deniedRun = await runtime.runner.runWorkflow(deniedTask, { requestApproval: approvalGranting(), generateReport: false })
  assert.equal(deniedRun.state, 'FAILED')
  assert.match(deniedRun.steps[0].error, /NETWORK_OUT_OF_SCOPE/)
  const deniedEvidence = await store.evidenceStore(deniedTask.id).readEvidence(100)
  assert.equal(deniedEvidence.length, 0, 'no evidence may be collected for an unauthorized target')

  // Authorize the exact target, create a fresh task and run it with a grant.
  await scope.authorize({ purpose: 'authorized lab target', operator: 'tester', networkTargets: ['lab.example.test'], riskCeiling: 'L2', ttlMs: 60_000 })
  const task = await store.create({
    title: 'approved network task',
    targetPath: target,
    targetKind: 'none',
    steps: [{ id: 'net', title: 'net', capabilityId: 'gate.network', options: { host: 'lab.example.test' } }],
  })
  const updated = await runtime.runner.runWorkflow(task, { requestApproval: approvalGranting() })
  assert.ok(['COMPLETED', 'PARTIAL_SUCCESS'].includes(updated.state), `unexpected state ${updated.state}`)
  assert.equal(updated.steps[0].status, 'DONE')
  const evidence = await store.evidenceStore(task.id).readEvidence(100)
  assert.ok(evidence.some((record) => record.title === 'network approval evidence'))
  const approvals = await scope.listApprovals()
  assert.ok(approvals.some((approval) => approval.riskLevel === 'L2' && approval.target.includes('lab.example.test') && approval.active))
})

test('L2 approval is consumed and rate-limited per target', async () => {
  const { runtime, workspace } = await gateRuntime()
  const scope = runtime.workspace(workspace).scope
  await scope.authorize({ purpose: 'rate limit lab', operator: 'tester', networkTargets: ['10.9.0.0/16'], riskCeiling: 'L2', ttlMs: 60_000 })
  const approval = await scope.recordApproval({ kind: 'L2', taskId: 'task-rate', target: '10.9.0.7', outcome: 'allowed-once', source: 'test' })
  for (let index = 0; index < 20; index += 1) {
    const check = await scope.checkNetwork({ taskId: 'task-rate', target: '10.9.0.7', approvalId: approval.id })
    if (!check.allowed) break
  }
  const limited = await scope.checkNetwork({ taskId: 'task-rate', target: '10.9.0.7', approvalId: approval.id })
  assert.equal(limited.allowed, false)
  assert.equal(limited.code, 'NETWORK_RATE_LIMITED')
})

test('L1 execution runs when isolation is available and the sample is approved', async () => {
  const { runtime, workspace } = await gateRuntime({ isolationAvailable: true })
  const store = runtime.workspace(workspace).taskStore
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'MZ-sample')
  const task = await store.create({ title: 'approved L1 task', targetPath: sample, targetKind: 'file', steps: [{ id: 'exec', title: 'exec', capabilityId: 'gate.exec', options: {} }] })
  const updated = await runtime.runner.runWorkflow(task, { requestApproval: approvalGranting() })
  assert.ok(['COMPLETED', 'PARTIAL_SUCCESS'].includes(updated.state), `unexpected state ${updated.state}`)
  assert.equal(updated.steps[0].status, 'DONE')
  const approvals = await runtime.workspace(workspace).scope.listApprovals()
  assert.ok(approvals.some((approval) => approval.riskLevel === 'L1'))
})

test('approval rejected at the workflow gate becomes REJECTED without execution', async () => {
  const { runtime, workspace } = await gateRuntime()
  const store = runtime.workspace(workspace).taskStore
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'gate')
  const task = await store.create({ title: 'rejected L1 task', targetPath: sample, targetKind: 'file', steps: [{ id: 'exec', title: 'exec', capabilityId: 'gate.exec', options: {} }] })
  await assert.rejects(
    () => runtime.runner.prepareTask(task, { requestApproval: async () => 'rejected' }),
    (error) => error instanceof PolicyDeniedError && error.code === 'APPROVAL_REJECTED',
  )
  assert.equal(task.state, 'REJECTED')
  const evidence = await store.evidenceStore(task.id).readEvidence(100)
  assert.equal(evidence.length, 0, 'nothing may be collected when approval is rejected')
})

test('L1 fails closed when the isolation self-test fails after approval', async () => {
  const { runtime, workspace } = await gateRuntime({ isolationAvailable: true, selfTestOk: false })
  const store = runtime.workspace(workspace).taskStore
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'MZ-sample')
  const task = await store.create({ title: 'self-test failure task', targetPath: sample, targetKind: 'file', steps: [{ id: 'exec', title: 'exec', capabilityId: 'gate.exec', options: {} }] })
  const updated = await runtime.runner.runWorkflow(task, { requestApproval: approvalGranting() })
  assert.equal(updated.state, 'FAILED')
  assert.match(updated.steps[0].error, /ISOLATION_SELFTEST_FAILED/)
  const evidence = await store.evidenceStore(task.id).readEvidence(100)
  assert.equal(evidence.length, 0, 'no evidence when the self-test fails')
})
