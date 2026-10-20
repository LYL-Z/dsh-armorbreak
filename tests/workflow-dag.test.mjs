/**
 * Stage C tests: dependency-graph compilation and DAG execution through the real
 * runner, including failure isolation and dependent skipping.
 */
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { blockedSteps, compilePlan, pendingSteps, planSummary, readySteps } from '../lib/core/dag.js'

function statuses(entries) {
  return new Map(entries)
}

test('compilePlan preserves legacy sequential semantics when dependsOn is absent', () => {
  const plan = compilePlan([
    { id: 'a', capabilityId: 'cap.a' },
    { id: 'b', capabilityId: 'cap.b' },
    { id: 'c', capabilityId: 'cap.c', dependsOn: [] },
  ])
  assert.deepEqual(plan.steps.map((step) => step.dependsOn), [[], ['a'], []])
  assert.deepEqual(plan.roots, ['a', 'c'])
  assert.equal(plan.byId.get('c').failurePolicy, 'skip-dependent')
  assert.equal(plan.byId.get('c').retryPolicy.maxAttempts, 1)
})

test('compilePlan accepts a parallel DAG and rejects malformed graphs', () => {
  const plan = compilePlan([
    { id: 'scan', capabilityId: 'sast.scan' },
    { id: 'secrets', capabilityId: 'sast.secrets', dependsOn: [] },
    { id: 'sbom', capabilityId: 'sast.sbom', dependsOn: ['scan', 'secrets'], failurePolicy: 'retry-transient', retryPolicy: { maxAttempts: 3, backoffMs: 10 } },
  ])
  assert.deepEqual(plan.roots, ['scan', 'secrets'])
  assert.equal(plan.byId.get('sbom').retryPolicy.maxAttempts, 3)
  assert.equal(planSummary(plan).parallelizable, true)
  assert.throws(() => compilePlan([{ id: 'a', capabilityId: 'x', dependsOn: ['a'] }]), /depends on itself/)
  assert.throws(() => compilePlan([{ id: 'a', capabilityId: 'x', dependsOn: ['missing'] }]), /unknown step/)
  assert.throws(() => compilePlan([{ id: 'a', capabilityId: 'x' }, { id: 'a', capabilityId: 'y' }]), /duplicate/)
  assert.throws(
    () => compilePlan([
      { id: 'a', capabilityId: 'x', dependsOn: ['b'] },
      { id: 'b', capabilityId: 'y', dependsOn: ['a'] },
    ]),
    /cycle/,
  )
})

test('readySteps and blockedSteps follow DONE/FAILED dependency states', () => {
  const plan = compilePlan([
    { id: 'a', capabilityId: 'x' },
    { id: 'b', capabilityId: 'y', dependsOn: ['a'] },
    { id: 'c', capabilityId: 'z', dependsOn: ['b'] },
  ])
  let state = statuses([['a', 'DONE'], ['b', 'PENDING'], ['c', 'PENDING']])
  assert.deepEqual(readySteps(plan, state).map((step) => step.id), ['b'])
  assert.deepEqual(blockedSteps(plan, state), [])
  state = statuses([['a', 'FAILED'], ['b', 'PENDING'], ['c', 'PENDING']])
  assert.deepEqual(readySteps(plan, state), [])
  assert.deepEqual(blockedSteps(plan, state).map((step) => step.id), ['b'])
  state = statuses([['a', 'DONE'], ['b', 'DONE'], ['c', 'PENDING']])
  assert.deepEqual(pendingSteps(plan, state).map((step) => step.id), ['c'])
})

async function workspaceWithProject() {
  const workspace = await mkdtemp(join(tmpdir(), 'abm-dag-ws-'))
  await mkdir(join(workspace, 'src'), { recursive: true })
  await writeFile(join(workspace, 'package.json'), JSON.stringify({ name: 'dag-fixture', dependencies: { lodash: '4.17.20' } }))
  await writeFile(join(workspace, 'src', 'app.js'), 'export function run(input) { return eval(input) }\n')
  await writeFile(join(workspace, 'src', 'config.js'), 'export const key = "AKIAIOSFODNN7EXAMPLE"\n')
  return workspace
}

test('runner executes independent DAG steps and waits for dependencies', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-dag-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workspace = await workspaceWithProject()
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'dag integration',
    targetPath: workspace,
    targetKind: 'directory',
    steps: [
      { id: 'scan', capabilityId: 'sast.scan', dependsOn: [] },
      { id: 'deps', capabilityId: 'sast.deps', dependsOn: [] },
      { id: 'sbom', capabilityId: 'sast.sbom', dependsOn: ['deps'] },
      { id: 'secrets', capabilityId: 'sast.secrets', dependsOn: ['scan'] },
    ],
  })
  const updated = await runtime.runner.runWorkflow(task, { generateReport: true, concurrency: 3 })
  assert.ok(['COMPLETED', 'PARTIAL_SUCCESS'].includes(updated.state), `unexpected state ${updated.state}`)
  assert.deepEqual(updated.steps.map((step) => step.status), ['DONE', 'DONE', 'DONE', 'DONE'])
  for (const stepId of ['scan', 'deps', 'sbom', 'secrets']) {
    const step = updated.steps.find((item) => item.id === stepId)
    assert.ok(step.finishedAt, `${stepId} must record a finish timestamp`)
  }
})

test('a failed step skips its dependents but independent steps still run', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-dag-fail-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workspace = await workspaceWithProject()
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'dag failure isolation',
    targetPath: workspace,
    targetKind: 'directory',
    steps: [
      // sast.semgrep fails deterministically: no local config path is provided.
      { id: 'semgrep', capabilityId: 'sast.semgrep', dependsOn: [] },
      { id: 'dependent', capabilityId: 'sast.sbom', dependsOn: ['semgrep'] },
      { id: 'independent', capabilityId: 'sast.scan', dependsOn: [] },
    ],
  })
  const updated = await runtime.runner.runWorkflow(task, { generateReport: true, concurrency: 3 })
  const byId = new Map(updated.steps.map((step) => [step.id, step]))
  assert.equal(byId.get('semgrep').status, 'FAILED')
  assert.match(byId.get('semgrep').error, /sast\.semgrep needs options\.config|Semgrep|config/)
  assert.equal(byId.get('dependent').status, 'SKIPPED')
  assert.equal(byId.get('independent').status, 'DONE')
  assert.equal(updated.state, 'PARTIAL_SUCCESS')
  assert.ok(updated.stats.evidence > 0)
})
