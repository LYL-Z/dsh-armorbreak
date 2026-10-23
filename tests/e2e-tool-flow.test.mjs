/**
 * End-to-end tool-flow test (mock model): drives the same tool calls a model would
 * make — health → workflow start → background run → status polling → evidence
 * chain → report — without an LLM and without a browser. This validates the tool
 * layer, DAG/queue, evidence chain and report integration. It does NOT replace a
 * real DeepSeek model session or GUI verification (tracked separately).
 */
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

async function loadTools(workspace) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-e2e-state-'))
  process.env.ARMORBREAK_HOME = stateRoot
  const defs = new Map()
  const ctx = {
    tools: {
      register(definition) {
        defs.set(definition.name, definition)
        return () => {}
      },
    },
    get(key) {
      return key === 'workingDirectory' && workspace ? { ensure: async () => workspace } : undefined
    },
    logger: { warn() {} },
  }
  const module = await import('../tools.js')
  module.apply(ctx)
  return { defs }
}

function mockExec() {
  return { agent: undefined, callId: 'call_e2e', signal: new AbortController().signal }
}

async function projectWorkspace() {
  const workspace = await mkdtemp(join(tmpdir(), 'abm-e2e-ws-'))
  await mkdir(join(workspace, 'src'), { recursive: true })
  await writeFile(join(workspace, 'package.json'), JSON.stringify({ name: 'e2e-fixture', dependencies: { lodash: '4.17.20' } }))
  await writeFile(join(workspace, 'src', 'app.js'), 'export function run(input) { return eval(input) }\n')
  await writeFile(join(workspace, 'src', 'config.js'), 'export const token = "AKIAIOSFODNN7EXAMPLE"\n')
  return workspace
}

test('mock-model E2E: workflow start → background run → evidence → report', async () => {
  const workspace = await projectWorkspace()
  const { defs } = await loadTools(workspace)
  const exec = mockExec()

  const health = await defs.get('armorbreak_health').execute({ workspace }, exec)
  assert.ok(health.data.registry.capabilities >= 41, 'registry must include the adapter capabilities')
  assert.equal(health.data.ui.policy.l2.activeAuthorizations, 0)
  assert.match(health.data.ui.policy.l2.label, /无授权目标/)

  const started = await defs.get('armorbreak_workflow').execute(
    { action: 'start', workflow: 'WebCodeSecurityReview', target: workspace, workspace, title: 'E2E mock model review' },
    exec,
  )
  const taskId = started.data.id
  assert.match(taskId, /^task_/)

  const launched = await defs.get('armorbreak_workflow').execute({ action: 'run_async', taskId, workspace, concurrency: 3 }, exec)
  assert.ok(launched.data.queue, 'run_async must return a queue entry')
  let status
  for (let attempt = 0; attempt < 60; attempt += 1) {
    status = await defs.get('armorbreak_workflow').execute({ action: 'status', taskId, workspace }, exec)
    if (['COMPLETED', 'PARTIAL_SUCCESS', 'FAILED', 'REJECTED', 'CANCELLED', 'TIMED_OUT'].includes(status.data.summary.state)) break
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 200))
  }
  const finalState = status.data.summary.state
  assert.ok(['COMPLETED', 'PARTIAL_SUCCESS'].includes(finalState), `unexpected final state ${finalState}`)
  for (const step of status.data.summary.steps) assert.notEqual(step.status, 'PENDING')

  const chain = await defs.get('armorbreak_evidence').execute({ action: 'chain', taskId, workspace }, exec)
  assert.equal(chain.data.evidence.valid, true)
  assert.ok(chain.data.evidence.records > 0)

  const report = await defs.get('armorbreak_report').execute({ taskId, workspace, format: 'markdown' }, exec)
  assert.ok(report.data.path, 'report path must be returned')
  assert.equal(existsSync(report.data.path), true)
  const text = await readFile(report.data.path, 'utf8')
  assert.match(text, /WebCodeSecurityReview|E2E mock model review/)
})
