import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { readFile, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { getWorkflow } from '../packages/core/src/workflows.js'
import { makeTestTempDirectory } from './helpers/temporary.js'

const fixtureDir = join('tests', 'fixtures', 'm5')
const pythonFixture = join(fixtureDir, 'python_candidate.py')
const reference = await import('../tests/fixtures/m5/javascript_reference.mjs')

function python(program, input, variant = 'correct') {
  const result = spawnSync('python', [pythonFixture], {
    input: JSON.stringify({ program, input, variant }),
    encoding: 'utf8',
    timeout: 5000,
    maxBuffer: 64 * 1024,
    windowsHide: true,
  })
  assert.equal(result.status, 0, `Python reference fixture failed: ${result.stderr}`)
  return JSON.parse(result.stdout)
}

function pythonWithTimeout(program, input, timeout = 150) {
  return spawnSync('python', [pythonFixture], {
    input: JSON.stringify({ program, input }),
    encoding: 'utf8',
    timeout,
    maxBuffer: 64 * 1024,
    windowsHide: true,
  })
}

function completed(value, evidenceRef) {
  return { status: 'complete', value, evidenceRefs: [evidenceRef] }
}

function behaviorBundle(cases) {
  const artifactBytes = Buffer.from('ArmorBreak M5 self-authored behavior fixtures v1')
  return {
    schema: 'armorbreak.behavior-comparison-bundle/v1',
    artifact: { sha256: createHash('sha256').update(artifactBytes).digest('hex') },
    implementations: { reference: 'javascript-reference-fixtures', candidate: 'python-independent-candidate' },
    coverageScope: 'Three self-authored pure functions (account formatter, arithmetic evaluator, and gated state transition); only the listed inputs were compared.',
    cases,
  }
}

test('M5 behavior comparison covers three executed JS/Python programs, broken candidates, timeout, and nondeterminism', async () => {
  const cases = []
  const addCase = (id, input, refValue, variant = 'correct') => {
    cases.push({
      id,
      inputSha256: createHash('sha256').update(JSON.stringify(input)).digest('hex'),
      environmentComparable: true,
      reference: completed(refValue, `fixture:${id}:js`),
      candidate: completed(python(id.split('-')[0], input, variant), `fixture:${id}:py`),
    })
  }

  addCase('format-valid-01', { value: 7 }, reference.formatAccount({ value: 7 }))
  addCase('format-invalid-02', { value: -1 }, reference.formatAccount({ value: -1 }))
  addCase('format-broken-03', { value: 23 }, reference.formatAccount({ value: 23 }), 'broken')

  const arithmeticInput = { operation: 'add', left: 4, right: 3 }
  cases.push({
    id: 'arithmetic-add-01', inputSha256: createHash('sha256').update(JSON.stringify(arithmeticInput)).digest('hex'), environmentComparable: true,
    reference: completed(reference.evaluateArithmetic(arithmeticInput), 'fixture:arithmetic-add-01:js'),
    candidate: completed(python('arithmetic', arithmeticInput), 'fixture:arithmetic-add-01:py'),
  })
  const arithmeticBrokenInput = { operation: 'add', left: 8, right: 5 }
  cases.push({
    id: 'arithmetic-broken-02', inputSha256: createHash('sha256').update(JSON.stringify(arithmeticBrokenInput)).digest('hex'), environmentComparable: true,
    reference: completed(reference.evaluateArithmetic(arithmeticBrokenInput), 'fixture:arithmetic-broken-02:js'),
    candidate: completed(python('arithmetic', arithmeticBrokenInput, 'broken'), 'fixture:arithmetic-broken-02:py'),
  })
  for (const [id, input] of [
    ['state-disabled-01', { state: 'idle', command: 'start', enabled: false }],
    ['state-enabled-02', { state: 'idle', command: 'start', enabled: true }],
    ['state-stop-03', { state: 'active', command: 'stop', enabled: true }],
  ]) {
    cases.push({
      id, inputSha256: createHash('sha256').update(JSON.stringify(input)).digest('hex'), environmentComparable: true,
      reference: completed(reference.transitionState(input), `fixture:${id}:js`),
      candidate: completed(python('state', input, id === 'state-disabled-01' ? 'broken' : 'correct'), `fixture:${id}:py`),
    })
  }

  const timeoutRun = pythonWithTimeout('hang', {}, 150)
  assert.equal(timeoutRun.error?.code, 'ETIMEDOUT', 'the authored Python candidate process must actually exceed the process timeout')
  const timeout = { status: 'timeout', evidenceRefs: ['fixture:timeout:python-process-150ms'] }
  cases.push({
    id: 'formatter-timeout-01', inputSha256: createHash('sha256').update('timeout-case').digest('hex'), environmentComparable: true,
    reference: completed(reference.formatAccount({ value: 1 }), 'fixture:timeout:reference'), candidate: timeout,
  })
  const randomRunA = python('random', {})
  const randomRunB = python('random', {})
  assert.notEqual(randomRunA.nonce, randomRunB.nonce, 'the authored Python candidate must produce distinct outputs across runs')
  cases.push({
    id: 'random-output-01', inputSha256: createHash('sha256').update('random-case').digest('hex'), environmentComparable: true,
    reference: { status: 'nondeterministic', value: randomRunA, evidenceRefs: ['fixture:random:run-1', 'fixture:random:run-2'] },
    candidate: completed(randomRunB, 'fixture:random:candidate'),
  })
  cases.push({
    id: 'environment-incomparable-01', inputSha256: createHash('sha256').update('environment-case').digest('hex'), environmentComparable: false,
    reference: completed({ state: 'active' }, 'fixture:environment:reference'), candidate: completed({ state: 'active' }, 'fixture:environment:candidate'),
  })

  const stateRoot = await makeTestTempDirectory('abm-m5-state-')
  const workspace = await makeTestTempDirectory('abm-m5-workspace-')
  const inputPath = join(workspace, 'comparison.json')
  const bundle = behaviorBundle(cases)
  await writeFile(inputPath, JSON.stringify(bundle))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workflow = getWorkflow('AuthorizedBehaviorReconstruction')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'M5 finite behavior comparison', objective: 'Compare already-produced JS and Python fixture outputs',
    targetPath: inputPath, targetKind: 'file', workflowId: workflow.id,
    steps: workflow.steps.map((step) => ({ ...step, options: {} })),
  })
  const completedTask = await runtime.runner.runWorkflow(task)
  assert.equal(completedTask.state, 'COMPLETED')
  const artifactNames = await readdir(join(store.taskDir(task.id), 'artifacts'))
  const outputName = artifactNames.find((name) => name === 'behavior-comparison.json')
  assert.ok(outputName)
  const output = JSON.parse(await readFile(join(store.taskDir(task.id), 'artifacts', outputName), 'utf8'))
  assert.deepEqual({ total: output.casesTotal, executed: output.casesExecuted, compared: output.casesCompared, passed: output.casesPassed, failed: output.casesFailed, inconclusive: output.casesInconclusive }, { total: 11, executed: 8, compared: 8, passed: 5, failed: 3, inconclusive: 3 })
  assert.equal(output.executionByArmorBreak, false)
  assert.equal(output.equivalenceClaim, 'MISMATCHES_FOUND')
  assert.deepEqual(output.cases.find((item) => item.id === 'format-broken-03').differingPaths, ['/value'])
  assert.equal(output.cases.find((item) => item.id === 'formatter-timeout-01').status, 'INCONCLUSIVE')
  assert.equal(output.cases.find((item) => item.id === 'random-output-01').status, 'INCONCLUSIVE')
  assert.equal(output.cases.find((item) => item.id === 'environment-incomparable-01').reason, 'environment_not_comparable')
})

test('M5 contract preparation preserves certainty and requires evidence references', async () => {
  const source = {
    schema: 'armorbreak.behavior-contract-source/v1',
    artifact: { sha256: 'b'.repeat(64) },
    observations: [
      { id: 'api-format', kind: 'api', statement: 'formatAccount returns a four-digit account string for non-negative integers.', certainty: 'observed', evidenceRefs: ['source:signature', 'test:format-valid'] },
      { id: 'input-bound', kind: 'constraint', statement: 'Negative values return an invalid error.', certainty: 'inferred', evidenceRefs: ['test:format-invalid'] },
      { id: 'timezone', kind: 'constraint', statement: 'Timezone behavior is outside the observed case set.', certainty: 'unknown', evidenceRefs: ['scope:omitted'] },
    ],
  }
  const stateRoot = await makeTestTempDirectory('abm-m5-contract-state-')
  const workspace = await makeTestTempDirectory('abm-m5-contract-workspace-')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const result = await runtime.registry.get('rebuild.contract').run({ buffer: Buffer.from(JSON.stringify(source)), env: {} })
  assert.equal(result.data.observationCount, 3)
  assert.equal(result.data.observedCount, 1)
  assert.equal(result.data.inferredCount, 1)
  assert.equal(result.data.unknownCount, 1)
  assert.equal(result.data.reviewStatus, 'not_independently_validated')
  const invalid = structuredClone(source)
  invalid.observations[0].evidenceRefs = []
  await assert.rejects(() => runtime.registry.get('rebuild.contract').run({ buffer: Buffer.from(JSON.stringify(invalid)), env: {} }), /requires at least one evidence reference/)
})
