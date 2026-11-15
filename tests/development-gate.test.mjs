import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { evaluateGate, requiredJobs } from '../scripts/validate-development-gate.mjs'
const sha = 'a'.repeat(40)
const good = () => Object.fromEntries(requiredJobs.map(id => [id, { result: 'success' }]))
test('all required jobs succeed for the exact candidate', () => assert.deepEqual(evaluateGate(good(), sha, sha), []))
for (const id of requiredJobs) {
  for (const result of ['failure', 'cancelled', 'skipped', 'timed_out', 'neutral', undefined]) {
    test(`${id} rejects ${result}`, () => {
      const needs = good(); needs[id].result = result
      assert.deepEqual(evaluateGate(needs, sha, sha), [`${id}: ${result ?? 'invalid result'}`])
    })
  }
  test(`${id} cannot be omitted`, () => {
    const needs = good(); delete needs[id]
    assert.deepEqual(evaluateGate(needs, sha, sha), [`${id}: missing`])
  })
}
test('old SHA cannot satisfy new candidate', () => assert.deepEqual(evaluateGate(good(), sha, 'b'.repeat(40)), ['candidate SHA mismatch']))
test('unexpected dependency cannot replace required job', () => {
  const needs = good(); needs.extra = { result: 'success' }
  assert.deepEqual(evaluateGate(needs, sha, sha), ['extra: unexpected dependency'])
})
test('invalid dependency payload fails closed', () => assert.deepEqual(evaluateGate(null, sha, sha), ['invalid dependency object']))
test('all PR names, docs PRs and main push use the same common gate', () => {
  const workflow = readFileSync('.github/workflows/development-gate.yml', 'utf8')
  assert.match(workflow, /pull_request:/)
  assert.match(workflow, /branches: \[main\]/)
  assert.doesNotMatch(workflow, /head_ref|paths-ignore|paths:|branches-ignore|continue-on-error/)
  assert.equal((workflow.match(/if:/g) || []).length, 1)
  assert.match(workflow, /if: \$\{\{ always\(\) \}\}/)
  assert.match(workflow, /needs: \[common-matrix, common-l0, common-l1\]/)
  assert.match(workflow, /busybox@sha256:[0-9a-f]{64}/)
})
