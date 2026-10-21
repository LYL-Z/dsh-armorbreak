import assert from 'node:assert/strict'
import test from 'node:test'
import { aggregateRuns, confusionMetrics, judgeRule, modelAssistedJudgment, wilsonInterval } from '../lib/aisec/judge.js'
import { createMockTarget } from '../lib/aisec/evaluator.js'
import { mapPyritResults, planPyrit } from '../lib/aisec/pyritAdapter.js'

test('confusion metrics compute TP/FP/TN/FN and Wilson intervals', () => {
  const metrics = confusionMetrics([
    { truth: 'unsafe', predicted: 'unsafe' },
    { truth: 'unsafe', predicted: 'safe' },
    { truth: 'safe', predicted: 'unsafe' },
    { truth: 'safe', predicted: 'safe' },
    { truth: 'safe', predicted: 'safe' },
  ])
  assert.equal(metrics.n, 5)
  assert.equal(metrics.tp, 1)
  assert.equal(metrics.fn, 1)
  assert.equal(metrics.fp, 1)
  assert.equal(metrics.tn, 2)
  assert.equal(metrics.tpr, 0.5)
  assert.equal(metrics.fpr, 1 / 3)
  assert.ok(metrics.tprCI.low < 0.5 && metrics.tprCI.high > 0.5)
  const interval = wilsonInterval(0, 0)
  assert.equal(interval.low, null)
})

test('model-assisted judge is not truth without human review', () => {
  const skipped = modelAssistedJudgment({ modelVerdict: 'PASS', humanReviewed: false })
  assert.equal(skipped.verdict, 'SKIPPED')
  assert.equal(skipped.humanReviewRequired, true)
  const reviewed = modelAssistedJudgment({ modelVerdict: 'PASS', humanReviewed: true, humanVerdict: 'FAIL' })
  assert.equal(reviewed.verdict, 'FAIL')
  const rule = judgeRule({ expected: 'safe', observed: 'refused', rules: [{ id: 'refusal', pattern: /refused/, verdict: 'PASS' }] })
  assert.equal(rule.verdict, 'PASS')
  const runs = aggregateRuns([{ score: 1 }, { score: 0.5 }, { score: 0 }])
  assert.equal(runs.runs, 3)
  assert.equal(runs.mean, 0.5)
  assert.ok(runs.stdev > 0)
})

test('PyRIT adapter requires authorized target, explicit outcomes and never stores raw prompts', () => {
  const target = createMockTarget('pyrit-mock')
  assert.throws(() => planPyrit({ target: { ...target, authorized: false } }), /rejected/)
  const plan = planPyrit({ target, objectives: ['tool-boundary-research'], budget: { maxAttempts: 2 } })
  const result = mapPyritResults([
    { conversation_id: 'c1', objective: 'tool-boundary-research', passed: true, output: 'RAW-SECRET' },
    { conversation_id: 'c2', objective: 'tool-boundary-research', passed: false },
    { conversation_id: 'c3', objective: 'tool-boundary-research' },
  ], plan)
  assert.equal(result.results.length, 2)
  assert.equal(result.results[0].verdict, 'PASS')
  assert.equal(result.results[1].verdict, 'FAIL')
  assert.equal(JSON.stringify(result).includes('RAW-SECRET'), false)
  assert.equal(result.externalModelCalls, undefined)
})
