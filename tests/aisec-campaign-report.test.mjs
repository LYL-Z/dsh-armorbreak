import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ResearchCampaign } from '../lib/aisec/campaign.js'
import { buildLLMReport, datasetFingerprint } from '../lib/aisec/report.js'

test('campaign orders DAG, retries, dedupes evidence and persists resume state', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-campaign-'))
  const file = join(dir, 'state.json')
  let calls = 0
  const campaign = new ResearchCampaign({
    id: 'campaign-1',
    stateFile: file,
    steps: [
      { id: 'a', maxAttempts: 2 },
      { id: 'b', dependsOn: ['a'] },
    ],
  })
  const state = await campaign.run({
    execute: async (step) => {
      calls += 1
      if (step.id === 'a' && calls === 1) throw new Error('transient')
      return { output: step.id, evidence: [{ sha256: 'same', kind: 'output' }, { sha256: 'same', kind: 'output' }] }
    },
  })
  assert.equal(state.status, 'DONE')
  assert.equal(state.steps.a.attempts, 2)
  assert.equal(state.evidence.length, 1)
  const persisted = JSON.parse(await readFile(file, 'utf8'))
  assert.equal(persisted.campaignId, 'campaign-1')
})

test('campaign cancellation leaves CANCELLED and resume completes remaining work', async () => {
  const campaign = new ResearchCampaign({ id: 'cancel-1', steps: [{ id: 'a' }, { id: 'b', dependsOn: ['a'] }] })
  const pending = campaign.run({
    execute: async (step, { signal }) => {
      if (step.id === 'a') {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, 50)
          signal.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('aborted')) })
        })
      }
      return { output: step.id }
    },
  })
  await new Promise((resolve) => setTimeout(resolve, 10))
  campaign.cancel()
  const cancelled = await pending
  assert.equal(cancelled.status, 'CANCELLED')
  const resumed = await campaign.run({ resume: true, execute: async (step) => ({ output: step.id }) })
  assert.equal(resumed.status, 'DONE')
  assert.equal(resumed.steps.b.status, 'DONE')
})

test('LLM report computes AVR/FRR/TCR/cost with model and dataset fingerprints', () => {
  const report = buildLLMReport({
    campaignId: 'c1',
    model: { name: 'mock', version: 'v1' },
    dataset: [{ id: 1 }],
    cases: [{ truth: 'unsafe', predicted: 'unsafe' }, { truth: 'unsafe', predicted: 'safe' }, { truth: 'safe', predicted: 'unsafe' }, { truth: 'safe', predicted: 'safe' }],
    costs: [0.1, 0.2],
    taskCompletion: { completed: 3, total: 4 },
    repeatedRuns: [{ score: 1 }, { score: 0.8 }, { score: 0.9 }],
  })
  assert.equal(report.counts.tp, 1)
  assert.equal(report.avr, 0.5)
  assert.equal(report.frr, 0.5)
  assert.equal(report.tcr, 0.75)
  assert.equal(report.cost.total, 0.30000000000000004)
  assert.equal(report.repeatedRuns.runs, 3)
  assert.equal(report.dataset.fingerprint, datasetFingerprint([{ id: 1 }]))
  assert.throws(() => buildLLMReport({ model: { name: 'x' }, dataset: [], cases: [] }), /model.version/)
})
