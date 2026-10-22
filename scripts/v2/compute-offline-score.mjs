#!/usr/bin/env node
/**
 * AB2-M4-08 offline-score report. Recomputes from the frozen benchmark output;
 * R_offline stays null until an online-reference run exists.
 */
import { readFile, writeFile } from 'node:fs/promises'

const bench = JSON.parse((await readFile('docs/v2/acceptance/offline-score.json', 'utf8')).replace(/^\uFEFF/, ''))
const targetTotal = bench.targetTotal
const targetPass = bench.summary?.targetPass ?? 0
const report = {
  schemaVersion: 'armorbreak.offline-score-final/v1',
  generatedAt: new Date().toISOString(),
  source: 'docs/v2/acceptance/offline-score.json',
  frozenScenarioSet: 'docs/v2/benchmark/core-scenarios.json',
  environment: bench.environment,
  denominator: { targetTotal, targetRunnable: bench.targetRunnable, extraScenarios: bench.summary?.extraScenarios ?? 0 },
  targetPass,
  coreOfflinePassRate: targetTotal > 0 ? targetPass / targetTotal : null,
  coreL0OfflineRate: targetTotal > 0 ? targetPass / targetTotal : null,
  relativeOfflineRetention: null,
  onlineOnlyFeatureShare: null,
  offlineCoverageWeighted: null,
  metricStatus: 'relative/weighted metrics N/A without a frozen online reference',
  rOffline: null,
  rOfflineReason: 'No frozen online-reference run; architecture formula requires A_online(i)=1 for the same target set. Not reported as 100%.',
  excluded: [{ id: 'extra-ctf-web', count: bench.summary?.extraScenarios ?? 0, reason: 'outside 62 target-domain denominator' }],
  gate: targetPass === targetTotal && targetTotal === 62 ? 'PASS' : 'FAIL',
  reproduce: 'node scripts/v2/core-benchmark.mjs && node scripts/v2/compute-offline-score.mjs',
}
await writeFile('docs/v2/acceptance/offline-score-v2.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ gate: report.gate, coreL0OfflineRate: report.coreL0OfflineRate, rOffline: report.rOffline, denominator: report.denominator }, null, 2))
