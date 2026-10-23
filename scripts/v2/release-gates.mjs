#!/usr/bin/env node
/** ABU-002/003: write the evidence-driven release gate report. */
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { computeReleaseGates, docsOnlyGateReport } from '../../lib/release/gates.js'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'

const arg = (name) => {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] && !process.argv[index + 1].startsWith('--') ? process.argv[index + 1] : undefined
}
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const base = arg('--base') ?? process.env.EVIDENCE_BASE_SHA
const validation = validateEvidence({
  repoRoot: process.cwd(),
  commit,
  base,
  allowDocsOnly: process.argv.includes('--allow-docs-only'),
  allowEvidenceAncestor: process.argv.includes('--allow-evidence-only'),
})
const report = validation.mode === 'docs-only'
  ? docsOnlyGateReport({ commit, validation })
  : computeReleaseGates({ commit, allowEvidenceAncestor: true })
writeFileSync('docs/v2/acceptance/release-gates.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ commit, releasable: report.releasable, mode: report.mode ?? 'release-gates', applicability: report.applicability ?? 'RELEASE_GATES', gates: report.gates ? Object.fromEntries(Object.entries(report.gates).map(([name, gate]) => [name, gate.status])) : undefined, testReport: report.testReport }, null, 2))
if (validation.mode === 'docs-only') {
  if (!validation.ok) process.exitCode = 1
} else if (!report.releasable) process.exitCode = 1
