#!/usr/bin/env node
/** ABU-002/003: write the evidence-driven release gate report. */
import { execFileSync } from 'node:child_process'
import { computeReleaseGates, docsOnlyGateReport } from '../../lib/release/gates.js'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'
import { writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const arg = (name) => {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] && !process.argv[index + 1].startsWith('--') ? process.argv[index + 1] : undefined
}
const isTag = process.env.GITHUB_REF_TYPE === 'tag' || String(process.env.GITHUB_REF ?? '').startsWith('refs/tags/')
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const base = arg('--base') ?? process.env.EVIDENCE_BASE_SHA
const allowDocsOnly = process.argv.includes('--allow-docs-only') && !isTag
const allowEvidenceOnly = process.argv.includes('--allow-evidence-only') && !isTag
const allowReadiness = process.argv.includes('--allow-readiness') && allowEvidenceOnly && !isTag
const validation = validateEvidence({
  repoRoot: process.cwd(),
  commit,
  base,
  allowDocsOnly,
  allowEvidenceAncestor: allowEvidenceOnly,
  allowReadiness,
})
let report
if (validation.mode === 'docs-only' && !isTag) {
  if (!base) {
    report = { schemaVersion: 'armorbreak.release-gates/v2', commit, mode: 'docs-only', applicability: 'BLOCKED', releasable: false, reason: 'docs-only mode requires a target base' }
  } else {
    const baseReport = computeReleaseGates({ repoRoot: process.cwd(), commit: base, allowEvidenceAncestor: true, allowDocsAncestor: true })
    report = docsOnlyGateReport({ commit, baseCommit: base, baseReport, validation })
  }
} else {
    report = computeReleaseGates({ commit, allowEvidenceAncestor: !isTag })
}
if (!validation.ok) {
  report.releasable = false
  report.reason = `evidence validation failed: ${validation.issues.join('; ')}`
}
writeSafeRepoFile(process.cwd(), 'docs/v2/acceptance/release-gates.json', `${JSON.stringify(report, null, 2)}\n`, { requiredPrefix: 'docs/v2/acceptance/' })
console.log(JSON.stringify({ commit, releasable: report.releasable, mode: report.mode ?? 'release-gates', applicability: report.applicability ?? 'RELEASE_GATES', gates: report.gates ? Object.fromEntries(Object.entries(report.gates).map(([name, gate]) => [name, gate.status])) : undefined, testReport: report.testReport }, null, 2))
if (!validation.ok || !report.releasable) process.exitCode = 1
