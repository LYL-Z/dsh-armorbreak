#!/usr/bin/env node
/** ABU-007: reproducible 2.2.0-rc.1 release smoke over the evidence chain. */
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { checkDocs } from '../../lib/release/docsConsistency.js'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'
import { computeReleaseGates } from '../../lib/release/gates.js'

const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const json = (path) => JSON.parse(readFileSync(path, 'utf8'))
const pkg = json('package.json')
const lock = json('docs/v2/bundle.lock.json')
const sbom = json('docs/v2/release/sbom.spdx.json')
const readiness = json('docs/v2/release/readiness.json')
const testReport = json('docs/v2/acceptance/test-report.json')
const manifest = json('docs/v2/acceptance/evidence-manifest.json')
const counts = (value) => JSON.stringify(value ?? null)
const checks = []
const add = (id, ok, detail) => checks.push({ id, status: ok ? 'PASS' : 'FAIL', detail })
add('package-version', pkg.version === '2.2.0-rc.1', pkg.version)
add('bundle-version', lock.version === pkg.version, lock.version)
add('sbom-version', String(sbom.name ?? '').includes(pkg.version), sbom.name)
add('readiness-version', readiness.package?.version === pkg.version, readiness.package?.version)
add('readiness-evidence-current', Boolean(
  readiness.evidence?.manifestCommit === manifest.commit
  && readiness.evidence?.testReportCommit === testReport.commit
  && counts(readiness.evidence?.testCounts) === counts(testReport.counts)
  && testReport.commit === manifest.commit
), `readiness=${readiness.evidence?.manifestCommit ?? 'missing'} manifest=${manifest.commit ?? 'missing'} tests=${testReport.commit ?? 'missing'}`)
const docIssues = checkDocs(process.cwd())
add('docs-consistency', docIssues.length === 0, docIssues.join('; ') || 'no issues')
const evidence = validateEvidence({ repoRoot: process.cwd(), commit, allowEvidenceAncestor: true })
add('evidence-hashes', evidence.ok, evidence.issues.join('; ') || `${evidence.checked} files verified`)
const gates = computeReleaseGates({ repoRoot: process.cwd(), commit, allowEvidenceAncestor: true })
add('release-gates', gates.releasable === true, gates.reason)
add('tag-immutable', (() => {
  try { return execFileSync('git', ['rev-parse', 'v2.0.0^{commit}'], { encoding: 'utf8' }).trim() === 'f96d03acad441b4b5a4b9d141dd553e3224c3745' } catch { return false }
})(), 'v2.0.0 tag still points at the published merge commit')
const report = { schemaVersion: 'armorbreak.release-smoke/v1', generatedAt: new Date().toISOString(), commit, version: pkg.version, checks, result: checks.every((check) => check.status === 'PASS') ? 'PASS' : 'FAIL' }
writeFileSync(join('docs/v2/acceptance', 'release-smoke.json'), `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ result: report.result, checks }, null, 2))
if (report.result !== 'PASS') process.exitCode = 1
