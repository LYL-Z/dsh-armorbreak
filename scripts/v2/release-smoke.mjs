#!/usr/bin/env node
/** Stable-scope smoke over current package metadata and preserved historical Full GA evidence. */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { checkDocs } from '../../lib/release/docsConsistency.js'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'
import { computeReleaseGates } from '../../lib/release/gates.js'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = process.cwd()
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const json = (path) => JSON.parse(readSafeRepoFile(root, path).toString('utf8'))
const pkg = json('package.json')
const stablePolicy = json('docs/v2/release/v2.2-stable-scope-v1.json')
const lock = json('docs/v2/bundle.lock.json')
const sbom = json('docs/v2/release/sbom.spdx.json')
const historicalReadinessBytes = readSafeRepoFile(root, 'docs/v2/release/readiness.json', { requiredPrefix: 'docs/v2/release/' })
const historicalReadiness = JSON.parse(historicalReadinessBytes.toString('utf8'))
const stableReadiness = json('docs/v2/release/stable-readiness.json')
const legacyReadinessBytes = readSafeRepoFile(root, 'docs/v2/acceptance/v2.2-readiness.json', { requiredPrefix: 'docs/v2/acceptance/' })
const legacyReadiness = json('docs/v2/acceptance/v2.2-readiness.json')
const legacyScope = json('docs/v2/acceptance/release-scope.json')
const testReport = json('docs/v2/acceptance/test-report.json')
const manifest = json('docs/v2/acceptance/evidence-manifest.json')
const counts = (value) => JSON.stringify(value ?? null)
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const checks = []
const add = (id, ok, detail) => checks.push({ id, status: ok ? 'PASS' : 'FAIL', detail })
add('package-version', pkg.version === stablePolicy.packageVersion && stablePolicy.channel === 'stable', pkg.version)
add('bundle-version', lock.version === pkg.version, lock.version)
add('sbom-version', String(sbom.name ?? '').includes(pkg.version), sbom.name)
add('historical-readiness-preserved', historicalReadiness.package?.version === stablePolicy.legacyFullGa?.legacyReleaseSnapshot?.packageVersion &&
  sha256(historicalReadinessBytes) === stablePolicy.legacyFullGa?.legacyReleaseSnapshot?.sha256 &&
  stablePolicy.legacyFullGa?.legacyReleaseSnapshot?.status === 'HISTORICAL_RC_EVIDENCE' &&
  stablePolicy.legacyFullGa?.legacyReleaseSnapshot?.preserveOriginalEvidence === true, historicalReadiness.package?.version)
add('legacy-full-ga-still-blocked', legacyReadiness.gaReady === false && Array.isArray(legacyReadiness.gaBlockers) &&
  legacyReadiness.gaBlockers.length > 0 &&
  sha256(legacyReadinessBytes) === stablePolicy.legacyFullGa?.readinessFileSha256 &&
  legacyScope.v22FullGa?.status === 'BLOCKED_EXTERNAL',
  `${legacyReadiness.gaBlockers?.length ?? 0} historical blockers; gaReady=${legacyReadiness.gaReady}`)
add('readiness-evidence-current', Boolean(
  stableReadiness.evidence?.manifestCommit === manifest.commit
  && stableReadiness.evidence?.testReportCommit === testReport.commit
  && counts(stableReadiness.evidence?.testCounts) === counts(testReport.counts)
  && testReport.commit === manifest.commit
), `readiness=${stableReadiness.evidence?.manifestCommit ?? 'missing'} manifest=${manifest.commit ?? 'missing'} tests=${testReport.commit ?? 'missing'}`)
const docIssues = checkDocs(process.cwd())
add('docs-consistency', docIssues.length === 0, docIssues.join('; ') || 'no issues')
const evidence = validateEvidence({ repoRoot: root, commit, allowEvidenceAncestor: true, allowReadiness: true })
add('evidence-hashes', evidence.ok, evidence.issues.join('; ') || `${evidence.checked} files verified`)
const gates = computeReleaseGates({ repoRoot: root, commit, allowEvidenceAncestor: true })
add('release-gates-local-checks', gates.localChecksPass === true && gates.releasable === false && gates.releaseAuthorization?.status === 'BLOCKED', gates.reason)
add('tag-immutable', (() => {
  try { return execFileSync('git', ['rev-parse', 'v2.0.0^{commit}'], { encoding: 'utf8' }).trim() === 'f96d03acad441b4b5a4b9d141dd553e3224c3745' } catch { return false }
})(), 'v2.0.0 tag still points at the published merge commit')
const report = { schemaVersion: 'armorbreak.release-smoke/v1', generatedAt: new Date().toISOString(), commit, version: pkg.version, checks, result: checks.every((check) => check.status === 'PASS') ? 'PASS' : 'FAIL' }
writeSafeRepoFile(root, 'docs/v2/acceptance/release-smoke.json', `${JSON.stringify(report, null, 2)}\n`, { requiredPrefix: 'docs/v2/acceptance/' })
console.log(JSON.stringify({ result: report.result, checks }, null, 2))
if (report.result !== 'PASS') process.exitCode = 1
