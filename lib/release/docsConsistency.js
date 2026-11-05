/**
 * ABU-004: release-document consistency checks. Historical v1.2 wording is
 * allowed only in explicitly historical files; current release documents must
 * not contradict the current evidence.
 */
import { readSafeRepoFile } from './safeEvidenceFile.js'

const RULES = [
  { file: 'docs/v2/release/platform-matrix.md', pattern: /Windows DSH Desktop real GUI \+ model[\s\S]{0,120}\*\*BLOCKED\*\*/i, message: 'platform matrix still marks Windows Desktop E2E BLOCKED' },
  { file: 'docs/v2/release/compatibility-runtime.md', pattern: /M4-06 remains REVIEW\/BLOCKED|real V2 Desktop GUI\/model E2E was \*\*not\*\*/i, message: 'compatibility runtime still says real V2 Desktop E2E was not executed' },
  { file: 'docs/v2/release/plan.md', pattern: /M4-06 real Desktop\/model E2E BLOCKED|M4-03\/04\/07\/10\/11\/12 remain REVIEW/i, message: 'release plan still lists completed M4 items as blockers' },
  { file: 'docs/v2/release/license-audit.md', pattern: /\*\*NOT READY\*\*/i, message: 'license audit still says NOT READY' },
  { file: 'docs/v2/acceptance/test-matrix.md', pattern: /269 tests|Desktop GUI model E2E[\s\S]{0,160}\| REVIEW \|/i, message: 'test matrix is stale or still marks Desktop E2E REVIEW' },
  { file: 'docs/known-issues.md', pattern: /^# 已知问题与限制（v1\.2\.0）/m, message: 'known issues title is still v1.2.0' },
  { file: 'README.md', pattern: /tests-190|190 \/ 190|\b190 个测试\b/, message: 'README still advertises the old 190-test count' },
]

export function checkDocs(root = process.cwd()) {
  const issues = []
  for (const rule of RULES) {
    let text
    try { text = readSafeRepoFile(root, rule.file).toString('utf8') } catch (error) {
      if (error?.code === 'ENOENT') continue
      issues.push(`${rule.file}: unsafe document path (${error?.message ?? 'read failed'})`)
      continue
    }
    if (rule.pattern.test(text)) issues.push(`${rule.file}: ${rule.message}`)
  }
  try {
    const pkg = JSON.parse(readSafeRepoFile(root, 'package.json').toString('utf8'))
    const readiness = JSON.parse(readSafeRepoFile(root, 'docs/v2/release/readiness.json', { requiredPrefix: 'docs/v2/release/' }).toString('utf8'))
    let stablePolicy = null
    try {
      stablePolicy = JSON.parse(readSafeRepoFile(root, 'docs/v2/release/v2.2-stable-scope-v1.json', { requiredPrefix: 'docs/v2/release/' }).toString('utf8'))
    } catch (error) { if (error?.code !== 'ENOENT') throw error }
    if (stablePolicy) {
      const snapshot = stablePolicy.legacyFullGa?.legacyReleaseSnapshot
      const readinessIsRecordedHistorical = snapshot?.status === 'HISTORICAL_RC_EVIDENCE' &&
        snapshot.file === 'docs/v2/release/readiness.json' && snapshot.preserveOriginalEvidence === true &&
        readiness.package?.version === snapshot.packageVersion
      if (stablePolicy.schemaVersion !== 'armorbreak.v2.2-stable-scope/v1' || stablePolicy.packageVersion !== '2.2.0' || stablePolicy.tag !== 'v2.2.0' || readiness.package?.version !== snapshot?.packageVersion || !readinessIsRecordedHistorical) {
        issues.push('historical V2.2 Stable policy/readiness identity or preservation record changed')
      }
      if (pkg.version === '2.3.0') {
        try {
          const matrix = JSON.parse(readSafeRepoFile(root, 'docs/v2.3/compatibility-matrix.json').toString('utf8'))
          const manifest = JSON.parse(readSafeRepoFile(root, 'docs/v2.3/evidence/p0-h/acceptance-manifest.json').toString('utf8'))
          const p0h = matrix.milestones?.find((item) => item.id === 'P0-H')
          const report = readSafeRepoFile(root, 'docs/v2.3/acceptance-report.md').toString('utf8')
          if (matrix.schemaVersion !== 'armorbreak.v2.3.compatibility-matrix/v1' || matrix.baselineSha !== '66ec0017af4b9d636f09e45f7cf55eed060512ac' || !['IN_PROGRESS', 'COMPLETE'].includes(p0h?.status)) issues.push('V2.3 candidate package has invalid version/milestone evidence')
          if (manifest.baselineSha !== matrix.baselineSha || !/\b(?:READY|NOT_READY)\b/.test(report)) issues.push('V2.3 candidate package does not state an explicit release readiness status')
        } catch (error) {
          issues.push(`V2.3 candidate metadata is missing or invalid (${error?.message ?? 'read failed'})`)
        }
      } else if (pkg.version !== stablePolicy.packageVersion) {
        issues.push(`Stable policy/package version mismatch: package.json=${pkg.version}, policy=${stablePolicy.packageVersion}`)
      }
      if (pkg.version !== '2.3.0' && readiness.package?.version && pkg.version !== readiness.package.version && !readinessIsRecordedHistorical) {
        issues.push(`version mismatch lacks a versioned historical-evidence record: package.json=${pkg.version}, readiness=${readiness.package.version}`)
      }
    } else if (readiness.package?.version && pkg.version !== readiness.package.version) {
      issues.push(`version mismatch: package.json=${pkg.version}, readiness=${readiness.package.version}`)
    }
  } catch (error) {
    /* missing files are reported by other release checks, not this linter */
    if (error?.code !== 'ENOENT') issues.push(`release metadata path is unsafe or invalid (${error?.message ?? 'read failed'})`)
  }
  return issues
}
