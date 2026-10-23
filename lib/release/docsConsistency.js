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
    if (readiness.package?.version && pkg.version !== readiness.package.version) {
      issues.push(`version mismatch: package.json=${pkg.version}, readiness=${readiness.package.version}`)
    }
  } catch (error) {
    /* missing files are reported by other release checks, not this linter */
    if (error?.code !== 'ENOENT') issues.push(`release metadata path is unsafe or invalid (${error?.message ?? 'read failed'})`)
  }
  return issues
}
