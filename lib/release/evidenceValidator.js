/** ABU-006: validate pinned evidence, raw test TAP, and Desktop evidence references. */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex')

const PROTECTED_DOC_PREFIXES = [
  'docs/v2/acceptance/',
  'docs/v2/tasks/',
  'docs/v2/generated/',
  'docs/v2/security/',
]
const PROTECTED_DOC_FILES = new Set([
  'SECURITY.md',
  'docs/security-model.md',
  'docs/security-boundary-review.md',
  'docs/v2/threat-model.md',
  'docs/v2/aisec-threat-map.md',
])

function git(repoRoot, args) {
  return execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim()
}

function isDocsOnlyPath(path) {
  const normalized = path.replaceAll('\\', '/')
  if (/^README(?:\.[A-Za-z0-9._-]+)?\.md$/.test(normalized)) return true
  if (!normalized.startsWith('docs/') || !normalized.endsWith('.md')) return false
  if (PROTECTED_DOC_PREFIXES.some((prefix) => normalized.startsWith(prefix))) return false
  if (PROTECTED_DOC_FILES.has(normalized)) return false
  if (normalized.startsWith('docs/v2/release/') && normalized !== 'docs/v2/release/user-guide.md') return false
  return true
}

/**
 * A docs-only change may reuse a pinned evidence baseline only when every path
 * changed between the evidence commit and the target is an allowed Markdown
 * document. This is path-based: PR titles, labels, and commit messages are not
 * trusted. Git replace refs are rejected because they can rewrite history.
 */
export function classifyDocsOnly({ repoRoot = process.cwd(), base, head } = {}) {
  const issues = []
  const changed = []
  if (!base || !head) return { ok: false, base: base ?? null, head: head ?? null, changed, issues: ['base and head are required'] }
  try {
    if (process.env.GIT_REPLACE_REF_BASE) {
      issues.push('custom GIT_REPLACE_REF_BASE is not allowed for docs-only classification')
    }
    const replaceRefs = git(repoRoot, ['for-each-ref', '--format=%(refname)', 'refs/replace/'])
    if (replaceRefs) issues.push('git replace refs are not allowed for docs-only classification')
    git(repoRoot, ['rev-parse', '--verify', `${base}^{commit}`])
    git(repoRoot, ['rev-parse', '--verify', `${head}^{commit}`])
    git(repoRoot, ['merge-base', '--is-ancestor', base, head])
    const output = git(repoRoot, ['diff', '--name-only', '--no-renames', `${base}..${head}`])
    changed.push(...output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))
    if (changed.length === 0) issues.push('no changed files; docs-only classification requires at least one document change')
    for (const path of changed) {
      if (!isDocsOnlyPath(path)) issues.push(`non-doc change is not eligible for docs-only evidence reuse: ${path}`)
    }
  } catch {
    issues.push('unable to classify docs-only change from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

export function validateEvidence({ repoRoot = process.cwd(), commit, base, allowEvidenceAncestor = false, allowDocsOnly = false } = {}) {
  const issues = []
  const acceptance = join(repoRoot, 'docs/v2/acceptance')
  const manifestPath = join(acceptance, 'evidence-manifest.json')
  if (!existsSync(manifestPath)) return { ok: false, issues: ['evidence-manifest.json missing'], checked: 0, mode: 'missing', docsOnly: null }
  let manifest
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) } catch { return { ok: false, issues: ['evidence-manifest.json is not valid JSON'], checked: 0, mode: 'invalid', docsOnly: null } }
  if (manifest.schemaVersion !== 'armorbreak.evidence-manifest/v1') issues.push('manifest schemaVersion is invalid')
  const allowedAncestor = (ancestor, tip) => {
    if (!allowEvidenceAncestor || !ancestor || !tip || ancestor === tip) return ancestor === tip
    try {
      execFileSync('git', ['merge-base', '--is-ancestor', ancestor, tip], { cwd: repoRoot, stdio: 'ignore' })
      const changed = execFileSync('git', ['diff', '--name-only', `${ancestor}..${tip}`], { cwd: repoRoot, encoding: 'utf8' }).split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
      return changed.length > 0 && changed.every((path) => path.startsWith('docs/v2/acceptance/') || path === 'docs/v2/release/readiness.json')
    } catch { return false }
  }
  const docsOnly = allowDocsOnly && commit && manifest.commit !== commit
    ? (base
      ? classifyDocsOnly({ repoRoot, base, head: commit })
      : { ok: false, base: null, head: commit, changed: [], issues: ['target branch base is required for docs-only evidence reuse'] })
    : null
  const docsOnlyAccepted = docsOnly?.ok === true
  const manifestAncestor = manifest.commit === commit || allowedAncestor(manifest.commit, commit)
  if (commit && manifest.commit !== commit && !manifestAncestor && !docsOnlyAccepted) {
    issues.push(`manifest commit ${manifest.commit} does not match ${commit}`)
  }
  if (docsOnly && !docsOnly.ok) issues.push(...docsOnly.issues.map((issue) => `docs-only: ${issue}`))
  let checked = 0
  for (const [rel, record] of Object.entries(manifest.files ?? {})) {
    const full = join(repoRoot, rel)
    if (!existsSync(full)) { issues.push(`${rel} is pinned but missing`); continue }
    const stat = statSync(full)
    if (stat.size !== record.size) { issues.push(`${rel} size mismatch`); continue }
    const actual = sha(full)
    if (actual !== record.sha256) { issues.push(`${rel} hash mismatch`); continue }
    checked += 1
  }
  const reportPath = join(acceptance, 'test-report.json')
  const tapPath = join(acceptance, 'test-report.tap')
  if (!existsSync(reportPath) || !existsSync(tapPath)) issues.push('test report/TAP missing')
  else {
    const report = JSON.parse(readFileSync(reportPath, 'utf8'))
    const reportAncestor = report.commit === commit || allowedAncestor(report.commit, commit) || docsOnlyAccepted
    if (commit && report.commit !== commit && !reportAncestor) issues.push('test report commit is stale')
    if (report.tapSha256 !== sha(tapPath)) issues.push('test report TAP hash mismatch')
  }
  const desktopPath = join(acceptance, 'desktop-e2e.json')
  if (existsSync(desktopPath)) {
    const desktop = JSON.parse(readFileSync(desktopPath, 'utf8'))
    for (const shot of desktop.screenshots ?? []) {
      const full = join(repoRoot, String(shot.path ?? ''))
      if (!existsSync(full)) issues.push(`desktop screenshot missing: ${shot.path}`)
      else if (sha(full) !== shot.sha256) issues.push(`desktop screenshot hash mismatch: ${shot.path}`)
    }
    const copy = join(acceptance, 'desktop-l0-report.md')
    if (desktop.l0Task?.reportSha256) {
      if (!existsSync(copy)) issues.push('desktop L0 report copy missing')
      else if (sha(copy) !== desktop.l0Task.reportSha256) issues.push('desktop L0 report hash mismatch')
    }
  }
  const mode = docsOnlyAccepted ? 'docs-only' : (manifest.commit === commit ? 'commit-bound' : 'legacy-evidence')
  return { ok: issues.length === 0, issues, checked, mode, docsOnly }
}
