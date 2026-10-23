/** ABU-006: validate pinned evidence, raw test TAP, and Desktop evidence references. */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex')

const PROTECTED_DOC_PREFIXES = [
  'docs/acceptance/',
  'docs/audit/',
  'docs/releases/',
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
  'docs/v2/aisec-worker-protocol.md',
  'docs/v2/provider-security.md',
])
const PROTECTED_DOC_PATTERNS = [/^docs\/acceptance(?:-.*)?\.md$/]

function git(repoRoot, args) {
  return execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim()
}

function isDocsOnlyPath(path) {
  if (path.includes('\\')) return false
  if (/^README(?:\.[A-Za-z0-9._-]+)?\.md$/.test(path)) return true
  if (!path.startsWith('docs/') || !path.endsWith('.md')) return false
  if (PROTECTED_DOC_PREFIXES.some((prefix) => path.startsWith(prefix))) return false
  if (PROTECTED_DOC_FILES.has(path)) return false
  if (PROTECTED_DOC_PATTERNS.some((pattern) => pattern.test(path))) return false
  if (path.startsWith('docs/v2/release/') && path !== 'docs/v2/release/user-guide.md') return false
  return true
}

function changedPaths(repoRoot, base, head) {
  const output = execFileSync('git', ['-C', repoRoot, 'diff', '--name-only', '--no-renames', '-z', `${base}..${head}`], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  return output.split('\0').filter(Boolean)
}

function fileEntryKind(repoRoot, head, path) {
  try {
    const output = git(repoRoot, ['ls-tree', '-z', head, '--', path])
    if (!output) return 'missing'
    const mode = output.split('\0')[0].split(' ')[0]
    if (mode === '100644' || mode === '100755') return 'regular'
    if (mode === '120000') return 'symlink'
    if (mode === '160000') return 'gitlink'
    return 'other'
  } catch {
    return 'missing'
  }
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
    changed.push(...changedPaths(repoRoot, base, head))
    if (changed.length === 0) issues.push('no changed files; docs-only classification requires at least one document change')
    for (const path of changed) {
      if (!isDocsOnlyPath(path)) {
        issues.push(`non-doc change is not eligible for docs-only evidence reuse: ${path}`)
      } else {
        const kind = fileEntryKind(repoRoot, head, path)
        if (kind === 'symlink' || kind === 'gitlink' || kind === 'other') {
          issues.push(`non-regular document entry is not eligible for docs-only reuse: ${path} (${kind})`)
        }
      }
    }
  } catch {
    issues.push('unable to classify docs-only change from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

/**
 * An evidence-only append is allowed only when every path changed after the
 * manifest's source commit is acceptance evidence or readiness metadata. The
 * source commit itself must remain the manifest baseline, and Git replace refs
 * are rejected just as in docs-only mode.
 */
export function classifyEvidenceOnly({ repoRoot = process.cwd(), base, head, allowReadiness = false } = {}) {
  const issues = []
  const changed = []
  if (!base || !head) return { ok: false, base: base ?? null, head: head ?? null, changed, issues: ['base and head are required'] }
  try {
    if (process.env.GIT_REPLACE_REF_BASE) {
      issues.push('custom GIT_REPLACE_REF_BASE is not allowed for evidence-only classification')
    }
    const replaceRefs = git(repoRoot, ['for-each-ref', '--format=%(refname)', 'refs/replace/'])
    if (replaceRefs) issues.push('git replace refs are not allowed for evidence-only classification')
    git(repoRoot, ['rev-parse', '--verify', `${base}^{commit}`])
    git(repoRoot, ['rev-parse', '--verify', `${head}^{commit}`])
    git(repoRoot, ['merge-base', '--is-ancestor', base, head])
    changed.push(...changedPaths(repoRoot, base, head))
    if (changed.length === 0) issues.push('no changed files; evidence-only append requires at least one evidence change')
    for (const path of changed) {
      if (!path.startsWith('docs/v2/acceptance/') && !(allowReadiness && path === 'docs/v2/release/readiness.json')) {
        issues.push(`non-evidence change is not eligible for evidence-only reuse: ${path}`)
      } else if (fileEntryKind(repoRoot, head, path) !== 'regular') {
        issues.push(`non-regular evidence entry is not eligible for evidence-only reuse: ${path}`)
      }
    }
  } catch {
    issues.push('unable to classify evidence-only change from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

/**
 * A target base may contain evidence commits and previously merged docs-only
 * changes, but no source/CI/build/security change after the manifest source.
 * This is the baseline condition for docs-only reuse.
 */
export function classifyDocsBaseline({ repoRoot = process.cwd(), base, head } = {}) {
  const issues = []
  const changed = []
  if (!base || !head) return { ok: false, base: base ?? null, head: head ?? null, changed, issues: ['base and head are required'] }
  try {
    if (process.env.GIT_REPLACE_REF_BASE) issues.push('custom GIT_REPLACE_REF_BASE is not allowed for docs baseline classification')
    if (git(repoRoot, ['for-each-ref', '--format=%(refname)', 'refs/replace/'])) issues.push('git replace refs are not allowed for docs baseline classification')
    git(repoRoot, ['rev-parse', '--verify', `${base}^{commit}`])
    git(repoRoot, ['rev-parse', '--verify', `${head}^{commit}`])
    git(repoRoot, ['merge-base', '--is-ancestor', base, head])
    changed.push(...changedPaths(repoRoot, base, head))
    for (const path of changed) {
      if (path.startsWith('docs/v2/acceptance/') || path === 'docs/v2/release/readiness.json') {
        // readiness is generated acceptance metadata on the target branch;
        // docs-only gate evaluation still evaluates the base release gates.
        if (fileEntryKind(repoRoot, head, path) !== 'regular') issues.push(`non-regular acceptance metadata in target base: ${path}`)
        continue
      }
      if (!isDocsOnlyPath(path)) {
        issues.push(`target base has non-doc change after evidence: ${path}`)
        continue
      }
      const kind = fileEntryKind(repoRoot, head, path)
      if (kind === 'symlink' || kind === 'gitlink' || kind === 'other') issues.push(`non-regular document entry in target base: ${path} (${kind})`)
    }
  } catch {
    issues.push('unable to classify target-base changes from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

export function validateEvidence({ repoRoot = process.cwd(), commit, base, allowEvidenceAncestor = false, allowDocsOnly = false, requireClean = false } = {}) {
  const issues = []
  if (requireClean) {
    try {
      if (git(repoRoot, ['status', '--porcelain'])) issues.push('working tree is dirty; evidence must be validated from a clean committed tree')
    } catch {
      issues.push('unable to verify clean working tree')
    }
  }
  const acceptance = join(repoRoot, 'docs/v2/acceptance')
  const manifestPath = join(acceptance, 'evidence-manifest.json')
  if (!existsSync(manifestPath)) return { ok: false, issues: [...issues, 'evidence-manifest.json missing'], checked: 0, mode: 'missing', docsOnly: null }
  let manifest
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) } catch { return { ok: false, issues: [...issues, 'evidence-manifest.json is not valid JSON'], checked: 0, mode: 'invalid', docsOnly: null } }
  if (manifest.schemaVersion !== 'armorbreak.evidence-manifest/v1') issues.push('manifest schemaVersion is invalid')
  for (const required of ['docs/v2/acceptance/test-report.json', 'docs/v2/acceptance/test-report.tap']) {
    if (!manifest.files?.[required]) issues.push(`manifest missing required evidence: ${required}`)
  }
  for (const rel of Object.keys(manifest.files ?? {})) {
    if (!rel.startsWith('docs/v2/acceptance/')) issues.push(`manifest pins a path outside acceptance evidence: ${rel}`)
  }
  const evidenceOnly = allowEvidenceAncestor && commit && manifest.commit !== commit
    ? classifyEvidenceOnly({ repoRoot, base: manifest.commit, head: commit })
    : null
  const evidenceOnlyAccepted = evidenceOnly?.ok === true
  const docsOnly = allowDocsOnly && commit && manifest.commit !== commit && !evidenceOnlyAccepted
    ? (base
      ? classifyDocsOnly({ repoRoot, base, head: commit })
      : { ok: false, base: null, head: commit, changed: [], issues: ['target branch base is required for docs-only evidence reuse'] })
    : null
  let docsOnlyAccepted = docsOnly?.ok === true
  let docsOnlyBase = null
  if (docsOnlyAccepted) {
    docsOnlyBase = manifest.commit === base
      ? { ok: true, base: base, changed: [], issues: [] }
      : classifyDocsBaseline({ repoRoot, base: manifest.commit, head: base })
    if (!docsOnlyBase.ok) {
      docsOnlyAccepted = false
      docsOnly.ok = false
      docsOnly.issues.push('target base contains source/security changes after the evidence baseline')
      issues.push('docs-only base is not evidence-backed: target base has unbound changes after the manifest source commit')
    }
  }
  const acceptedBaseline = manifest.commit === commit || evidenceOnlyAccepted || docsOnlyAccepted
  if (commit && manifest.commit !== commit && !acceptedBaseline) {
    issues.push(`manifest commit ${manifest.commit} does not match ${commit}`)
  }
  if (evidenceOnly && !evidenceOnly.ok && !docsOnlyAccepted) {
    issues.push(...evidenceOnly.issues.map((issue) => `evidence-only: ${issue}`))
  }
  if (docsOnly && !docsOnly.ok && !evidenceOnlyAccepted) {
    issues.push(...docsOnly.issues.map((issue) => `docs-only: ${issue}`))
  }
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
    let report = null
    try { report = JSON.parse(readFileSync(reportPath, 'utf8')) } catch { issues.push('test report is not valid JSON') }
    if (report) {
      const reportAncestor = report.commit === commit ||
        ((evidenceOnlyAccepted || docsOnlyAccepted) && report.commit === manifest.commit)
      if (commit && report.commit !== commit && !reportAncestor) issues.push('test report commit is stale')
      if (report.tapSha256 !== sha(tapPath)) issues.push('test report TAP hash mismatch')
    }
  }
  const desktopPath = join(acceptance, 'desktop-e2e.json')
  if (existsSync(desktopPath)) {
    let desktop = null
    try { desktop = JSON.parse(readFileSync(desktopPath, 'utf8')) } catch { issues.push('desktop E2E evidence is not valid JSON') }
    if (desktop) {
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
  }
  const mode = docsOnlyAccepted ? 'docs-only' : evidenceOnlyAccepted ? 'evidence-only' : (manifest.commit === commit ? 'commit-bound' : 'legacy-evidence')
  return { ok: issues.length === 0, issues, checked, mode, docsOnly, docsOnlyBase, evidenceOnly }
}
