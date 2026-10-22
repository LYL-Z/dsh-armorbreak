/** ABU-006: validate pinned evidence, raw test TAP, and Desktop evidence references. */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex')

export function validateEvidence({ repoRoot = process.cwd(), commit, allowEvidenceAncestor = false } = {}) {
  const issues = []
  const acceptance = join(repoRoot, 'docs/v2/acceptance')
  const manifestPath = join(acceptance, 'evidence-manifest.json')
  if (!existsSync(manifestPath)) return { ok: false, issues: ['evidence-manifest.json missing'], checked: 0 }
  let manifest
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) } catch { return { ok: false, issues: ['evidence-manifest.json is not valid JSON'], checked: 0 } }
  if (manifest.schemaVersion !== 'armorbreak.evidence-manifest/v1') issues.push('manifest schemaVersion is invalid')
  const allowedAncestor = (ancestor, tip) => {
    if (!allowEvidenceAncestor || !ancestor || !tip || ancestor === tip) return ancestor === tip
    try {
      execFileSync('git', ['merge-base', '--is-ancestor', ancestor, tip], { cwd: repoRoot, stdio: 'ignore' })
      const changed = execFileSync('git', ['diff', '--name-only', `${ancestor}..${tip}`], { cwd: repoRoot, encoding: 'utf8' }).split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
      return changed.length > 0 && changed.every((path) => path.startsWith('docs/v2/acceptance/') || path === 'docs/v2/release/readiness.json')
    } catch { return false }
  }
  const manifestAncestor = manifest.commit === commit || allowedAncestor(manifest.commit, commit)
  if (commit && manifest.commit !== commit && !manifestAncestor) issues.push(`manifest commit ${manifest.commit} does not match ${commit}`)
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
    const reportAncestor = report.commit === commit || allowedAncestor(report.commit, commit)
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
  return { ok: issues.length === 0, issues, checked }
}
