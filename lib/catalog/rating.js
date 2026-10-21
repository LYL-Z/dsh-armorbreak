/**
 * AB2-M2-13 explainable open-source rating.
 *
 * Every score is derived from explicit evidence entries (source + date +
 * status). Unknown license or dangerous install scripts block S/A ratings; no
 * opaque popularity-only score.
 */
import { assessLicense, assessScripts } from './licenseGate.js'

const WEIGHTS = { license: 25, integrity: 20, scripts: 20, sbom: 15, vulnerabilities: 10, maintenance: 10 }

function evidence(check, status, detail, source, date) {
  return { check, status, detail, source: source ?? 'catalog-metadata', date: date ?? new Date().toISOString().slice(0, 10) }
}

export function rateProject(input = {}) {
  const entries = []
  let score = 0

  const license = assessLicense(input.license)
  if (license.allowed) { score += WEIGHTS.license; entries.push(evidence('license', 'PASS', input.license, input.source, input.date)) }
  else entries.push(evidence('license', 'FAIL', license.code, input.source, input.date))

  if (input.commit && input.digest) { score += WEIGHTS.integrity; entries.push(evidence('commit-digest', 'PASS', `${input.commit} / ${input.digest}`)) }
  else entries.push(evidence('commit-digest', 'FAIL', 'missing commit or digest'))

  const scripts = assessScripts(input.scripts ?? {})
  if (scripts.allowed) { score += WEIGHTS.scripts; entries.push(evidence('install-scripts', 'PASS', 'no install scripts')) }
  else entries.push(evidence('install-scripts', 'FAIL', scripts.reasons.map((reason) => reason.code).join(',')))

  const sbomComponents = Number(input.sbom?.components ?? 0)
  if (sbomComponents > 0) { score += WEIGHTS.sbom; entries.push(evidence('sbom', 'PASS', `${sbomComponents} components`)) }
  else entries.push(evidence('sbom', 'FAIL', 'no SBOM components'))

  if (input.osvKnown === false) { score += WEIGHTS.vulnerabilities; entries.push(evidence('osv-known-vulns', 'PASS', 'no known OSV match')) }
  else if (input.osvKnown === undefined) entries.push(evidence('osv-known-vulns', 'UNKNOWN', 'OSV not checked'))
  else entries.push(evidence('osv-known-vulns', 'FAIL', 'known OSV match'))

  if (input.maintainedDays !== undefined && input.maintainedDays <= 180) { score += WEIGHTS.maintenance; entries.push(evidence('maintenance', 'PASS', `${input.maintainedDays} days since release`)) }
  else if (input.maintainedDays === undefined) entries.push(evidence('maintenance', 'UNKNOWN', 'release date unavailable'))
  else entries.push(evidence('maintenance', 'FAIL', `${input.maintainedDays} days since release`))

  const blocked = !license.allowed || !scripts.allowed
  let grade = blocked ? 'C' : score >= 90 ? 'S' : score >= 75 ? 'A' : score >= 60 ? 'B' : 'C'
  if (!input.commit || !input.digest) grade = 'C'
  return {
    schemaVersion: 'armorbreak.rating/v1',
    grade,
    score,
    blocked,
    licenseStatus: license.code,
    evidence: entries,
    source: input.source ?? 'catalog-metadata',
    date: input.date ?? new Date().toISOString().slice(0, 10),
    automaticDeployment: false,
  }
}
