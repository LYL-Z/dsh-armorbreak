/**
 * AB2-M2-10 License/SBOM/supply-chain gate.
 * Unknown licenses and dangerous install scripts fail closed. This is a policy
 * decision function only; it does not install or execute anything.
 */
export const ALLOWED_LICENSES = Object.freeze(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD'])
export const COPYLEFT_LICENSES = Object.freeze(['GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0'])

const DANGEROUS_SCRIPT = /(curl|wget|powershell|cmd(?:\.exe)?\s+\/c|node\s+-e|base64\s+-d|Invoke-WebRequest|Start-Process|chmod\s+\+x)/i

export function assessLicense(license) {
  const value = String(license ?? '').trim()
  if (!value) return { allowed: false, code: 'UNKNOWN_LICENSE', reason: 'license is missing; automatic assembly denied' }
  if (COPYLEFT_LICENSES.some((item) => value.toUpperCase().startsWith(item.toUpperCase()))) return { allowed: false, code: 'COPYLEFT_DENIED', reason: `copyleft license requires explicit review: ${value}` }
  if (!ALLOWED_LICENSES.includes(value)) return { allowed: false, code: 'UNKNOWN_LICENSE', reason: `license not on allowlist: ${value}` }
  return { allowed: true, code: 'LICENSE_OK', reason: value }
}

export function assessScripts(scripts = {}) {
  const reasons = []
  for (const [name, body] of Object.entries(scripts ?? {})) {
    if (!['preinstall', 'install', 'postinstall', 'prepare'].includes(name)) continue
    if (!body) continue
    if (DANGEROUS_SCRIPT.test(String(body))) reasons.push({ code: 'DANGEROUS_SCRIPT', name, value: String(body).slice(0, 300) })
    else reasons.push({ code: 'INSTALL_SCRIPT_REQUIRES_REVIEW', name, value: String(body).slice(0, 300) })
  }
  return { allowed: reasons.length === 0, reasons }
}

export function assessComponent(component, options = {}) {
  const license = assessLicense(component?.license)
  const scripts = assessScripts(component?.scripts)
  const reasons = []
  if (!license.allowed) reasons.push({ code: license.code, detail: license.reason })
  reasons.push(...scripts.reasons)
  if (!component?.commit) reasons.push({ code: 'MISSING_COMMIT', detail: 'immutable commit is required' })
  if (!component?.digest) reasons.push({ code: 'MISSING_DIGEST', detail: 'artifact digest is required' })
  if (component?.nodeGyp === true) reasons.push({ code: 'NATIVE_BUILD_DENIED', detail: 'node-gyp/native build requires sandboxed review' })
  if (component?.osv?.known === true) reasons.push({ code: 'KNOWN_VULNERABILITY', detail: String(component.osv.summary ?? 'OSV reports known vulnerability').slice(0, 200) })
  if (options.requireScorecard === true && !component?.scorecard) reasons.push({ code: 'SCORECARD_MISSING', detail: 'OpenSSF Scorecard required for automatic assembly' })
  if (component?.scorecard && Number(component.scorecard.score) < 5) reasons.push({ code: 'LOW_SCORECARD', detail: 'OpenSSF Scorecard below 5' })
  return {
    schemaVersion: 'armorbreak.supplychain/v1',
    component: { name: String(component?.name ?? '').slice(0, 200), version: String(component?.version ?? '').slice(0, 100) },
    allowed: reasons.length === 0,
    license: license.code,
    reasons,
    sbom: { components: Array.isArray(component?.sbom?.components) ? component.sbom.components.length : 0 },
    executable: false,
  }
}

export function assessPlan(plan) {
  const components = (plan?.components ?? []).map((component) => assessComponent(component, { requireScorecard: plan?.requireScorecard === true }))
  const denied = components.filter((item) => !item.allowed)
  return {
    schemaVersion: 'armorbreak.supplychain-plan/v1',
    allowed: denied.length === 0 && components.length > 0,
    components,
    denied: denied.length,
    reasons: denied.flatMap((item) => item.reasons),
    automatic: false,
  }
}
