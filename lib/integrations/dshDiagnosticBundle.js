/** Composite read-only workflow; all input bytes come from the Core reader. */
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { canonicalConfig, resolveConfig } from './configOverlay.js'
import { maintenancePath } from '../../packages/installer/maintenancePlan.js'
import { inspectDshHostHealth } from './dshHostHealth.js'
import { inspectDshHostProfile } from './dshHostInspector.js'
import { diagnoseDshAnchors } from './dshAnchorDiagnostic.js'
import { verifyPluginPackage } from '../catalog/pluginPackage.js'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')

export async function diagnoseHostBundle(input) {
  if (!input.env?.readFile) throw new Error('Core directory reader required')
  const path = relative => join(input.targetPath, ...maintenancePath(relative))
  const readJson = async relative => {
    const bytes = await input.env.readFile(path(relative), 1024 * 1024 + 1)
    if (bytes.length > 1024 * 1024 || input.env.targetTruncated) throw new Error('complete bounded diagnostic JSON required')
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  }
  let request
  try { request = await readJson('armorbreak-host-diagnostics.json') } catch (error) { throw new Error(`diagnostic request unavailable or invalid: ${error.code ?? 'INVALID_JSON'}`) }
  canonicalConfig(request)
  if (!request || Array.isArray(request) || request.schema !== 'armorbreak.host-diagnostics-request/v1' || Object.keys(request).some(key => !['schema', 'resources', 'expectedVersion', 'profile', 'anchors', 'configurationBundle', 'pluginRoot'].includes(key)) || typeof request.resources !== 'string') throw new Error('invalid host diagnostic request')
  const health = await inspectDshHostHealth({ resources: path(request.resources), readFile: input.env.readFile, expectedVersion: request.expectedVersion })
  let profile = { status: 'NOT_REQUESTED' }, anchors = { status: 'NOT_REQUESTED' }, configuration = { status: 'NOT_REQUESTED' }, plugins = { status: 'NOT_REQUESTED' }
  if (request.profile !== undefined) {
    const inspected = await inspectDshHostProfile({ home: input.targetPath, profile: request.profile, readFile: input.env.readFile })
    const { target, ...safe } = inspected
    profile = safe
  }
  if (request.anchors !== undefined) {
    const spec = request.anchors
    if (!spec || Array.isArray(spec) || typeof spec !== 'object' || Object.keys(spec).some(key => !['target', 'spec'].includes(key))) throw new Error('invalid anchor request')
    const { targetFile, ...safe } = await diagnoseDshAnchors({ targetFile: path(spec.target), specFile: path(spec.spec), readFile: input.env.readFile })
    anchors = safe
  }
  if (request.configurationBundle !== undefined) configuration = resolveConfig(await readJson(request.configurationBundle)).preview
  if (request.pluginRoot !== undefined) plugins = await verifyPluginPackage({ ...input, targetPath: path(request.pluginRoot) })
  const issues = []
  if (health.observation !== 'DETECTED_ON_DISK') issues.push({ code: 'DISK_IDENTITY_UNKNOWN', recovery: 'Select one explicit supported Resources directory; no process or runtime state is inferred.' })
  if (health.compatibility.versionRequirement === 'MISMATCH') issues.push({ code: 'VERSION_REQUIREMENT_MISMATCH', recovery: 'Review the expected disk version; do not patch automatically.' })
  if (profile.status === 'INCOMPLETE') issues.push({ code: 'PROFILE_INCOMPLETE', recovery: 'Review missing or malformed profile files without exposing secret configuration.' })
  if (anchors.status === 'REVIEW_REQUIRED') issues.push({ code: 'ANCHOR_DRIFT', recovery: 'Inspect the pinned anchor specification and host version before any separate maintenance decision.' })
  if (configuration.status === 'CONFLICT') issues.push({ code: 'CONFIGURATION_CONFLICT', recovery: 'Resolve explicit data layers in a preview; do not overwrite host configuration.' })
  if (plugins.plugins?.some(p => !p.riskClassificationEligible)) issues.push({ code: 'PLUGIN_RISK_DENIED', recovery: 'Retain disallowed implementations outside the execution surface.' })
  if (plugins.plugins?.some(p => !p.sourceAuthenticated || !p.rightsVerified)) issues.push({ code: 'PLUGIN_TRUST_UNVERIFIED', recovery: 'Listed-file integrity and license claims do not authorize installation, activation or redistribution.' })
  return { schema: 'armorbreak.host-diagnostics/v1', requestSha256: hash(canonicalConfig(request)), mode: 'READ_ONLY',
    status: issues.length ? 'REVIEW_REQUIRED' : 'DISK_DIAGNOSTICS_COMPLETE', health, profile, anchors, configuration, plugins, issues,
    process: 'UNKNOWN', runtime: 'UNKNOWN', feature: 'UNKNOWN', realHostVerified: false, hostModified: false,
    limitations: ['Disk and textual metadata only. No running instance, loaded plugin, model delivery, active probe or real host compatibility is verified.'] }
}
