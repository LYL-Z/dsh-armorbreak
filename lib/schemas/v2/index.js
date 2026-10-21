/**
 * ArmorBreak V2 schema contracts (AB2-M1-07).
 *
 * The validators are intentionally dependency-free and conservative: they add a
 * schemaVersion to new writes while allowing old v1 tasks to be read and
 * displayed. They do not silently reinterpret old authorization records.
 */
export const SCHEMA_VERSION = 'armorbreak/v2'

export const TASK_STATES = Object.freeze([
  'PENDING', 'PLANNING', 'APPROVAL_REQUIRED', 'EXECUTING', 'COLLECTING_EVIDENCE',
  'VERIFYING', 'REPORTING', 'COMPLETED', 'PARTIAL_SUCCESS', 'FAILED', 'REJECTED',
  'CANCELLED', 'TIMED_OUT', 'WAITING', 'PAUSED', 'INTERRUPTED', 'RECOVERABLE',
])

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireString(errors, value, field) {
  if (typeof value !== 'string' || value.trim() === '') errors.push(`${field} must be a non-empty string`)
}

/** @param {any} capability */
export function toCapabilityV2(capability) {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: String(capability.id ?? ''),
    domain: String(capability.domain ?? ''),
    title: String(capability.title ?? ''),
    description: String(capability.description ?? ''),
    riskLevel: capability.riskLevel ?? 'L0',
    targetKind: capability.targetKind ?? 'file',
    permissions: permissionsForRisk(capability.riskLevel ?? 'L0'),
    externalTools: Array.isArray(capability.externalTools) ? capability.externalTools.slice(0, 20) : [],
  }
}

export function permissionsForRisk(riskLevel) {
  if (riskLevel === 'L0') return ['READ', 'ANALYZE']
  if (riskLevel === 'L1') return ['READ', 'ANALYZE', 'EXECUTE_ISOLATED']
  if (riskLevel === 'L2') return ['READ', 'ANALYZE', 'NETWORK_L2']
  return []
}

/** @param {any} task @param {{allowV1?: boolean}} [options] */
export function validateTaskV2(task, options = {}) {
  const errors = []
  if (!isObject(task)) return { valid: false, errors: ['task must be an object'] }
  if (!options.allowV1 && task.schemaVersion !== SCHEMA_VERSION) errors.push(`schemaVersion must be ${SCHEMA_VERSION}`)
  requireString(errors, task.id, 'id')
  requireString(errors, task.title, 'title')
  requireString(errors, task.state, 'state')
  if (!Array.isArray(task.steps)) errors.push('steps must be an array')
  if (task.state && !TASK_STATES.includes(task.state)) errors.push(`unknown task state: ${task.state}`)
  for (const [index, step] of (task.steps ?? []).entries()) {
    if (!isObject(step)) { errors.push(`steps[${index}] must be an object`); continue }
    requireString(errors, step.id, `steps[${index}].id`)
    requireString(errors, step.capabilityId, `steps[${index}].capabilityId`)
  }
  return { valid: errors.length === 0, errors }
}

/** @param {any} task */
export function toTaskV2(task) {
  const migrated = {
    ...task,
    schemaVersion: SCHEMA_VERSION,
    steps: Array.isArray(task.steps) ? task.steps.map((step) => ({ ...step })) : [],
    approvals: Array.isArray(task.approvals) ? [...task.approvals] : [],
    stats: isObject(task.stats) ? { ...task.stats } : { evidence: 0, findings: 0 },
  }
  const check = validateTaskV2(migrated)
  if (!check.valid) throw new Error(`cannot write task v2: ${check.errors.join('; ')}`)
  return migrated
}

/** @param {any} finding */
export function toFindingV2(finding) {
  const result = {
    schemaVersion: SCHEMA_VERSION,
    id: String(finding.id ?? ''),
    title: String(finding.title ?? ''),
    severity: String(finding.severity ?? 'info'),
    description: String(finding.description ?? ''),
    verification: String(finding.verification ?? 'hypothesis'),
    evidence: Array.isArray(finding.evidence) ? finding.evidence : [],
    ...finding,
  }
  result.schemaVersion = SCHEMA_VERSION
  return result
}

/** @param {any} evidence */
export function toEvidenceV2(evidence) {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: String(evidence.id ?? ''),
    title: String(evidence.title ?? ''),
    kind: String(evidence.kind ?? 'artifact'),
    excerpt: String(evidence.excerpt ?? '').slice(0, 4000),
    sha256: evidence.sha256 ?? null,
    ...evidence,
    schemaVersion: SCHEMA_VERSION,
  }
}

/** @param {any} artifact */
export function toArtifactV2(artifact) {
  return {
    schemaVersion: SCHEMA_VERSION,
    path: String(artifact.path ?? ''),
    sha256: artifact.sha256 ?? null,
    bytes: Number(artifact.bytes ?? 0) || 0,
    ...artifact,
    schemaVersion: SCHEMA_VERSION,
  }
}

export function validateCapabilityV2(capability) {
  const errors = []
  if (!isObject(capability)) return { valid: false, errors: ['capability must be an object'] }
  if (capability.schemaVersion !== SCHEMA_VERSION) errors.push('schemaVersion mismatch')
  requireString(errors, capability.id, 'id')
  requireString(errors, capability.domain, 'domain')
  requireString(errors, capability.title, 'title')
  if (!['L0', 'L1', 'L2', 'L3'].includes(capability.riskLevel)) errors.push('invalid riskLevel')
  if (!Array.isArray(capability.permissions)) errors.push('permissions must be an array')
  return { valid: errors.length === 0, errors }
}
