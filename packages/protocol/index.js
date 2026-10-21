/**
 * @armorbreak/protocol v1
 *
 * Stable code-first contracts for host adapters. The JSON Schema files are the
 * wire authority; this module supplies the error vocabulary and a dependency-free
 * envelope validator so Core can reject malformed host input before policy work.
 */
export const PROTOCOL_VERSION = '1.0.0'

export const ERROR_CODES = Object.freeze({
  INVALID_REQUEST: 'INVALID_REQUEST',
  UNKNOWN_CAPABILITY: 'UNKNOWN_CAPABILITY',
  POLICY_DENIED: 'POLICY_DENIED',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  TARGET_OUT_OF_SCOPE: 'TARGET_OUT_OF_SCOPE',
  CANCELLED: 'CANCELLED',
  TIMEOUT: 'TIMEOUT',
  ENGINE_UNAVAILABLE: 'ENGINE_UNAVAILABLE',
  EVIDENCE_MISMATCH: 'EVIDENCE_MISMATCH',
})

export const INVOCATION_SCHEMA = Object.freeze({
  type: 'object',
  required: ['principal', 'workspaceId', 'requestId', 'traceId'],
  properties: {
    principal: { type: 'object', required: ['id', 'kind'] },
    workspaceId: { type: 'string', minLength: 1 },
    requestId: { type: 'string', minLength: 1 },
    traceId: { type: 'string', minLength: 1 },
    connectionId: { type: 'string' },
  },
  additionalProperties: false,
})

export const EVIDENCE_ENVELOPE_SCHEMA = Object.freeze({
  type: 'object',
  required: ['traceId', 'runId', 'taskId', 'principalId', 'origin', 'targetHash'],
  properties: {
    traceId: { type: 'string', minLength: 1 },
    runId: { type: 'string', minLength: 1 },
    taskId: { type: 'string', minLength: 1 },
    principalId: { type: 'string', minLength: 1 },
    origin: { type: 'string', enum: ['dsh', 'mcp', 'cli', 'sdk'] },
    targetHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
  },
  additionalProperties: true,
})

function required(value, keys) {
  return keys.every((key) => value && typeof value[key] === 'string' && value[key].length > 0)
}

/** Validate an invocation envelope without pulling in a schema library. */
export function validateInvocation(value) {
  const issues = []
  if (!value || typeof value !== 'object') return { ok: false, issues: ['invocation must be an object'] }
  if (!value.principal || typeof value.principal !== 'object') issues.push('principal is required')
  else if (!required(value.principal, ['id', 'kind'])) issues.push('principal.id and principal.kind are required')
  for (const key of ['workspaceId', 'requestId', 'traceId']) if (!required(value, [key])) issues.push(`${key} is required`)
  return { ok: issues.length === 0, issues }
}

export function validateEvidenceEnvelope(value) {
  const issues = []
  if (!value || typeof value !== 'object') return { ok: false, issues: ['evidence envelope must be an object'] }
  for (const key of EVIDENCE_ENVELOPE_SCHEMA.required) if (!required(value, [key])) issues.push(`${key} is required`)
  if (value.origin && !EVIDENCE_ENVELOPE_SCHEMA.properties.origin.enum.includes(value.origin)) issues.push('origin is not allowed')
  if (value.targetHash && !/^[a-f0-9]{64}$/.test(value.targetHash)) issues.push('targetHash must be lowercase sha256')
  return { ok: issues.length === 0, issues }
}
