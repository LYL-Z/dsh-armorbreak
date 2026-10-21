/** P1 evidence/event envelope helpers. Raw secrets are never copied into envelopes. */
import { createHash } from 'node:crypto'
import { validateEvidenceEnvelope, validateInvocation } from '../protocol/index.js'

const SENSITIVE = /token|secret|password|passwd|api[_-]?key|private[_-]?key|authorization|cookie|credential|session[_-]?id/i
const MAX_PAYLOAD = 64 * 1024

function sanitize(value, depth = 0) {
  if (depth > 12) throw new Error('evidence payload is too deeply nested')
  if (value === null || value === undefined) return value
  if (typeof value === 'string') return value.length > 8192 ? `${value.slice(0, 8192)}…` : value
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (Array.isArray(value)) return value.slice(0, 500).map((item) => sanitize(item, depth + 1))
  if (typeof value === 'object') {
    const out = {}
    for (const [key, child] of Object.entries(value).slice(0, 500)) {
      out[key] = SENSITIVE.test(key) ? '[REDACTED]' : sanitize(child, depth + 1)
    }
    return out
  }
  return String(value)
}

export function sanitizeEvidencePayload(payload) {
  const safe = sanitize(payload ?? {})
  const text = JSON.stringify(safe)
  if (text.length > MAX_PAYLOAD) throw new Error(`evidence payload exceeds ${MAX_PAYLOAD} bytes after sanitization`)
  return { safe, sha256: createHash('sha256').update(text).digest('hex') }
}

export function createEvidenceEnvelope({ ctx, taskId, origin = 'sdk', targetHash, payload = {}, runId } = {}) {
  const invocation = validateInvocation(ctx)
  if (!invocation.ok) throw new Error(`invalid invocation: ${invocation.issues.join('; ')}`)
  if (!taskId || typeof taskId !== 'string') throw new Error('taskId is required')
  if (!/^[a-f0-9]{64}$/.test(String(targetHash ?? ''))) throw new Error('targetHash must be lowercase sha256')
  const sanitized = sanitizeEvidencePayload(payload)
  const envelope = {
    traceId: ctx.traceId,
    runId: runId ?? ctx.requestId,
    taskId,
    principalId: ctx.principal.id,
    origin,
    targetHash,
    payloadSha256: sanitized.sha256,
    payload: sanitized.safe,
    createdAt: new Date().toISOString(),
  }
  const checked = validateEvidenceEnvelope(envelope)
  if (!checked.ok) throw new Error(`invalid evidence envelope: ${checked.issues.join('; ')}`)
  return envelope
}

export function createEventEnvelope({ ctx, taskId, origin = 'sdk', targetHash, event, payload = {}, runId } = {}) {
  if (!event || typeof event !== 'string') throw new Error('event is required')
  const envelope = createEvidenceEnvelope({ ctx, taskId, origin, targetHash, payload, runId })
  return { ...envelope, type: 'event', event: event.slice(0, 200) }
}
