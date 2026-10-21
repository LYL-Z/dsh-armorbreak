/**
 * AB2-M3-01 AISEC contracts.
 *
 * Scenario/Target/Judge/Result share one traceId. A target must be explicitly
 * operator-authorized; model-supplied claims of authorization are ignored.
 * Endpoints are mock/local only in this module; no external requests are made.
 */
import { createHash, randomUUID } from 'node:crypto'

export const AISEC_SCHEMA = 'armorbreak.aisec/v1'

export function traceId(seed) {
  return `trace-${createHash('sha256').update(`${seed ?? ''}|${randomUUID()}`).digest('hex').slice(0, 24)}`
}

export function validateScenario(input) {
  const errors = []
  if (!input || typeof input !== 'object') return { valid: false, errors: ['scenario must be an object'] }
  for (const key of ['id', 'title', 'category', 'targetId']) if (!String(input[key] ?? '').trim()) errors.push(`${key} required`)
  if (!['prompt-injection', 'tool-abuse', 'data-exfiltration', 'memory-poisoning', 'multimodal', 'jailbreak-research'].includes(input.category)) errors.push('category not allowed')
  if (input.authorizationRequired !== true) errors.push('authorizationRequired must be true')
  return { valid: errors.length === 0, errors }
}

export function validateTarget(input) {
  const errors = []
  if (!input || typeof input !== 'object') return { valid: false, errors: ['target must be an object'] }
  for (const key of ['id', 'operator']) if (!String(input[key] ?? '').trim()) errors.push(`${key} required`)
  const endpoint = String(input.endpoint ?? '')
  if (!endpoint.startsWith('mock://') && !endpoint.startsWith('local://')) errors.push('M3-01 only allows mock:// or local:// endpoints')
  if (input.authorized !== true) errors.push('target is not operator-authorized')
  if (!String(input.approvalRef ?? '').trim()) errors.push('approvalRef required')
  if (input.approvedByModel === true) errors.push('model-supplied authorization is not accepted')
  return { valid: errors.length === 0, errors }
}

export function validateJudge(input) {
  const errors = []
  if (!input || typeof input !== 'object') return { valid: false, errors: ['judge must be an object'] }
  if (!['rule', 'human', 'model-assisted'].includes(input.type)) errors.push('judge type must be rule/human/model-assisted')
  if (input.type === 'model-assisted' && input.humanReviewRequired !== true) errors.push('model-assisted judge needs humanReviewRequired=true')
  return { valid: errors.length === 0, errors }
}

export function validateResult(input) {
  const errors = []
  if (!input || typeof input !== 'object') return { valid: false, errors: ['result must be an object'] }
  for (const key of ['traceId', 'scenarioId', 'targetId', 'verdict']) if (!String(input[key] ?? '').trim()) errors.push(`${key} required`)
  if (!['PASS', 'FAIL', 'ERROR', 'SKIPPED'].includes(input.verdict)) errors.push('verdict not allowed')
  return { valid: errors.length === 0, errors }
}
