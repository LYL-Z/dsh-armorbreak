/**
 * AB2-M3-04 PyRIT result adapter (normalized export, no raw prompts).
 *
 * PyRIT is not bundled. Callers provide a normalized result export; outcomes are
 * only PASS/FAIL when an explicit boolean is present, otherwise SKIPPED. Targets
 * must be operator-authorized mock/local endpoints.
 */
import { createHash } from 'node:crypto'
import { validateTarget } from './schema.js'

export const PYRIT_ADAPTER_VERSION = 'armorbreak.pyrit-adapter/v1'

export function planPyrit(input = {}) {
  const targetCheck = validateTarget(input.target)
  if (!targetCheck.valid) throw new Error(`PyRIT target rejected: ${targetCheck.errors.join('; ')}`)
  const objectives = (input.objectives ?? ['prompt-injection-research', 'tool-boundary-research']).map(String)
  return {
    schemaVersion: 'armorbreak.pyrit-plan/v1',
    adapterVersion: PYRIT_ADAPTER_VERSION,
    target: { id: input.target.id, endpoint: input.target.endpoint, operator: input.target.operator, approvalRef: input.target.approvalRef },
    objectives,
    budget: { maxAttempts: Math.max(1, Math.min(Number(input.budget?.maxAttempts ?? 50), 500)) },
    captureRawPrompts: false,
    externalModelCalls: false,
    traceId: input.traceId ?? `pyrit-${createHash('sha256').update(`${input.target.id}|${objectives.join(',')}`).digest('hex').slice(0, 20)}`,
  }
}

export function mapPyritResults(records, plan) {
  const results = []
  for (const record of Array.isArray(records) ? records : []) {
    if (results.length >= plan.budget.maxAttempts) break
    const explicit = record.passed
    const verdict = explicit === true ? 'PASS' : explicit === false ? 'FAIL' : 'SKIPPED'
    const conversationId = String(record.conversation_id ?? record.conversationId ?? 'unknown').slice(0, 100)
    results.push({
      schemaVersion: 'armorbreak.aisec-result/v1',
      traceId: plan.traceId,
      scenarioId: `pyrit:${String(record.objective ?? 'unknown').slice(0, 100)}`,
      targetId: plan.target.id,
      targetEndpoint: plan.target.endpoint,
      judge: { type: 'rule', id: 'pyrit-explicit-outcome', humanReviewRequired: false },
      verdict,
      outputSha256: createHash('sha256').update(JSON.stringify(record.output ?? record.response ?? '')).digest('hex'),
      outputPreview: '[PyRIT raw conversation omitted; hash retained]',
      error: record.error ? String(record.error).slice(0, 300) : null,
      startedAt: record.startedAt ?? null,
      finishedAt: record.finishedAt ?? null,
      evidence: [],
      provenance: { adapter: PYRIT_ADAPTER_VERSION, conversationId },
    })
  }
  return { schemaVersion: 'armorbreak.pyrit-results/v1', traceId: plan.traceId, results, attempts: results.length, budget: plan.budget.maxAttempts }
}
