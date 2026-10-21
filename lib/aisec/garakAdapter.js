/**
 * AB2-M3-03 Garak report adapter.
 *
 * This is an adapter/planner, not a claim that Garak is installed. It accepts a
 * fixed probe allowlist, requires an operator-authorized mock/local target, and
 * maps Garak attempt records to armorbreak.aisec results without retaining raw
 * harmful payloads.
 */
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { validateTarget } from './schema.js'

export const GARAK_ADAPTER_VERSION = 'armorbreak.garak-adapter/v1'
export const GARAK_VERSION = '0.17.1'
export const SAFE_PROBES = Object.freeze(['promptinject', 'encoding', 'xss', 'continuation'])

export function planGarak(input) {
  const target = input.target
  const targetCheck = validateTarget(target)
  if (!targetCheck.valid) throw new Error(`Garak target rejected: ${targetCheck.errors.join('; ')}`)
  const probes = (input.probes ?? ['promptinject', 'encoding']).map(String)
  const unsupported = probes.filter((probe) => !SAFE_PROBES.includes(probe))
  if (unsupported.length > 0) throw new Error(`Garak probes not allowlisted: ${unsupported.join(',')}`)
  return {
    schemaVersion: 'armorbreak.garak-plan/v1',
    adapterVersion: GARAK_ADAPTER_VERSION,
    target: { id: target.id, endpoint: target.endpoint, operator: target.operator, approvalRef: target.approvalRef },
    probes,
    captureRawPayloads: false,
    externalModelCalls: false,
    traceId: input.traceId ?? `garak-${createHash('sha256').update(`${target.id}|${probes.join(',')}`).digest('hex').slice(0, 20)}`,
  }
}

function parseLines(text) {
  return text.split(/\r?\n/).filter(Boolean).map((line) => { try { return JSON.parse(line) } catch { return null } }).filter(Boolean)
}

export function mapGarakReport({ text, plan, targetId }) {
  const results = []
  for (const entry of parseLines(text)) {
    if (entry.entry_type !== 'attempt') continue
    if (!SAFE_PROBES.includes(String(entry.probe))) continue
    const raw = String(entry.output ?? entry.outputs?.join?.('\n') ?? '')
    const verdict = entry.passed === true ? 'PASS' : entry.passed === false ? 'FAIL' : 'SKIPPED'
    results.push({
      schemaVersion: 'armorbreak.aisec-result/v1',
      traceId: plan.traceId,
      scenarioId: `garak:${entry.probe}:${String(entry.detector ?? 'unknown').slice(0, 80)}`,
      targetId,
      targetEndpoint: plan.target.endpoint,
      judge: { type: 'rule', id: 'garak-verdict', humanReviewRequired: false },
      verdict,
      outputSha256: createHash('sha256').update(raw).digest('hex'),
      outputPreview: raw ? '[raw Garak output retained only as hash]' : '',
      error: null,
      startedAt: entry.started_at ?? plan.traceId,
      finishedAt: entry.finished_at ?? new Date().toISOString(),
      evidence: raw ? [{ kind: 'garak-output-sha256', sha256: createHash('sha256').update(raw).digest('hex') }] : [],
      provenance: { adapter: GARAK_ADAPTER_VERSION, probe: entry.probe, detector: entry.detector ?? null },
    })
  }
  return results
}

export async function readGarakReport({ reportPath, plan, targetId }) {
  return mapGarakReport({ text: await readFile(reportPath, 'utf8'), plan, targetId })
}
