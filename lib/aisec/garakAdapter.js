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
  const entries = parseLines(text)
  const useEval = entries.some((entry) => entry.entry_type === 'eval')
  const results = []
  for (const entry of entries) {
    if (useEval) {
      if (entry.entry_type !== 'eval') continue
      const probe = String(entry.probe ?? '')
      if (!SAFE_PROBES.includes(probe.split('.')[0])) continue
      const passed = entry.passed === true || (Number(entry.passed) > 0 && Number(entry.fails ?? 0) === 0 && Number(entry.total_evaluated ?? entry.passed) > 0)
      results.push({
        schemaVersion: 'armorbreak.aisec-result/v1',
        traceId: plan.traceId,
        scenarioId: `garak:${probe}:${String(entry.detector ?? 'unknown').slice(0, 80)}`,
        targetId,
        targetEndpoint: plan.target.endpoint,
        judge: { type: 'rule', id: 'garak-eval-verdict', humanReviewRequired: false },
        verdict: passed ? 'PASS' : 'FAIL',
        outputSha256: createHash('sha256').update(`${probe}|${entry.detector ?? ''}|${entry.passed}|${entry.total_evaluated ?? ''}`).digest('hex'),
        outputPreview: '[Garak eval summary only]',
        error: null,
        startedAt: null,
        finishedAt: null,
        evidence: [],
        provenance: { adapter: GARAK_ADAPTER_VERSION, probe, detector: entry.detector ?? null, totalEvaluated: entry.total_evaluated ?? null },
      })
      continue
    }
    if (entry.entry_type !== 'attempt') continue
    const attemptProbe = String(entry.probe_classname ?? entry.probe ?? '')
    if (!SAFE_PROBES.includes(attemptProbe.split('.')[0])) continue
    const raw = String(entry.output ?? entry.outputs?.join?.('\n') ?? '')
    const verdict = entry.passed === true ? 'PASS' : entry.passed === false ? 'FAIL' : 'SKIPPED'
    results.push({
      schemaVersion: 'armorbreak.aisec-result/v1',
      traceId: plan.traceId,
      scenarioId: `garak:${attemptProbe}:${String(entry.detector ?? 'unknown').slice(0, 80)}`,
      targetId,
      targetEndpoint: plan.target.endpoint,
      judge: { type: 'rule', id: 'garak-verdict', humanReviewRequired: false },
      verdict,
      outputSha256: createHash('sha256').update(raw).digest('hex'),
      outputPreview: raw ? '[raw Garak output retained only as hash]' : '',
      error: null,
      startedAt: entry.started_at ?? null,
      finishedAt: entry.finished_at ?? null,
      evidence: raw ? [{ kind: 'garak-output-sha256', sha256: createHash('sha256').update(raw).digest('hex') }] : [],
      provenance: { adapter: GARAK_ADAPTER_VERSION, probe: attemptProbe, detector: entry.detector ?? null },
    })
  }
  return results
}

export async function readGarakReport({ reportPath, plan, targetId }) {
  return mapGarakReport({ text: await readFile(reportPath, 'utf8'), plan, targetId })
}
