/**
 * AB2-M4-04 evaluation dashboard aggregation.
 *
 * Works on persisted AISEC results. Model identity is explicit; mock results are
 * marked mock and are never presented as a live model evaluation.
 */
import { createHash } from 'node:crypto'

export function buildEvaluationDashboard(records, options = {}) {
  const items = Array.isArray(records) ? records : []
  const byVerdict = { PASS: 0, FAIL: 0, ERROR: 0, SKIPPED: 0 }
  const categories = {}
  const judgeTypes = {}
  const failed = []
  for (const item of items) {
    if (byVerdict[item.verdict] !== undefined) byVerdict[item.verdict] += 1
    const scenario = String(item.scenarioId ?? 'unknown')
    const category = scenario.split(':')[0] || 'unknown'
    categories[category] = (categories[category] ?? 0) + 1
    const judge = item.judge?.type ?? 'unknown'
    judgeTypes[judge] = (judgeTypes[judge] ?? 0) + 1
    if (item.verdict === 'FAIL' || item.verdict === 'ERROR') failed.push({ traceId: item.traceId, scenarioId: item.scenarioId, verdict: item.verdict, outputSha256: item.outputSha256, error: item.error ?? null })
  }
  return {
    schemaVersion: 'armorbreak.llm-report-dashboard/v1',
    generatedAt: new Date().toISOString(),
    sampleCount: items.length,
    byVerdict,
    categories,
    judgeTypes,
    failed,
    failedEvidence: failed.map((item) => item.outputSha256).filter(Boolean),
    model: { name: options.modelName ?? 'mock', version: options.modelVersion ?? 'local-mock' },
    datasetFingerprint: createHash('sha256').update(JSON.stringify(items.map((item) => item.traceId))).digest('hex'),
    mockModel: true,
    liveModelCall: false,
    cost: { total: 0, currency: 'N/A' },
    notes: ['mock target only; no live model evaluation', 'model judgments without human review are not truth'],
  }
}
