/** Offline review of caller-supplied claims, never an attack/replay executor. */
import { createHash } from 'node:crypto'
import { canonicalConfig } from './configOverlay.js'
import { correlateEvidenceBundle, EVIDENCE_BUNDLE_SCHEMA } from '../analyzers/security/correlator.js'
const sha = value => createHash('sha256').update(value).digest('hex')
const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/.test(value)
function object(value, allowed) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).some(key => !allowed.includes(key))) throw new Error('invalid assessment record shape')
}
export function reviewAssessment(bytes) {
  if (bytes.length > 1024 * 1024) throw new Error('assessment exceeds 1 MiB')
  const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  canonicalConfig(input)
  object(input, ['schema', 'artifactSha256', 'evidence', 'findings'])
  if (input.schema !== 'armorbreak.assessment-review-input/v1' || !/^[a-f0-9]{64}$/.test(input.artifactSha256 ?? '') || !Array.isArray(input.evidence) || input.evidence.length > 200 || !Array.isArray(input.findings) || input.findings.length > 200) throw new Error('invalid bounded assessment input')
  const records = new Map()
  for (const record of input.evidence) {
    object(record, ['id', 'confidence', 'authority', 'content', 'sha256', 'supportingIds'])
    if (!id(record.id) || records.has(record.id) || !['claimed', 'observed', 'derived', 'inferred'].includes(record.confidence) || !['tool-output', 'database-record', 'screenshot', 'operator-input', 'subagent-report'].includes(record.authority) || typeof record.content !== 'string' || Buffer.byteLength(record.content) > 8192 || !Array.isArray(record.supportingIds) || record.supportingIds.length > 32 || new Set(record.supportingIds).size !== record.supportingIds.length || record.supportingIds.some(value => !id(value))) throw new Error('invalid or duplicate assessment evidence')
    if (sha(record.content) !== record.sha256) throw new Error('assessment evidence content hash mismatch')
    records.set(record.id, record)
  }
  const active = new Set(), visited = new Set()
  const visit = key => {
    if (!records.has(key)) throw new Error('assessment evidence reference missing')
    if (active.has(key)) throw new Error('assessment evidence cycle')
    if (visited.has(key)) return
    active.add(key); for (const next of records.get(key).supportingIds) visit(next)
    active.delete(key); visited.add(key)
  }
  for (const key of records.keys()) visit(key)
  const findingIds = new Set()
  const findings = input.findings.map(finding => {
    object(finding, ['id', 'ruleId', 'severity', 'evidenceIds'])
    if (!id(finding.id) || findingIds.has(finding.id) || !id(finding.ruleId) || !['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity) || !Array.isArray(finding.evidenceIds) || !finding.evidenceIds.length || finding.evidenceIds.length > 32 || new Set(finding.evidenceIds).size !== finding.evidenceIds.length || finding.evidenceIds.some(key => !records.has(key))) throw new Error('invalid finding or missing evidence reference')
    findingIds.add(finding.id)
    // Caller labels/commands/targets are not an authorization or verified fact.
    return { id: `finding-${sha(finding.id).slice(0, 16)}`, ruleId: `rule-${sha(finding.ruleId).slice(0, 16)}`,
      severity: finding.severity, title: 'Imported assessment claim; independent verification required',
      evidenceContext: finding.evidenceIds.map(key => records.get(key).sha256).sort().join(','),
      verification: 'unverified', vulnerabilityStatus: 'not_tested', artifactHash: input.artifactSha256 }
  })
  const correlation = correlateEvidenceBundle(Buffer.from(JSON.stringify({ schema: EVIDENCE_BUNDLE_SCHEMA, artifact: { sha256: input.artifactSha256 }, sources: [{ id: 'offline-assessment', kind: 'armorbreak', sourceFamily: 'untrusted-import', findings }] })))
  const data = { schema: 'armorbreak.assessment-review/v1', inputSha256: sha(bytes), artifactSha256: input.artifactSha256,
    mode: 'OFFLINE_DATA_REVIEW', evidence: [...records.values()].map(record => ({ idDigest: sha(record.id), contentSha256: record.sha256,
      sourceDeclaredConfidence: record.confidence, sourceDeclaredAuthority: record.authority,
      verification: 'UNVERIFIED_INPUT', supportingIdDigests: record.supportingIds.map(sha) })),
    findingCount: findings.length, correlation: correlation.data, networkAccess: 'none', executionAllowed: false,
    vulnerabilityStatus: 'not_tested', rightsState: 'NOT_IMPORTED',
    limitations: ['Content hashes bind supplied bytes only; no tool output, screenshot, source authority, assessment authorization or vulnerability claim is independently verified.', 'No HTTP replay, synthesized command, scan, credential operation or upstream SQLite/code import is performed.'] }
  return { ...correlation, summary: `Offline assessment review: ${records.size} unverified evidence records, ${findings.length} claims`, data,
    evidence: [{ kind: 'assessment-review', title: 'Offline claim integrity review', excerpt: `inputSha256=${data.inputSha256}; evidence=${records.size}; claims=${findings.length}; all claims unverified` }],
    artifacts: [...correlation.artifacts, { name: 'assessment-review.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
}
