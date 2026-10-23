/**
 * Evidence and finding store for one task.
 * Every evidence record carries the SHA-256 of the analyzed bytes, a redacted
 * excerpt, and a per-task hash chain so silent edits are detectable.
 * @module dsh-armorbreak/lib/core/evidence
 */
import { appendJsonl, chainHash, newId, nowIso, readJson, readJsonl, redactDeep, redactText, sanitizeText, sha256, withFileMutex, writeJsonAtomic } from './util.js'
import { withAppendFileLock } from './append-lock.js'

/**
 * @typedef {'critical'|'high'|'medium'|'low'|'info'} Severity
 * @typedef {'observed'|'corroborated'|'hypothesis'|'unverified'} Verification
 */

export const SEVERITIES = /** @type {const} */ (['critical', 'high', 'medium', 'low', 'info'])
export const VERIFICATIONS = /** @type {const} */ (['observed', 'corroborated', 'hypothesis', 'unverified'])

/** CVSS-ish severity when the analyzer only gives a severity label. */
export const SEVERITY_SCORE = { critical: 9.5, high: 8.0, medium: 5.5, low: 2.5, info: 0.0 }

/**
 * @param {unknown} value
 * @param {readonly string[]} allowed
 * @param {string} fallback
 */
function oneOf(value, allowed, fallback) {
  return typeof value === 'string' && allowed.includes(value) ? value : fallback
}

export class EvidenceStore {
  /**
   * @param {{taskDir: string, audit?: import('./audit.js').AuditLog, taskId: string}} options
   */
  constructor(options) {
    this.taskDir = options.taskDir
    this.taskId = options.taskId
    this.audit = options.audit
    this.evidenceFile = `${options.taskDir}/evidence.jsonl`
    this.findingsFile = `${options.taskDir}/findings.json`
  }

  /** @returns {Promise<{headHash: string, count: number}>} */
  async tail() {
    const records = await readJsonl(this.evidenceFile, { limit: 1 })
    const last = records[records.length - 1]
    return { headHash: last?.hash ?? 'genesis', count: last?.index ?? 0 }
  }

  /**
   * Persist one evidence record.
   * @param {{title: string, kind?: string, excerpt?: string, meta?: Record<string, unknown>, capabilityId?: string, targetPath?: string|null, targetSha256?: string|null}} input
   */
  async addEvidence(input) {
    return withAppendFileLock(this.evidenceFile, async () => {
      const { headHash, count } = await this.tail()
      const body = {
        schemaVersion: 'armorbreak/v2',
        id: newId('ev'),
        taskId: this.taskId,
        index: count + 1,
        at: nowIso(),
        capabilityId: input.capabilityId ?? null,
        title: sanitizeText(input.title ?? 'evidence', 300),
        kind: sanitizeText(input.kind ?? 'observation', 60),
        excerpt: redactText(sanitizeText(input.excerpt ?? '', 2000)),
        targetPath: input.targetPath ?? null,
        targetSha256: input.targetSha256 ?? null,
        meta: redactDeep(input.meta ?? {}),
      }
      const hash = chainHash(headHash, body)
      const record = { ...body, prevHash: headHash, hash }
      await appendJsonl(this.evidenceFile, record)
      await this.audit?.append({ action: 'evidence.add', taskId: this.taskId, evidenceId: record.id, title: record.title, target: record.targetPath })
      return record
    })
  }

  /** @returns {Promise<any[]>} */
  async readEvidence(limit = 500) {
    return readJsonl(this.evidenceFile, { limit })
  }

  /** @returns {Promise<{findings: any[]}>} */
  async readFindings() {
    const state = await readJson(this.findingsFile, { findings: [] })
    return { findings: Array.isArray(state.findings) ? state.findings : [] }
  }

  /**
   * Merge one analyzer finding with provenance evidence ids.
   * @param {any} raw
   * @param {{evidenceIds?: string[], capabilityId?: string, targetPath?: string|null}} context
   */
  async addFinding(raw, context = {}) {
    return withFileMutex(this.findingsFile, async () => {
      const store = await this.readFindings()
    const severity = oneOf(raw.severity, SEVERITIES, 'info')
    const verification = oneOf(raw.verification, VERIFICATIONS, 'unverified')
    const title = sanitizeText(raw.title ?? 'untitled finding', 300)
    const target = sanitizeText(raw.target ?? context.targetPath ?? '', 500)
    const cwe = typeof raw.cwe === 'string' && /^CWE-\d+$/i.test(raw.cwe) ? raw.cwe.toUpperCase() : null
    const fingerprint = sha256(`${title}|${target}|${cwe ?? ''}|${severity}`)
    const existing = store.findings.find((item) => item.fingerprint === fingerprint)
    if (existing) {
      existing.occurrences = (existing.occurrences ?? 1) + 1
      existing.evidenceIds = unique([...(existing.evidenceIds ?? []), ...(context.evidenceIds ?? [])])
      existing.updatedAt = nowIso()
      await writeJsonAtomic(this.findingsFile, { version: 1, taskId: this.taskId, findings: store.findings })
      return { finding: existing, merged: true }
    }
    const finding = {
      schemaVersion: 'armorbreak/v2',
      id: newId('fnd'),
      taskId: this.taskId,
      fingerprint,
      title,
      severity,
      severityScore: typeof raw.cvss === 'number' && raw.cvss >= 0 && raw.cvss <= 10 ? raw.cvss : SEVERITY_SCORE[severity],
      cvss: typeof raw.cvss === 'number' && raw.cvss >= 0 && raw.cvss <= 10 ? raw.cvss : null,
      cwe,
      verification,
      method: sanitizeText(raw.method ?? context.capabilityId ?? 'static-analysis', 500),
      description: redactText(sanitizeText(raw.description ?? '', 4000)),
      remediation: redactText(sanitizeText(raw.remediation ?? '', 2000)),
      target,
      evidenceIds: unique(context.evidenceIds ?? []),
      capabilityId: context.capabilityId ?? null,
      occurrences: 1,
      createdAt: nowIso(),
      updatedAt: nowIso(),
    }
    store.findings.push(finding)
    await writeJsonAtomic(this.findingsFile, { version: 1, taskId: this.taskId, findings: store.findings })
    await this.audit?.append({ action: 'finding.record', taskId: this.taskId, findingId: finding.id, severity, verification, title })
    return { finding, merged: false }
    })
  }

  /**
   * Update verification status (human/model judgement after corroboration).
   * @param {string} findingId
   * @param {{verification?: Verification, note?: string, severity?: Severity}} patch
   */
  async verifyFinding(findingId, patch) {
    return withFileMutex(this.findingsFile, async () => {
      const store = await this.readFindings()
    const finding = store.findings.find((item) => item.id === findingId)
    if (!finding) throw new Error(`finding not found: ${findingId}`)
    if (patch.verification) finding.verification = oneOf(patch.verification, VERIFICATIONS, finding.verification)
    if (patch.severity) finding.severity = oneOf(patch.severity, SEVERITIES, finding.severity)
    if (patch.note) {
      finding.verificationNotes = finding.verificationNotes ?? []
      finding.verificationNotes.push({ at: nowIso(), note: redactText(sanitizeText(patch.note, 1000)) })
    }
    finding.updatedAt = nowIso()
    await writeJsonAtomic(this.findingsFile, { version: 1, taskId: this.taskId, findings: store.findings })
    await this.audit?.append({ action: 'finding.verify', taskId: this.taskId, findingId, verification: finding.verification })
    return finding
    })
  }

  /**
   * Integrity check of the evidence chain.
   */
  async verifyChain() {
    const records = await readJsonl(this.evidenceFile, { limit: 10000 })
    let prevHash = 'genesis'
    for (const record of records) {
      if (record.prevHash !== prevHash) return { valid: false, records: records.length, brokenAt: record.index, reason: 'prevHash mismatch' }
      const { hash, prevHash: recordPrev, ...body } = record
      if (chainHash(prevHash, body) !== hash) return { valid: false, records: records.length, brokenAt: record.index, reason: 'record hash mismatch' }
      prevHash = hash
    }
    return { valid: true, records: records.length, brokenAt: null, reason: null }
  }
}

/** @param {string[]} items */
function unique(items) {
  return [...new Set(items.filter(Boolean))]
}

export default EvidenceStore
