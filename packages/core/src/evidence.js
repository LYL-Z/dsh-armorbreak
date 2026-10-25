/**
 * Evidence and finding store for one task.
 * Every evidence record carries the SHA-256 of the analyzed bytes, a redacted
 * excerpt, and a per-task hash chain so silent edits are detectable.
 * @module dsh-armorbreak/lib/core/evidence
 */
import { lstat, realpath } from 'node:fs/promises'
import { isAbsolute, parse, relative, resolve, sep } from 'node:path'
import { appendJsonl, chainHash, newId, nowIso, readBounded, readJson, readJsonl, redactDeep, redactText, sanitizeText, sha256, withFileMutex, writeJsonAtomic } from './util.js'
import { withAppendFileLock } from './append-lock.js'

const HEAD_SCHEMA = 'armorbreak.evidence-head/v1'
const HEAD_FILE = 'evidence.head.json'

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

function pathIsWithin(root, target) {
  const rel = relative(root, target)
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

async function hasLinkComponent(path) {
  // realpath expands valid Windows 8.3 names; inspect the supplied path itself
  // for links, then compare the resolved head under the resolved task root.
  const absolute = resolve(path)
  const root = parse(absolute).root
  let current = root
  for (const part of relative(root, absolute).split(sep).filter(Boolean)) {
    current = resolve(current, part)
    const info = await lstat(current, { bigint: true })
    if (info.isSymbolicLink()) return true
  }
  return false
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]))
}

function findingStateHash(finding) {
  return sha256(JSON.stringify(stableValue(finding)))
}

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
    this.findingAudit = options.audit ?? null
    this.evidenceFile = `${options.taskDir}/evidence.jsonl`
    this.headFile = resolve(options.taskDir, HEAD_FILE)
    this.findingsFile = `${options.taskDir}/findings.json`
  }

  /**
   * Read the separately persisted chain head. A missing anchor is acceptable
   * only for a task with no evidence; legacy evidence without an anchor is
   * deliberately reported as unverified rather than silently trusted.
   * @returns {Promise<{anchor: any|null, error: string|null}>}
   */
  async readHeadAnchor() {
    const taskRoot = resolve(this.taskDir)
    try {
      const { buffer, truncated } = await readBounded(this.headFile, 4096, {
        authorize: async (candidate) => {
          try {
            const [rootReal, rootInfo, headInfo, rootHasLink, headHasLink] = await Promise.all([
              realpath(taskRoot),
              lstat(taskRoot, { bigint: true }),
              lstat(candidate, { bigint: true }),
              hasLinkComponent(taskRoot),
              hasLinkComponent(candidate),
            ])
            const target = resolve(candidate)
            if (rootHasLink || headHasLink || rootInfo.isSymbolicLink() || !rootInfo.isDirectory() ||
                !pathIsWithin(taskRoot, target) || !samePath(target, this.headFile) ||
                headInfo.isSymbolicLink() || !headInfo.isFile()) {
              return { allowed: false, code: 'EVIDENCE_HEAD_UNSAFE', reason: 'evidence head path is not a regular file inside the task directory' }
            }
            const canonical = await realpath(target)
            if (!pathIsWithin(rootReal, canonical)) {
              return { allowed: false, code: 'EVIDENCE_HEAD_UNSAFE', reason: 'evidence head path resolves outside the task directory' }
            }
            return { allowed: true, resolved: canonical }
          } catch (error) {
            return { allowed: false, code: error?.code ?? 'EVIDENCE_HEAD_UNSAFE', reason: 'evidence head path could not be verified' }
          }
        },
      })
      if (truncated) return { anchor: null, error: 'evidence head anchor exceeds the size limit' }
      let anchor
      try { anchor = JSON.parse(buffer.toString('utf8')) } catch { return { anchor: null, error: 'evidence head anchor is not valid JSON' } }
      if (!anchor || anchor.schemaVersion !== HEAD_SCHEMA || anchor.taskId !== this.taskId ||
          !Number.isSafeInteger(anchor.count) || anchor.count < 0 ||
          !(anchor.headHash === 'genesis' || /^[a-f0-9]{64}$/i.test(anchor.headHash ?? ''))) {
        return { anchor: null, error: 'evidence head anchor has an invalid schema or value' }
      }
      return { anchor, error: null }
    } catch (error) {
      if (error?.code === 'ENOENT') return { anchor: null, error: null }
      return { anchor: null, error: `evidence head anchor is unsafe or unreadable: ${error?.code ?? error?.message ?? 'unknown error'}` }
    }
  }

  /** Persist the latest head after the evidence append; any interrupted update fails closed. */
  async writeHeadAnchor(count, headHash) {
    const anchor = { schemaVersion: HEAD_SCHEMA, taskId: this.taskId, count, headHash }
    await writeJsonAtomic(this.headFile, anchor)
    const saved = await this.readHeadAnchor()
    if (saved.error || saved.anchor?.count !== count || saved.anchor?.headHash !== headHash) {
      throw new Error(saved.error ?? 'evidence head anchor did not persist')
    }
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
      const current = await this.verifyChain()
      if (!current.valid) {
        const error = new Error(`cannot append to an invalid evidence chain: ${current.reason}`)
        error.code = 'EVIDENCE_CHAIN_INVALID'
        throw error
      }
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
      await this.writeHeadAnchor(record.index, hash)
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
    const findings = Array.isArray(state.findings) ? state.findings : []
    if (!this.findingAudit) {
      return {
        findings: findings.map((finding) => ({
          ...finding,
          severity: 'info',
          severityScore: SEVERITY_SCORE.info,
          cvss: null,
          verification: 'unverified',
          evidenceIds: [],
        })),
        integrityStatus: findings.length ? 'UNVERIFIED_NO_AUDIT' : 'VERIFIED',
      }
    }
    const chain = await this.findingAudit.verify()
    if (!chain.valid) {
      const error = new Error(`finding integrity audit is invalid: ${chain.reason ?? 'unknown chain error'}`)
      error.code = 'FINDING_AUDIT_INVALID'
      throw error
    }
    const events = await this.findingAudit.read({ taskId: this.taskId, limit: 1000 })
    const committed = new Map()
    for (const event of events) {
      if (!['finding.record', 'finding.merge', 'finding.verify'].includes(event.action) || typeof event.findingId !== 'string') continue
      committed.set(event.findingId, /^[a-f0-9]{64}$/i.test(event.stateHash ?? '') ? event.stateHash.toLowerCase() : null)
    }
    const byId = new Map()
    for (const finding of findings) {
      if (typeof finding?.id !== 'string') continue
      if (byId.has(finding.id)) {
        const error = new Error(`finding snapshot contains duplicate id: ${finding.id}`)
        error.code = 'FINDING_INTEGRITY_INVALID'
        throw error
      }
      byId.set(finding.id, finding)
    }
    for (const [findingId, stateHash] of committed) {
      if (stateHash && !byId.has(findingId)) {
        const error = new Error(`finding snapshot is missing audited finding: ${findingId}`)
        error.code = 'FINDING_INTEGRITY_MISMATCH'
        throw error
      }
    }
    let legacyCount = 0
    const verified = findings.map((finding) => {
      const expectedHash = typeof finding?.id === 'string' ? committed.get(finding.id) : null
      if (expectedHash && expectedHash !== findingStateHash(finding)) {
        const error = new Error(`finding snapshot does not match its audit commitment: ${finding.id}`)
        error.code = 'FINDING_INTEGRITY_MISMATCH'
        throw error
      }
      if (expectedHash) return finding
      legacyCount += 1
      return {
        ...finding,
        severity: 'info',
        severityScore: SEVERITY_SCORE.info,
        cvss: null,
        verification: 'unverified',
        evidenceIds: [],
      }
    })
    return { findings: verified, integrityStatus: legacyCount ? 'UNVERIFIED_LEGACY' : 'VERIFIED' }
  }

  /**
   * Merge one analyzer finding with provenance evidence ids.
   * @param {any} raw
   * @param {{evidenceIds?: string[], capabilityId?: string, targetPath?: string|null}} context
   */
  async addFinding(raw, context = {}) {
    if (!this.findingAudit) {
      const error = new Error('finding persistence requires an integrity audit log')
      error.code = 'FINDING_AUDIT_REQUIRED'
      throw error
    }
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
      await this.findingAudit.append({ action: 'finding.merge', taskId: this.taskId, findingId: existing.id, stateHash: findingStateHash(existing) })
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
    await this.findingAudit.append({ action: 'finding.record', taskId: this.taskId, findingId: finding.id, severity, verification, title, stateHash: findingStateHash(finding) })
    return { finding, merged: false }
    })
  }

  /**
   * Update verification status (human/model judgement after corroboration).
   * @param {string} findingId
   * @param {{verification?: Verification, note?: string, severity?: Severity, evidenceIds?: string[]}} patch
   */
  async verifyFinding(findingId, patch) {
    if (!this.findingAudit) {
      const error = new Error('finding verification requires an integrity audit log')
      error.code = 'FINDING_AUDIT_REQUIRED'
      throw error
    }
    return withFileMutex(this.findingsFile, async () => {
      const store = await this.readFindings()
    const finding = store.findings.find((item) => item.id === findingId)
    if (!finding) throw new Error(`finding not found: ${findingId}`)
    const priorVerification = finding.verification
    const priorSeverity = finding.severity
    const nextVerification = patch.verification ? oneOf(patch.verification, VERIFICATIONS, finding.verification) : finding.verification
    const nextSeverity = patch.severity ? oneOf(patch.severity, SEVERITIES, finding.severity) : finding.severity
    const verificationElevated = nextVerification === 'corroborated' && finding.verification !== 'corroborated'
    const severityElevated = SEVERITY_SCORE[nextSeverity] > SEVERITY_SCORE[finding.severity]
    const citedIds = [...new Set((Array.isArray(patch.evidenceIds) ? patch.evidenceIds : []).filter((id) => typeof id === 'string' && id.length <= 160))]
    if (verificationElevated || severityElevated) {
      const minimumEvidence = verificationElevated ? 2 : 1
      if (citedIds.length < minimumEvidence) throw new Error(`finding elevation requires at least ${minimumEvidence} task evidence id(s)`)
      const evidenceIds = new Set((await this.readEvidence(10000)).filter((item) => item.taskId === this.taskId).map((item) => item.id))
      const missing = citedIds.filter((id) => !evidenceIds.has(id))
      if (missing.length) throw new Error(`finding elevation references unknown task evidence: ${missing.join(', ')}`)
      finding.evidenceIds = unique([...(finding.evidenceIds ?? []), ...citedIds])
    }
    if (patch.verification) finding.verification = oneOf(patch.verification, VERIFICATIONS, finding.verification)
    if (patch.severity) finding.severity = oneOf(patch.severity, SEVERITIES, finding.severity)
    if (patch.note) {
      finding.verificationNotes = finding.verificationNotes ?? []
      finding.verificationNotes.push({ at: nowIso(), note: redactText(sanitizeText(patch.note, 1000)) })
    }
    finding.updatedAt = nowIso()
    await writeJsonAtomic(this.findingsFile, { version: 1, taskId: this.taskId, findings: store.findings })
    await this.findingAudit.append({
      action: 'finding.verify', taskId: this.taskId, findingId,
      priorVerification, priorSeverity,
      verification: finding.verification, severity: finding.severity,
      evidenceIds: citedIds, note: patch.note ?? null, stateHash: findingStateHash(finding),
    })
    return finding
    })
  }

  /**
   * Integrity check of the evidence chain.
   */
  async verifyChain() {
    const records = await readJsonl(this.evidenceFile, { limit: 10000 })
    const { anchor, error } = await this.readHeadAnchor()
    if (error) return { valid: false, records: records.length, brokenAt: null, reason: error }
    if (records.length === 0 && !anchor) return { valid: true, records: 0, brokenAt: null, reason: null }
    if (!anchor) return { valid: false, records: records.length, brokenAt: records.length || 1, reason: 'evidence head anchor missing' }
    if (anchor.count > 10000) return { valid: false, records: records.length, brokenAt: null, reason: 'evidence chain exceeds verification limit' }
    let prevHash = 'genesis'
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index]
      if (record.index !== index + 1) return { valid: false, records: records.length, brokenAt: record.index ?? index + 1, reason: 'evidence index mismatch' }
      if (record.prevHash !== prevHash) return { valid: false, records: records.length, brokenAt: record.index, reason: 'prevHash mismatch' }
      const { hash, prevHash: recordPrev, ...body } = record
      if (chainHash(prevHash, body) !== hash) return { valid: false, records: records.length, brokenAt: record.index, reason: 'record hash mismatch' }
      prevHash = hash
    }
    if (anchor.count !== records.length || anchor.headHash !== (records.at(-1)?.hash ?? 'genesis')) {
      return { valid: false, records: records.length, brokenAt: records.length + 1, reason: 'evidence head anchor mismatch' }
    }
    return { valid: true, records: records.length, brokenAt: null, reason: null }
  }
}

/** @param {string[]} items */
function unique(items) {
  return [...new Set(items.filter(Boolean))]
}

export default EvidenceStore
