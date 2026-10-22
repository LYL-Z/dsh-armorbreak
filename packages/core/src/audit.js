/**
 * Append-only audit log with a per-record hash chain.
 * Records are redacted before they are written; the chain makes silent edits detectable.
 * @module dsh-armorbreak/lib/core/audit
 */
import { appendJsonl, chainHash, nowIso, readJsonl, redactDeep, withFileMutex } from './util.js'

/** Fields never written to the audit log. */
const DROP_KEYS = new Set(['buffer', 'text', 'content', 'bytes', 'signal'])

/**
 * @param {unknown} value
 * @returns {unknown}
 */
function compact(value) {
  if (Array.isArray(value)) return value.slice(0, 100).map(compact)
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {}
    let count = 0
    for (const [key, inner] of Object.entries(value)) {
      if (DROP_KEYS.has(key)) continue
      if (count >= 40) break
      out[key] = compact(inner)
      count += 1
    }
    return out
  }
  return value
}

export class AuditLog {
  /**
   * @param {{file: string, taskFile?: (taskId: string) => string}} options
   */
  constructor(options) {
    this.file = options.file
  }

  /** @returns {Promise<{seq: number, prevHash: string}>} */
  async tail() {
    const records = await readJsonl(this.file, { limit: 1 })
    const last = records[records.length - 1]
    if (!last || typeof last.seq !== 'number') return { seq: 0, prevHash: 'genesis' }
    return { seq: last.seq, prevHash: last.hash ?? 'genesis' }
  }

  /**
   * Append one redacted event. Execution must not depend on a successful audit write:
   * the caller decides whether a failure is fatal.
   * @param {Record<string, any>} event
   * @returns {Promise<{seq: number, hash: string}>}
   */
  async append(event) {
    return withFileMutex(this.file, async () => {
      const { seq, prevHash } = await this.tail()
      const payload = {
        seq: seq + 1,
        at: nowIso(),
        prevHash,
        ...compact(redactDeep(event)),
      }
      payload.seq = seq + 1
      payload.prevHash = prevHash
      const hash = chainHash(prevHash, payload)
      await appendJsonl(this.file, { ...payload, hash })
      return { seq: payload.seq, hash }
    })
  }

  /**
   * Read the most recent records.
   * @param {{limit?: number, taskId?: string}} [filter]
   */
  async read(filter = {}) {
    const records = await readJsonl(this.file, { limit: filter.limit ? Math.min(filter.limit * 4, 4000) : 2000 })
    const filtered = filter.taskId ? records.filter((record) => record.taskId === filter.taskId) : records
    const limit = filter.limit ?? 200
    return filtered.slice(-limit)
  }

  /**
   * Verify the hash chain over the complete log.
   * @returns {Promise<{valid: boolean, records: number, brokenAt: number|null, reason: string|null}>}
   */
  async verify() {
    const records = await readJsonl(this.file, { limit: 100000 })
    let prevHash = 'genesis'
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index]
      if (record.prevHash !== prevHash) {
        return { valid: false, records: records.length, brokenAt: index + 1, reason: 'prevHash mismatch' }
      }
      const { hash, ...payload } = record
      if (chainHash(prevHash, payload) !== hash) {
        return { valid: false, records: records.length, brokenAt: index + 1, reason: 'record hash mismatch' }
      }
      prevHash = hash
    }
    return { valid: true, records: records.length, brokenAt: null, reason: null }
  }
}

export default AuditLog
