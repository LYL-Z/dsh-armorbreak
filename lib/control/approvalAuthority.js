/**
 * AB2-M1-04 approval authority: platform approvals are bound to an exact
 * task/target/risk/session and signed with a Host-local key. The model never sees
 * the key; tokens are single-use, expire, and can be revoked. This raises the bar
 * over "anyone can append a JSON record"; a local user with write access to the
 * key remains an acknowledged residual risk.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import { readSafeRepoFile } from '../release/safeEvidenceFile.js'

export const APPROVAL_TOKEN_VERSION = 'abappr1'
const LOCK_TIMEOUT_MS = 5000

export function makeApprovalId() {
  return `appr_${randomUUID().replace(/-/g, '').slice(0, 20)}`
}

function base64url(value) {
  return Buffer.from(value, 'utf8').toString('base64url')
}

function parseBase64url(value) {
  return Buffer.from(value, 'base64url').toString('utf8')
}

export class ApprovalAuthority {
  /**
   * @param {{stateRoot: string, clock?: () => number, ttlMs?: number}} input
   */
  constructor(input) {
    this.stateRoot = input.stateRoot
    this.clock = input.clock ?? Date.now
    this.ttlMs = input.ttlMs ?? 30 * 60 * 1000
    this.secretPath = join(this.stateRoot, 'approval.key')
    this.statePath = join(this.stateRoot, 'approval-state.json')
    mkdirSync(this.stateRoot, { recursive: true })
    this.secret = this.loadSecret()
    this.state = this.loadState()
  }

  loadSecret() {
    const transientConcurrentRead = (error) => error?.code === 'APPROVAL_KEY_INCOMPLETE'
      || (error?.code === 'EVIDENCE_PATH_UNSAFE' && [
        'evidence file changed while reading: approval.key',
        'evidence file size changed or exceeded its limit: approval.key',
      ].includes(error.message))
    const readExisting = () => {
      const existing = readSafeRepoFile(this.stateRoot, 'approval.key', { maxBytes: 4096 })
      if (existing.length < 32) {
        const error = new Error('approval key is too short; refusing to replace it')
        error.code = 'APPROVAL_KEY_INCOMPLETE'
        throw error
      }
      return existing
    }
    const readConcurrentWinner = () => {
      const deadline = Date.now() + 1000
      while (true) {
        try { return readExisting() } catch (error) {
          if (!transientConcurrentRead(error) || Date.now() >= deadline) throw error
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10)
        }
      }
    }
    try {
      return readExisting()
    } catch (error) {
      if (error?.code === 'ENOENT') {
        // Another initializer may have won the exclusive create and still be
        // writing the key. Wait only for the exact incomplete/read-changed
        // states produced by that race; symlinks, hard links, and identity
        // changes continue to fail closed immediately.
      } else if (transientConcurrentRead(error)) {
        try { return readConcurrentWinner() } catch (readError) {
          throw new Error(`approval key is unreadable; failing closed: ${readError.message}`)
        }
      } else {
        throw new Error(`approval key is unreadable; failing closed: ${error.message}`)
      }
    }

    const secret = randomBytes(32)
    let descriptor
    try {
      descriptor = openSync(this.secretPath, 'wx', 0o600)
      let offset = 0
      while (offset < secret.length) offset += writeSync(descriptor, secret, offset, secret.length - offset)
      fsyncSync(descriptor)
      closeSync(descriptor)
      descriptor = undefined
      return secret
    } catch (error) {
      if (descriptor !== undefined) closeSync(descriptor)
      if (error?.code === 'EEXIST') {
        try { return readConcurrentWinner() } catch (readError) {
          throw new Error(`approval key creation raced with an unsafe or invalid file; failing closed: ${readError.message}`)
        }
      }
      throw new Error(`approval key could not be created; failing closed: ${error.message}`)
    }
  }

  loadState() {
    if (!existsSync(this.statePath)) return { usedNonces: [], revoked: [] }
    try {
      const parsed = JSON.parse(readFileSync(this.statePath, 'utf8'))
      if (!parsed || !Array.isArray(parsed.usedNonces) || !Array.isArray(parsed.revoked)) throw new Error('invalid approval state schema')
      return { usedNonces: parsed.usedNonces, revoked: parsed.revoked }
    } catch (error) {
      throw new Error(`approval state is unreadable; failing closed: ${error.message}`)
    }
  }

  saveState() {
    const tmp = `${this.statePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    let fd
    try {
      fd = openSync(tmp, 'wx', 0o600)
      writeFileSync(fd, `${JSON.stringify(this.state)}\n`)
      fsyncSync(fd)
      closeSync(fd)
      fd = undefined
      renameSync(tmp, this.statePath)
    } finally {
      if (fd !== undefined) closeSync(fd)
      try { rmSync(tmp, { force: true }) } catch { /* best-effort temp cleanup */ }
    }
  }

  withStateLock(operation) {
    const lockPath = `${this.statePath}.lock`
    const deadline = Date.now() + LOCK_TIMEOUT_MS
    let fd
    while (fd === undefined) {
      try {
        fd = openSync(lockPath, 'wx', 0o600)
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error
        if (Date.now() >= deadline) throw new Error('approval state lock timed out; operation failed closed')
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10)
      }
    }
    try {
      this.state = this.loadState()
      return operation()
    } finally {
      closeSync(fd)
      try { rmSync(lockPath, { force: true }) } catch { /* a leftover lock fails closed on the next operation */ }
    }
  }

  sign(payloadText) {
    const text = typeof payloadText === 'string' ? payloadText : JSON.stringify(payloadText)
    return createHmac('sha256', this.secret).update(text).digest('hex')
  }

  /**
   * @param {{id: string, riskLevel: 'L1'|'L2', taskId: string, target: string, operator: string, sessionId?: string|null, ttlMs?: number}} input
   */
  issue(input) {
    if (!input.id || !input.taskId || !input.target || !input.operator) throw new Error('approval token requires id/taskId/target/operator')
    if (!['L1', 'L2'].includes(input.riskLevel)) throw new Error('approval token is only for L1/L2')
    const issuedAt = this.clock()
    const payload = {
      v: APPROVAL_TOKEN_VERSION,
      id: String(input.id),
      riskLevel: input.riskLevel,
      taskId: String(input.taskId),
      target: String(input.target),
      operator: String(input.operator),
      sessionId: input.sessionId ?? null,
      issuedAt: new Date(issuedAt).toISOString(),
      expiresAt: new Date(issuedAt + (input.ttlMs ?? this.ttlMs)).toISOString(),
      nonce: randomBytes(16).toString('hex'),
    }
    const body = base64url(JSON.stringify(payload))
    return { token: `${APPROVAL_TOKEN_VERSION}.${body}.${this.sign(payload)}`, payload }
  }

  /**
   * @param {string} token
   * @param {{id?: string, taskId?: string, target?: string, riskLevel?: string, sessionId?: string|null, operator?: string}} [expected]
   */
  verify(token, expected = {}) {
    // Instances may be long-lived while other processes consume or revoke
    // approvals. Never make a decision from constructor-time state.
    this.state = this.loadState()
    const text = String(token ?? '')
    const parts = text.split('.')
    if (parts.length !== 3 || parts[0] !== APPROVAL_TOKEN_VERSION) return { valid: false, code: 'TOKEN_FORMAT' , reason: 'malformed approval token' }
    let payload
    try {
      payload = JSON.parse(parseBase64url(parts[1]))
    } catch {
      return { valid: false, code: 'TOKEN_FORMAT', reason: 'approval token payload is not JSON' }
    }
    const actual = Buffer.from(this.sign(payload), 'utf8')
    const supplied = Buffer.from(parts[2], 'utf8')
    if (actual.length !== supplied.length || !timingSafeEqual(actual, supplied)) return { valid: false, code: 'TOKEN_SIGNATURE', reason: 'approval token signature mismatch' }
    if (payload.v !== APPROVAL_TOKEN_VERSION) return { valid: false, code: 'TOKEN_VERSION', reason: 'unsupported approval token version' }
    if (Date.parse(payload.expiresAt) <= this.clock()) return { valid: false, code: 'TOKEN_EXPIRED', reason: 'approval token expired' }
    if (this.state.revoked.includes(payload.id)) return { valid: false, code: 'TOKEN_REVOKED', reason: 'approval token revoked' }
    if (this.state.usedNonces.includes(payload.nonce)) return { valid: false, code: 'TOKEN_REPLAYED', reason: 'approval token already consumed' }
    for (const key of ['id', 'taskId', 'target', 'riskLevel', 'operator']) {
      if (expected[key] !== undefined && expected[key] !== null && String(payload[key]) !== String(expected[key])) {
        return { valid: false, code: 'TOKEN_BINDING_MISMATCH', reason: `approval token ${key} does not match` }
      }
    }
    if (expected.sessionId !== undefined && expected.sessionId !== null && String(payload.sessionId ?? '') !== String(expected.sessionId)) {
      return { valid: false, code: 'TOKEN_BINDING_MISMATCH', reason: 'approval token session does not match' }
    }
    return { valid: true, payload }
  }

  /** Verify and consume in one step; a second consume is rejected as replay. */
  consume(token, expected = {}) {
    return this.withStateLock(() => {
      const verified = this.verify(token, expected)
      if (!verified.valid) return verified
      this.state.usedNonces.push(verified.payload.nonce)
      this.saveState()
      return verified
    })
  }

  revoke(id) {
    const value = String(id ?? '')
    if (value) this.withStateLock(() => {
      if (!this.state.revoked.includes(value)) {
        this.state.revoked.push(value)
        this.saveState()
      }
    })
    return { revoked: value, revokedAt: new Date(this.clock()).toISOString() }
  }
}
