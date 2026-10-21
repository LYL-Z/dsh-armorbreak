/**
 * AB2-M1-04 approval authority: platform approvals are bound to an exact
 * task/target/risk/session and signed with a Host-local key. The model never sees
 * the key; tokens are single-use, expire, and can be revoked. This raises the bar
 * over "anyone can append a JSON record"; a local user with write access to the
 * key remains an acknowledged residual risk.
 */
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

export const APPROVAL_TOKEN_VERSION = 'abappr1'

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
    if (existsSync(this.secretPath)) {
      const existing = readFileSync(this.secretPath)
      if (existing.length >= 32) return existing
    }
    const secret = randomBytes(32)
    writeFileSync(this.secretPath, secret, { mode: 0o600 })
    try {
      // best-effort on Windows; POSIX gets 0600 above
      writeFileSync(this.secretPath, secret, { mode: 0o600 })
    } catch {
      /* ignore */
    }
    return secret
  }

  loadState() {
    try {
      const parsed = JSON.parse(readFileSync(this.statePath, 'utf8'))
      return { usedNonces: Array.isArray(parsed.usedNonces) ? parsed.usedNonces : [], revoked: Array.isArray(parsed.revoked) ? parsed.revoked : [] }
    } catch {
      return { usedNonces: [], revoked: [] }
    }
  }

  saveState() {
    const tmp = `${this.statePath}.${process.pid}.tmp`
    writeFileSync(tmp, `${JSON.stringify(this.state)}\n`)
    renameSync(tmp, this.statePath)
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
    const verified = this.verify(token, expected)
    if (!verified.valid) return verified
    this.state.usedNonces.push(verified.payload.nonce)
    this.saveState()
    return verified
  }

  revoke(id) {
    const value = String(id ?? '')
    if (value && !this.state.revoked.includes(value)) {
      this.state.revoked.push(value)
      this.saveState()
    }
    return { revoked: value, revokedAt: new Date(this.clock()).toISOString() }
  }
}
