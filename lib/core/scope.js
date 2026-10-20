/**
 * Scope / permission policy engine.
 *
 * Four capability levels, enforced in code, never by prompting:
 *   L0  offline read-only analysis inside the task workspace (or an authorized path)
 *   L1  local dynamic analysis —only inside an isolated provider, with platform approval
 *   L2  active testing against an explicitly authorized network target, with platform approval and rate limits
 *   L3  destructive / exfiltration / persistence —always denied
 *
 * Authorizations are durable records with an integrity signature; approvals are
 * short-lived, single-use-bounded records created only after the platform
 * approval service answered `allowed-once`.
 * @module dsh-armorbreak/lib/core/scope
 */
import { realpathSync } from 'node:fs'
import { statSync } from 'node:fs'
import { isIP } from 'node:net'
import { lookup as dnsLookupCallback } from 'node:dns'
import { dirname, resolve } from 'node:path'
import { appendJsonl, isPathInside, newId, nowIso, readJson, sha256, canonicalJson, writeJsonAtomic } from './util.js'

/** @typedef {'L0'|'L1'|'L2'|'L3'} RiskLevel */
/** @typedef {{host: string, ports?: number[]}} NetworkTarget */

export const RISK_LEVELS = /** @type {const} */ (['L0', 'L1', 'L2', 'L3'])

/** Always-denied host locations for read/write targets (defence in depth). */
const SENSITIVE_PATH_PATTERNS = [
  /[\\/]windows[\\/]system32([\\/]|$)/i,
  /[\\/]windows[\\/]syswow64([\\/]|$)/i,
  /[\\/]windows[\\/]system32[\\/]config([\\/]|$)/i,
  /^[\\/]?proc([\\/]|$)/i,
  /^[\\/]?sys([\\/]|$)/i,
  /^[\\/]?dev([\\/]|$)/i,
  /^[\\/]?etc[\\/]shadow$/i,
]

/** Rate-limit defaults for L2 active testing. */
const RATE = { capacity: 20, refillPerSec: 0.5, maxUsesPerApproval: 200 }

/** Cloud metadata endpoints that are never a legitimate research target. */
const DENIED_RESOLVED_IPS = new Set(['169.254.169.254', 'fd00:ec2::254', '100.100.100.200'])

/** @param {string} host */
async function defaultResolveHost(host) {
  return new Promise((resolvePromise, reject) => {
    dnsLookupCallback(host, { all: true }, (error, addresses) => {
      if (error) reject(error)
      else resolvePromise((addresses ?? []).map((item) => item.address))
    })
  })
}

/**
 * Reject path forms with device/UNC/ambiguous semantics before touching the FS.
 * @param {string} value
 */
export function isUnsafePathForm(value) {
  const text = String(value ?? '')
  if (text.includes('\u0000')) return true
  if (/^\\\\[?.]\\/.test(text)) return true
  if (/^\\\\[^\\]/.test(text)) return true
  if (/^\/\/[^/]/.test(text)) return true
  return false
}

/**
 * Compare a risk level numerically.
 * @param {string} a
 * @param {string} b
 */
export function riskAtLeast(a, b) {
  const indexOf = (/** @type {string} */ level) => Math.max(0, RISK_LEVELS.indexOf(level))
  return indexOf(a) >= indexOf(b)
}

/**
 * Normalize a network target string: strip scheme/path/port, lowercase.
 * @param {string} raw
 * @returns {{host: string, port: number|null}}
 */
export function parseNetworkTarget(raw) {
  let text = String(raw ?? '').trim().toLowerCase()
  if (!text) throw new Error('network target must be a non-empty host, domain, or CIDR')
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
  // CIDR must be preserved: the slash is part of the target, not a path.
  if (text.includes('/')) {
    const slash = text.lastIndexOf('/')
    const address = text.slice(0, slash)
    const bits = text.slice(slash + 1)
    if (isIP(address) !== 0 && /^\d{1,3}$/.test(bits)) return { host: `${address}/${bits}`, port: null }
  }
  text = text.replace(/[/?#].*$/, '')
  const ipv6Bracket = text.match(/^\[([0-9a-f:]+)\](?::(\d+))?$/)
  if (ipv6Bracket) return { host: ipv6Bracket[1], port: ipv6Bracket[2] ? Number(ipv6Bracket[2]) : null }
  const withPort = text.match(/^([^:]+):(\d+)$/)
  if (withPort && isIP(withPort[1]) !== 6) return { host: withPort[1], port: Number(withPort[2]) }
  return { host: text, port: null }
}

/**
 * Match one host against one authorized network target pattern.
 * Supports exact hosts, `*.domain` wildcards, IPv4/IPv6 CIDR, and optional ports.
 * @param {NetworkTarget} pattern
 * @param {{host: string, port: number|null}} target
 * @returns {boolean}
 */
export function networkTargetMatches(pattern, target) {
  if (!pattern || !pattern.host) return false
  const patternPorts = Array.isArray(pattern.ports) ? pattern.ports : []
  // A port-scoped authorization/approval never covers a target with an unknown port.
  if (patternPorts.length > 0 && (target.port === null || !patternPorts.includes(target.port))) return false
  const host = target.host
  const patternHost = pattern.host.toLowerCase()
  if (patternHost.includes('/')) {
    const range = patternHost.split('/')[0]
    const family = isIP(range)
    if (family === 4) return ipv4InCidr(host, patternHost)
    if (family === 6) return ipv6InCidr(host, patternHost)
    return false
  }
  if (patternHost.startsWith('*.')) {
    const suffix = patternHost.slice(1)
    return host.endsWith(suffix) && host.length > suffix.length
  }
  return host === patternHost
}

/**
 * @param {string} host
 * @param {string} cidr
 */
function ipv4InCidr(host, cidr) {
  const [range, bitsRaw] = cidr.split('/')
  const bits = Number(bitsRaw)
  const toInt = (/** @type {string} */ ip) => {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  }
  const hostInt = toInt(host)
  const rangeInt = toInt(range)
  if (hostInt === null || rangeInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false
  if (bits === 0) return true
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (hostInt & mask) === (rangeInt & mask)
}

/**
 * @param {string} host
 * @param {string} cidr
 */
function ipv6InCidr(host, cidr) {
  if (isIP(host) !== 6) return false
  const [range, bitsRaw] = cidr.split('/')
  const bits = Number(bitsRaw)
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return false
  const parse = (/** @type {string} */ ip) => {
    const normalized = ip.toLowerCase()
    const [head, tail] = normalized.split('::')
    const headParts = head ? head.split(':') : []
    const tailParts = tail ? tail.split(':') : []
    const missing = 8 - headParts.length - tailParts.length
    const parts = [...headParts, ...Array(Math.max(0, missing)).fill('0'), ...tailParts]
    let value = 0n
    for (const part of parts) {
      const group = BigInt(parseInt(part || '0', 16))
      value = (value << 16n) | group
    }
    return value
  }
  const hostValue = parse(host)
  const rangeValue = parse(range)
  const shift = BigInt(128 - bits)
  return hostValue >> shift === rangeValue >> shift
}

/**
 * @param {string} path
 * @returns {string}
 */
function realpathOrResolved(path) {
  try {
    return realpathSync.native(path)
  } catch {
    try {
      return realpathSync(path)
    } catch {
      return resolve(path)
    }
  }
}

/**
 * @param {string} path
 */
function isSensitivePath(path) {
  const normalized = path.replace(/\//g, '\\').replace(/^([a-z]):/i, (m) => m.toUpperCase())
  return SENSITIVE_PATH_PATTERNS.some((pattern) => pattern.test(normalized) || pattern.test(path))
}

/**
 * Validate and normalize the fields shared by authorization requests and records.
 * @param {any} input
 * @param {number} now
 */
function normalizeAuthorizationInput(input, now) {
  const purpose = String(input?.purpose ?? '').trim()
  const operator = String(input?.operator ?? '').trim()
  if (purpose.length < 4) throw new Error('authorization needs a purpose of at least 4 characters (what is being researched and why)')
  if (operator.length < 2) throw new Error('authorization needs an operator: the human or team granting it')
  const paths = (Array.isArray(input?.paths) ? input.paths : [])
    .filter((item) => typeof item === 'string' && item.trim() !== '')
    .map((item) => resolve(item))
  /** @type {NetworkTarget[]} */
  const networkTargets = (Array.isArray(input?.networkTargets) ? input.networkTargets : [])
    .filter(Boolean)
    .map((item) => {
      if (typeof item === 'string') {
        const parsed = parseNetworkTarget(item)
        return { host: parsed.host, ports: parsed.port !== null ? [parsed.port] : [] }
      }
      return { host: String(item.host ?? '').toLowerCase(), ports: Array.isArray(item.ports) ? item.ports : [] }
    })
    .filter((item) => item.host !== '')
  if (paths.length === 0 && networkTargets.length === 0) {
    throw new Error('authorization must cover at least one path or one network target; empty authorizations grant nothing')
  }
  const createdAt = new Date(now).toISOString()
  const expiresAt = input?.expiresAt && !Number.isNaN(Date.parse(input.expiresAt))
    ? new Date(input.expiresAt).toISOString()
    : new Date(now + (input?.ttlMs ?? 24 * 60 * 60 * 1000)).toISOString()
  return {
    purpose,
    operator,
    paths,
    networkTargets,
    riskCeiling: input?.riskCeiling ?? 'L2',
    createdAt,
    expiresAt,
  }
}

/** @param {string} file */
async function fileExists(file) {
  try {
    statSync(file)
    return true
  } catch {
    return false
  }
}

export class ScopePolicy {
  /**
   * @param {{stateRoot: string, clock?: () => number, dnsLookup?: (host: string) => Promise<string[]>}} options
   */
  constructor(options) {
    this.stateRoot = options.stateRoot
    this.stateFile = `${options.stateRoot}/policy.json`
    this.clock = options.clock ?? (() => Date.now())
    this.dnsLookup = options.dnsLookup ?? defaultResolveHost
    /** @type {{authorizations: any[], approvals: any[], authorizationRequests: any[]}} */
    this.state = { authorizations: [], approvals: [], authorizationRequests: [] }
    /** @type {Map<string, {tokens: number, last: number}>} */
    this.buckets = new Map()
    this.loaded = false
  }

  async load() {
    if (this.loaded) return
    const state = await readJson(this.stateFile, null)
    if (state && Array.isArray(state.authorizations) && Array.isArray(state.approvals)) {
      this.state = { authorizations: state.authorizations, approvals: state.approvals, authorizationRequests: Array.isArray(state.authorizationRequests) ? state.authorizationRequests : [] }
    }
    this.loaded = true
  }

  async save() {
    await writeJsonAtomic(this.stateFile, { version: 1, savedAt: nowIso(), ...this.state })
  }

  /**
   * Create a durable authorization record.
   * @param {{purpose: string, operator: string, paths?: string[], networkTargets?: NetworkTarget[]|string[], riskCeiling?: RiskLevel, expiresAt?: string, ttlMs?: number}} input
   */
  async authorize(input) {
    await this.load()
    const purpose = String(input.purpose ?? '').trim()
    const operator = String(input.operator ?? '').trim()
    if (purpose.length < 4) throw new Error('authorization needs a purpose of at least 4 characters (what is being researched and why)')
    if (operator.length < 2) throw new Error('authorization needs an operator: the human or team granting it')
    const paths = (Array.isArray(input.paths) ? input.paths : [])
      .filter((item) => typeof item === 'string' && item.trim() !== '')
      .map((item) => resolve(item))
    /** @type {NetworkTarget[]} */
    const networkTargets = (Array.isArray(input.networkTargets) ? input.networkTargets : [])
      .filter(Boolean)
      .map((item) => {
        if (typeof item === 'string') {
          const parsed = parseNetworkTarget(item)
          return { host: parsed.host, ports: parsed.port !== null ? [parsed.port] : [] }
        }
        return { host: String(item.host ?? '').toLowerCase(), ports: Array.isArray(item.ports) ? item.ports : [] }
      })
      .filter((item) => item.host !== '')
    if (paths.length === 0 && networkTargets.length === 0) {
      throw new Error('authorization must cover at least one path or one network target; empty authorizations grant nothing')
    }
    const createdAt = new Date(this.clock()).toISOString()
    const expiresAt = input.expiresAt && !Number.isNaN(Date.parse(input.expiresAt))
      ? new Date(input.expiresAt).toISOString()
      : new Date(this.clock() + (input.ttlMs ?? 24 * 60 * 60 * 1000)).toISOString()
    const body = {
      kind: 'authorization',
      purpose,
      operator,
      paths,
      networkTargets,
      riskCeiling: input.riskCeiling ?? 'L2',
      createdAt,
      expiresAt,
    }
    const record = { id: newId('authz'), ...body }
    record.signature = sha256(canonicalJson(record))
    this.state.authorizations.push(record)
    await this.save()
    return record
  }

  /**
   * Model-facing part 1: record an authorization REQUEST. This does not grant
   * anything; activation requires a platform approval grant (see below).
   * @param {{purpose: string, operator: string, paths?: string[], networkTargets?: NetworkTarget[]|string[], riskCeiling?: RiskLevel, ttlMs?: number}} input
   */
  async requestAuthorization(input) {
    await this.load()
    const request = {
      kind: 'authorization-request',
      id: newId('authreq'),
      requestedAt: new Date(this.clock()).toISOString(),
      status: 'pending',
      item: normalizeAuthorizationInput(input, this.clock()),
    }
    request.signature = sha256(canonicalJson({ kind: request.kind, id: request.id, item: request.item, requestedAt: request.requestedAt }))
    this.state.authorizationRequests.push(request)
    await this.save()
    return request
  }

  /**
   * Model-facing part 2: activate a pending request. Only the Host may call this,
   * and only with a platform approval grant. The approval identity is recorded in
   * the authorization record so later policy/evidence consumers can audit it.
   * @param {string} requestId
   * @param {{approvedBy: string, approvalId?: string, approvalSource?: string, source?: string}} approval
   */
  async activateAuthorization(requestId, approval) {
    await this.load()
    const request = this.state.authorizationRequests.find((item) => item.id === requestId)
    if (!request) throw new Error(`authorization request not found: ${requestId}`)
    if (request.status !== 'pending') throw new Error(`authorization request is not pending: ${requestId} (${request.status})`)
    const approvedBy = String(approval?.approvedBy ?? '').trim()
    const approvalSource = String(approval?.approvalSource ?? approval?.source ?? '').trim()
    if (approvedBy.length < 2) throw new Error('activation requires the approving human/operator (approvedBy)')
    if (approvalSource !== 'platform-approval') throw new Error('activation requires a platform approval grant (approvalSource=platform-approval)')
    const body = { ...request.item, approvedBy, approvalSource, approvalId: approval?.approvalId ?? null }
    const record = { id: newId('authz'), ...body, createdAt: new Date(this.clock()).toISOString() }
    record.signature = sha256(canonicalJson(record))
    this.state.authorizations.push(record)
    request.status = 'activated'
    request.activatedAt = record.createdAt
    request.authorizationId = record.id
    await this.save()
    return record
  }

  /** @param {string} id */
  async revokeRequest(id) {
    await this.load()
    const request = this.state.authorizationRequests.find((item) => item.id === id)
    if (!request) throw new Error(`authorization request not found: ${id}`)
    request.status = 'revoked'
    request.revokedAt = new Date(this.clock()).toISOString()
    await this.save()
    return request
  }

  async listRequests() {
    await this.load()
    return this.state.authorizationRequests.map((item) => ({ ...item }))
  }

  /**
   * Internal/test helper: create an active authorization directly. Model-facing
   * code must use requestAuthorization + activateAuthorization with approval.
   * @param {{purpose: string, operator: string, paths?: string[], networkTargets?: NetworkTarget[]|string[], riskCeiling?: RiskLevel, expiresAt?: string, ttlMs?: number}} input
   */
  async authorize(input) {
    await this.load()
    const record = { id: newId('authz'), ...normalizeAuthorizationInput(input, this.clock()) }
    record.signature = sha256(canonicalJson(record))
    this.state.authorizations.push(record)
    await this.save()
    return record
  }

  /** @param {string} id */
  async revoke(id) {
    await this.load()
    const before = this.state.authorizations.length
    this.state.authorizations = this.state.authorizations.filter((item) => item.id !== id)
    if (this.state.authorizations.length === before) throw new Error(`authorization not found: ${id}`)
    await this.save()
    return { revoked: id }
  }

  async listAuthorizations() {
    await this.load()
    return this.state.authorizations.map((item) => ({ ...item, active: this.isAuthorizationActive(item), expired: !this.isAuthorizationActive(item) }))
  }

  async listApprovals() {
    await this.load()
    return this.state.approvals.map((item) => ({ ...item, active: this.isApprovalActive(item), expired: !this.isApprovalActive(item) }))
  }

  /** @param {any} record */
  isAuthorizationActive(record) {
    if (!record || typeof record !== 'object') return false
    if (Date.parse(record.expiresAt) <= this.clock()) return false
    const { signature, ...body } = record
    return sha256(canonicalJson(body)) === signature
  }

  /** @param {any} record */
  isApprovalActive(record) {
    if (!record || typeof record !== 'object') return false
    if (record.outcome !== 'allowed-once') return false
    if (Date.parse(record.expiresAt) <= this.clock()) return false
    if (record.used >= record.maxUses) return false
    return true
  }

  /**
   * Record an approval only after the platform approval service returned a grant.
   * @param {{kind: 'L1'|'L2', taskId: string, target: string, source?: 'platform'|'test', outcome: string, toolName?: string, ttlMs?: number}} input
   */
  async recordApproval(input) {
    await this.load()
    if (input.outcome !== 'allowed-once') {
      throw new Error(`approval outcome ${input.outcome} is not a grant; nothing recorded`)
    }
    const createdAt = new Date(this.clock()).toISOString()
    const record = {
      id: newId('appr'),
      kind: 'approval',
      riskLevel: input.kind,
      taskId: input.taskId,
      target: String(input.target ?? ''),
      source: input.source ?? 'platform',
      outcome: input.outcome,
      toolName: input.toolName ?? 'armorbreak_analyze',
      createdAt,
      expiresAt: new Date(this.clock() + (input.ttlMs ?? 30 * 60 * 1000)).toISOString(),
      used: 0,
      maxUses: RATE.maxUsesPerApproval,
    }
    this.state.approvals.push(record)
    await this.save()
    return record
  }

  async findApproval(id) {
    await this.load()
    return this.state.approvals.find((item) => item.id === id)
  }

  async consumeApproval(id) {
    const record = await this.findApproval(id)
    if (!record) throw new Error(`approval not found: ${id}`)
    record.used += 1
    await this.save()
    return record
  }

  /**
   * Validate a file target for offline analysis.
   * @param {{taskId: string, targetPath: string, workspaceRoot: string}} input
   * @returns {Promise<{allowed: boolean, code: string, reason: string, resolved: string, authorizationId: string|null, level: 'L0'}>}
   */
  async checkFile(input) {
    await this.load()
    if (isUnsafePathForm(input.targetPath)) {
      return {
        allowed: false,
        code: 'INVALID_PATH_FORM',
        reason: `refusing ambiguous/device/UNC path: ${String(input.targetPath).slice(0, 200)}`,
        resolved: String(input.targetPath).slice(0, 300),
        authorizationId: null,
        level: 'L0',
      }
    }
    const raw = resolve(input.targetPath)
    const resolved = realpathOrResolved(raw)
    const workspace = realpathOrResolved(input.workspaceRoot)
    if (isSensitivePath(resolved)) {
      return { allowed: false, code: 'SENSITIVE_PATH_DENIED', reason: `refusing to analyze protected host location: ${resolved}`, resolved, authorizationId: null, level: 'L0' }
    }
    if (isPathInside(workspace, resolved)) {
      return { allowed: true, code: 'WORKSPACE_ALLOWED', reason: 'target is inside the task workspace', resolved, authorizationId: null, level: 'L0' }
    }
    for (const authorization of this.state.authorizations) {
      if (!this.isAuthorizationActive(authorization)) continue
      for (const authorizedPath of authorization.paths ?? []) {
        const authorized = realpathOrResolved(authorizedPath)
        if (isPathInside(authorized, resolved) || resolved === authorized) {
          return {
            allowed: true,
            code: 'AUTHORIZED_PATH',
            reason: `target covered by authorization ${authorization.id} (${authorization.purpose})`,
            resolved,
            authorizationId: authorization.id,
            level: 'L0',
          }
        }
      }
    }
    return {
      allowed: false,
      code: 'OUT_OF_SCOPE',
      reason: `target is outside the task workspace (${workspace}) and no active authorization covers it. Request one with armorbreak_scope action=request paths=["${dirname(resolved)}"], then activate it after platform approval, or copy the artifact into the workspace.`,
      resolved,
      authorizationId: null,
      level: 'L0',
    }
  }

  /**
   * Check whether a network target may be actively tested.
   * @param {{taskId: string, target: string, approvalId?: string|null}} input
   */
  async checkNetwork(input) {
    await this.load()
    const parsed = parseNetworkTarget(input.target)
    const authorization = this.state.authorizations.find((item) => {
      if (!this.isAuthorizationActive(item)) return false
      if (!riskAtLeast(item.riskCeiling, 'L2')) return false
      return (item.networkTargets ?? []).some((pattern) => networkTargetMatches(pattern, parsed))
    })
    if (!authorization) {
      return {
        allowed: false,
        code: 'NETWORK_OUT_OF_SCOPE',
        reason: `network target ${parsed.host} is not covered by any active authorization with L2 ceiling. Active testing is denied by default; authorize the exact target first.`,
      }
    }
    const approval = input.approvalId ? this.state.approvals.find((item) => item.id === input.approvalId) : null
    if (!approval || !this.isApprovalActive(approval)) {
      return { allowed: false, code: 'NETWORK_APPROVAL_REQUIRED', reason: 'L2 active testing requires a platform approval grant for this exact target.' }
    }
    if (!networkTargetMatches(parseNetworkTarget(approval.target), parsed)) {
      return { allowed: false, code: 'NETWORK_APPROVAL_MISMATCH', reason: `approval ${approval.id} covers ${approval.target}, not ${parsed.host}.` }
    }
    if (approval.taskId !== input.taskId) {
      return { allowed: false, code: 'NETWORK_APPROVAL_TASK_MISMATCH', reason: 'approval belongs to a different task.' }
    }
    const rate = this.takeToken(parsed.host)
    if (!rate.allowed) {
      return { allowed: false, code: 'NETWORK_RATE_LIMITED', reason: `rate limit for ${parsed.host}: retry in ${Math.ceil(rate.retryAfterMs / 1000)} s.` }
    }
    // Resolve once at policy time; the capability pins the connection to these
    // addresses so a later DNS answer cannot redirect the approved request.
    let resolvedIps = []
    if (isIP(parsed.host) !== 0) {
      resolvedIps = [parsed.host]
    } else {
      try {
        resolvedIps = await this.dnsLookup(parsed.host)
      } catch {
        resolvedIps = []
      }
    }
    const deniedIps = resolvedIps.filter((ip) => DENIED_RESOLVED_IPS.has(ip))
    if (deniedIps.length > 0) {
      return { allowed: false, code: 'NETWORK_METADATA_ENDPOINT_DENIED', reason: `denied resolved address (cloud metadata endpoint): ${deniedIps.join(', ')}` }
    }
    return {
      allowed: true,
      code: 'NETWORK_AUTHORIZED',
      reason: `covered by ${authorization.id}, approved by ${approval.id}`,
      authorizationId: authorization.id,
      approvalId: approval.id,
      resolvedIps,
      dnsWarning: resolvedIps.length === 0 ? 'DNS resolution failed at policy time; the request will fail if the host stays unresolvable.' : null,
    }
  }

  /**
   * Check whether local dynamic execution may proceed.
   * @param {{taskId: string, targetPath: string, workspaceRoot: string, isolationAvailable: boolean, approvalId?: string|null}} input
   */
  async checkExecution(input) {
    await this.load()
    if (!input.isolationAvailable) {
      return {
        allowed: false,
        code: 'ISOLATION_UNAVAILABLE',
        reason: 'L1 dynamic analysis is denied: no isolated container/VM provider is available on this host. Install Docker Desktop (or configure a VM provider) and pass its health check, or stay with offline static analysis.',
      }
    }
    const file = await this.checkFile({ taskId: input.taskId, targetPath: input.targetPath, workspaceRoot: input.workspaceRoot })
    if (!file.allowed) return { allowed: false, code: file.code, reason: file.reason }
    const approval = input.approvalId ? this.state.approvals.find((item) => item.id === input.approvalId) : null
    if (!approval || !this.isApprovalActive(approval)) {
      return { allowed: false, code: 'EXECUTION_APPROVAL_REQUIRED', reason: 'L1 dynamic analysis requires a platform approval grant for this exact sample and isolation provider.' }
    }
    if (approval.riskLevel !== 'L1' || approval.target !== resolve(input.targetPath)) {
      return { allowed: false, code: 'EXECUTION_APPROVAL_MISMATCH', reason: 'approval does not cover this sample.' }
    }
    return { allowed: true, code: 'EXECUTION_AUTHORIZED', reason: `approved by ${approval.id}`, approvalId: approval.id }
  }

  /**
   * Token bucket per host.
   * @param {string} host
   */
  takeToken(host) {
    const now = this.clock()
    let bucket = this.buckets.get(host)
    if (!bucket) {
      bucket = { tokens: RATE.capacity, last: now }
      this.buckets.set(host, bucket)
    }
    const elapsedSec = Math.max(0, (now - bucket.last) / 1000)
    bucket.tokens = Math.min(RATE.capacity, bucket.tokens + elapsedSec * RATE.refillPerSec)
    bucket.last = now
    if (bucket.tokens < 1) {
      return { allowed: false, retryAfterMs: Math.ceil(((1 - bucket.tokens) / RATE.refillPerSec) * 1000) }
    }
    bucket.tokens -= 1
    return { allowed: true, retryAfterMs: 0 }
  }

  /**
   * Append one policy decision to an audit log (best effort, caller owns audit instance).
   * @param {import('./audit.js').AuditLog} audit
   * @param {Record<string, any>} event
   */
  async audit(audit, event) {
    try {
      await audit.append({ kind: 'policy', ...event })
    } catch {
      /* auditing must not break the caller; the caller records its own outcome too */
    }
  }

  /**
   * Public, secret-free policy snapshot for health/UI surfaces.
   */
  async snapshot() {
    await this.load()
    const authorizations = this.state.authorizations.map((item) => ({
      id: item.id,
      purpose: item.purpose,
      operator: item.operator,
      paths: item.paths,
      networkTargets: item.networkTargets,
      riskCeiling: item.riskCeiling,
      createdAt: item.createdAt,
      expiresAt: item.expiresAt,
      active: this.isAuthorizationActive(item),
    }))
    const approvals = this.state.approvals.map((item) => ({
      id: item.id,
      riskLevel: item.riskLevel,
      taskId: item.taskId,
      target: item.target,
      source: item.source,
      createdAt: item.createdAt,
      expiresAt: item.expiresAt,
      active: this.isApprovalActive(item),
    }))
    return { authorizations, approvals, sensitivePathCount: SENSITIVE_PATH_PATTERNS.length }
  }
}

export default ScopePolicy
