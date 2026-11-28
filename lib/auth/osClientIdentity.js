/**
 * Local OS-client identity boundary for one short-lived workspace grant.
 *
 * The host supplies `{ platform, userSid | uid, sessionId }`. `issue` binds that
 * principal and session to one workspace path and one action name. `present`
 * accepts the grant only for that same tuple. `revoke` drops it before expiry.
 *
 * A loopback address (127.0.0.1, ::1, localhost), a CSRF token, and a
 * model-supplied operator string are not OS identity. Tool arguments are not
 * read. Those values cannot take the place of the host descriptor, and they
 * are not compared when they sit beside one.
 *
 * Decisions use only this instance's grant records, the injected clock, and the
 * host request. There is no network, filesystem, environment, or OS-credential
 * read. In particular this module does not read the real Windows access token,
 * process token, logon session, or POSIX uid. A forged descriptor supplied by
 * the host is bound as supplied. Workspace and action checks are exact
 * trimmed-string comparisons: they do not resolve symlinks, junctions, 8.3
 * names, or case-insensitive filesystem paths, and they do not consult ACLs.
 * Records live in this boundary instance only. They are not process-global,
 * durable, or shared with tool dispatch.
 */
import { randomUUID } from 'node:crypto'

export const OS_CLIENT_GRANT_TTL_MS = 60_000

const HOST_PRINCIPAL_REASON = 'OS principal requires platform, userSid or uid, and sessionId from the host. A loopback address, a CSRF token, and a model-supplied operator string are not OS identity, and tool arguments are not read.'
const LOOPBACK_CLAIMS = new Set(['127.0.0.1', '::1', 'localhost', '0.0.0.0', '[::1]', '::ffff:127.0.0.1'])

function coded(code, reason) {
  const error = new Error(reason)
  error.code = code
  return error
}

function denial(code, reason) {
  return Object.freeze({ ok: false, code, reason })
}

function defaultRandomId() {
  return `osg_${randomUUID()}`
}

// Loopback addresses, CSRF tokens, and model-supplied operator strings are not
// OS identity. Only platform, userSid or uid, and sessionId are read. `operator`,
// `csrfToken`, `csrf`, `loopback`, `remoteAddress`, `arguments`, and
// `toolArguments` are never identity, including when a model or a tool places a
// SID inside them.
function readHostPrincipal(descriptor) {
  if (typeof descriptor === 'string' || descriptor == null || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
  }
  const platform = canonicalPlatform(descriptor.platform)
  const sessionId = canonicalSession(descriptor.sessionId)
  const sidProvided = Object.prototype.hasOwnProperty.call(descriptor, 'userSid') && descriptor.userSid != null
  const uidProvided = Object.prototype.hasOwnProperty.call(descriptor, 'uid') && descriptor.uid != null
  if (sidProvided && uidProvided) throw coded('AMBIGUOUS_PRINCIPAL', 'supply userSid or uid, not both')
  if (sidProvided) return Object.freeze({ platform, kind: 'sid', id: canonicalSid(descriptor.userSid), sessionId })
  if (uidProvided) return Object.freeze({ platform, kind: 'uid', id: canonicalUid(descriptor.uid), sessionId })
  throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
}

function canonicalPlatform(value) {
  if (typeof value !== 'string') throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
  const platform = value.trim().toLowerCase()
  if (!/^[a-z][a-z0-9._-]{0,31}$/.test(platform)) throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
  return platform
}

function canonicalSession(value) {
  if (typeof value !== 'string') throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
  const sessionId = value.trim()
  if (sessionId.length === 0 || sessionId.length > 256 || sessionId.includes('\0') || isLoopbackClaim(sessionId)) {
    throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
  }
  return sessionId
}

function isLoopbackClaim(value) {
  return LOOPBACK_CLAIMS.has(value.trim().toLowerCase())
}

function canonicalSid(value) {
  if (typeof value !== 'string') throw coded('INVALID_SID', 'userSid must be a Windows SID string from the host')
  const sid = value.trim().toUpperCase()
  if (sid.length === 0 || sid.length > 256 || !/^S-\d+-\d+(-\d+)*$/.test(sid)) {
    throw coded('INVALID_SID', 'userSid must be a Windows SID string from the host')
  }
  return sid
}

function canonicalUid(value) {
  let digits
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw coded('INVALID_UID', 'uid must be a non-negative safe integer from the host')
    digits = String(value)
  } else if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!/^\d+$/.test(trimmed)) throw coded('INVALID_UID', 'uid must be a non-negative safe integer from the host')
    digits = trimmed.replace(/^0+(?=\d)/, '')
  } else {
    throw coded('INVALID_UID', 'uid must be a non-negative safe integer from the host')
  }
  if (digits.length > 16) throw coded('INVALID_UID', 'uid must be a non-negative safe integer from the host')
  const numeric = Number(digits)
  if (!Number.isSafeInteger(numeric) || String(numeric) !== digits) {
    throw coded('INVALID_UID', 'uid must be a non-negative safe integer from the host')
  }
  return digits
}

function readWorkspace(value) {
  if (typeof value !== 'string') throw coded('INVALID_WORKSPACE', 'workspace must be one host-supplied path')
  const workspace = value.trim()
  if (workspace.length === 0 || workspace.length > 4096 || workspace.includes('\0')) {
    throw coded('INVALID_WORKSPACE', 'workspace must be one host-supplied path')
  }
  return workspace
}

function readAction(value) {
  if (typeof value !== 'string') throw coded('INVALID_ACTION', 'action must be one action name')
  const action = value.trim()
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(action)) throw coded('INVALID_ACTION', 'action must be one action name')
  return action
}

function samePrincipal(bound, presented) {
  return bound.platform === presented.platform && bound.kind === presented.kind && bound.id === presented.id
}

function publicGrant(record) {
  return Object.freeze({
    id: record.id,
    platform: record.principal.platform,
    principalKind: record.principal.kind,
    sessionId: record.principal.sessionId,
    workspace: record.workspace,
    action: record.action,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
  })
}

/**
 * @param {{ clock?: () => number, randomId?: () => string, ttlMs?: number }} [options]
 * Clock and randomId are injected so tests stay deterministic. Defaults are
 * local only: `Date.now` and a `crypto.randomUUID` id. Neither contacts a network
 * or reads an OS token.
 */
export function createOsClientIdentity(options = {}) {
  if (options == null || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('options must be an object')
  const clock = options.clock ?? Date.now
  const randomId = options.randomId ?? defaultRandomId
  const ttlMs = options.ttlMs ?? OS_CLIENT_GRANT_TTL_MS
  if (typeof clock !== 'function') throw new TypeError('clock must be a function')
  if (typeof randomId !== 'function') throw new TypeError('randomId must be a function')
  if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) throw coded('INVALID_TTL', 'ttlMs must be a positive finite number')

  const grants = new Map()

  function readClock() {
    const now = clock()
    if (typeof now !== 'number' || !Number.isFinite(now)) throw coded('INVALID_CLOCK', 'clock must return a finite millisecond timestamp')
    return now
  }

  function nextId() {
    const id = randomId()
    if (typeof id !== 'string' || id.length === 0 || id.length > 200 || id.trim() !== id || id.includes('\0')) {
      throw coded('INVALID_GRANT_ID', 'randomId must return a non-empty trimmed string')
    }
    if (grants.has(id)) throw coded('GRANT_ID_COLLISION', 'randomId returned an id that is already in use')
    return id
  }

  function issue(request) {
    if (request == null || typeof request !== 'object' || Array.isArray(request)) throw coded('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
    const principal = readHostPrincipal(request.principal)
    const workspace = readWorkspace(request.workspace)
    const action = readAction(request.action)
    const issuedAt = readClock()
    const expiresAt = issuedAt + ttlMs
    if (!Number.isFinite(expiresAt)) throw coded('INVALID_CLOCK', 'clock must return a finite millisecond timestamp')
    const id = nextId()
    const record = {
      id,
      principal,
      workspace,
      action,
      issuedAt,
      expiresAt,
      revoked: false,
    }
    grants.set(id, record)
    return publicGrant(record)
  }

  function present(request) {
    if (request == null || typeof request !== 'object' || Array.isArray(request)) return denial('OS_PRINCIPAL_REQUIRED', HOST_PRINCIPAL_REASON)
    let principal
    try {
      principal = readHostPrincipal(request.principal)
    } catch (error) {
      return denial(error.code || 'OS_PRINCIPAL_REQUIRED', error.message)
    }
    if (typeof request.grantId !== 'string' || !grants.has(request.grantId)) return denial('GRANT_NOT_FOUND', 'grant was not issued by this boundary')
    const record = grants.get(request.grantId)
    if (!samePrincipal(record.principal, principal)) return denial('PRINCIPAL_MISMATCH', 'OS principal does not match this grant')
    if (record.principal.sessionId !== principal.sessionId) return denial('SESSION_MISMATCH', 'OS session does not match this grant')
    if (record.revoked) return denial('REVOKED', 'grant was revoked')
    let now
    try {
      now = readClock()
    } catch (error) {
      return denial(error.code || 'INVALID_CLOCK', error.message)
    }
    if (now >= record.expiresAt) return denial('EXPIRED', 'grant expired')
    let workspace
    try {
      workspace = readWorkspace(request.workspace)
    } catch {
      return denial('WORKSPACE_MISMATCH', 'workspace does not match this grant')
    }
    if (workspace !== record.workspace) return denial('WORKSPACE_MISMATCH', 'workspace does not match this grant')
    let action
    try {
      action = readAction(request.action)
    } catch {
      return denial('ACTION_MISMATCH', 'action does not match this grant')
    }
    if (action !== record.action) return denial('ACTION_MISMATCH', 'action does not match this grant')
    return Object.freeze({ ok: true, grantId: record.id, workspace: record.workspace, action: record.action, expiresAt: record.expiresAt })
  }

  function revoke(grantId) {
    if (typeof grantId !== 'string' || !grants.has(grantId)) return denial('GRANT_NOT_FOUND', 'grant was not issued by this boundary')
    const record = grants.get(grantId)
    record.revoked = true
    return Object.freeze({ ok: true, grantId: record.id })
  }

  return Object.freeze({ issue, present, revoke })
}
