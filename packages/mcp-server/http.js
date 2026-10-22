/**
 * MCP Streamable HTTP transport (P2).
 * - loopback-only by default; non-loopback binding is denied here
 * - optional bearer token(s); token can map to a trusted principal/workspace
 * - recoverable sessions persisted in stateRoot
 * - POST /mcp, JSON or SSE response
 */
import { createServer } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { randomUUID, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { McpServer } from './index.js'

const MAX_BODY = 1024 * 1024
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000

function bearerMatches(header, token) {
  const supplied = String(header ?? '').replace(/^Bearer\s+/i, '')
  const a = Buffer.from(supplied)
  const b = Buffer.from(token)
  return a.length === b.length && timingSafeEqual(a, b)
}

function identityKey(principalId, workspaceId) {
  return `${principalId}\0${workspaceId}`
}

export async function createMcpHttpServer({
  engine, principal, workspaceId, host = '127.0.0.1', port = 0,
  token = null, tokens = null, principals = null, tls = null,
  stateRoot = null, sessionTtlMs = DEFAULT_TTL_MS,
} = {}) {
  if (!LOOPBACK.has(host)) throw new Error('HTTP MCP must bind loopback by default; remote binding is not enabled')
  if (!engine) throw new Error('engine is required')
  if (!principal?.id || !principal?.kind) throw new Error('trusted principal is required')
  if (!workspaceId) throw new Error('workspaceId is required')
  if (tls && (!tls.key || !tls.cert)) throw new Error('tls requires key and cert')
  if (!Number.isInteger(sessionTtlMs) || sessionTtlMs < 1000) throw new Error('sessionTtlMs must be >= 1000')
  const knownPrincipals = Array.isArray(principals) && principals.length > 0 ? principals : [principal]
  const defaultIdentity = { principal, workspaceId }
  const identities = new Map()
  const normalizeIdentity = (value) => {
    const principalId = typeof value === 'string' ? value : value?.principalId
    const nextWorkspace = typeof value === 'object' && value?.workspaceId ? String(value.workspaceId) : workspaceId
    const found = knownPrincipals.find((item) => item.id === principalId)
    if (!found) throw new Error(`token maps to an unknown principal: ${String(principalId)}`)
    return { principal: found, workspaceId: nextWorkspace }
  }
  if (tokens) {
    for (const [value, target] of Object.entries(tokens)) identities.set(value, normalizeIdentity(target))
  }
  const sessions = new Map()
  const servers = new Map()
  const defaultSessions = new Map()
  const sessionsFile = stateRoot ? resolve(join(stateRoot, 'mcp-http-sessions.json')) : null
  if (sessionsFile && existsSync(sessionsFile)) {
    try {
      const stored = JSON.parse(readFileSync(sessionsFile, 'utf8'))
      for (const session of stored.sessions ?? []) {
        if (typeof session?.id === 'string' && typeof session.principalId === 'string' && typeof session.workspaceId === 'string') sessions.set(session.id, session)
      }
      for (const [key, id] of Object.entries(stored.defaults ?? {})) defaultSessions.set(key, id)
    } catch { /* a corrupt session file starts clean */ }
  }
  const persist = () => {
    if (!sessionsFile) return
    try {
      mkdirSync(resolve(stateRoot), { recursive: true })
      writeFileSync(sessionsFile, `${JSON.stringify({ schemaVersion: 'armorbreak.mcp-http-sessions/v1', sessions: [...sessions.values()], defaults: Object.fromEntries(defaultSessions) }, null, 2)}\n`)
    } catch { /* persistence must never break the protocol */ }
  }
  const resolveIdentity = (req) => {
    if (tokens && identities.size > 0) {
      const supplied = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '')
      for (const [value, identity] of identities) if (bearerMatches(req.headers.authorization, value)) return identity
      if (supplied) return null
      return null
    }
    if (token) return bearerMatches(req.headers.authorization, token) ? defaultIdentity : null
    return defaultIdentity
  }
  const sessionAlive = (session) => Boolean(session) && Date.now() - Date.parse(session.updatedAt) <= sessionTtlMs
  const bindServer = (session) => {
    const key = identityKey(session.principalId, session.workspaceId)
    if (servers.has(session.id)) return servers.get(session.id)
    const found = knownPrincipals.find((item) => item.id === session.principalId)
    if (!found) return null
    const server = new McpServer({ engine, principal: found, workspaceId: session.workspaceId })
    server.initialized = Boolean(session.initialized)
    servers.set(session.id, server)
    return server
  }
  const createSession = (identity, initialized = false) => {
    const session = {
      id: randomUUID(), principalId: identity.principal.id, workspaceId: identity.workspaceId,
      initialized, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    }
    sessions.set(session.id, session)
    defaultSessions.set(identityKey(session.principalId, session.workspaceId), session.id)
    persist()
    return session
  }
  const defaultSession = (identity) => {
    const key = identityKey(identity.principal.id, identity.workspaceId)
    const existing = sessions.get(defaultSessions.get(key))
    if (sessionAlive(existing) && existing.principalId === identity.principal.id) return existing
    return createSession(identity)
  }
  const handler = async (req, res) => {
    const send = (status, value) => {
      res.statusCode = status
      res.setHeader('content-type', 'application/json; charset=utf-8')
      res.end(JSON.stringify(value))
    }
    if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true })
    if (req.method !== 'POST' || req.url !== '/mcp') return send(404, { error: 'not found' })
    const hostName = String(req.headers.host ?? '').replace(/^\[|\](?=:)|:\d+$/g, '')
    if (!LOOPBACK.has(hostName)) return send(403, { error: 'host not allowed' })
    const origin = req.headers.origin
    if (origin) {
      try { if (!LOOPBACK.has(new URL(String(origin)).hostname)) return send(403, { error: 'origin not allowed' }) } catch { return send(403, { error: 'origin not allowed' }) }
    }
    const identity = resolveIdentity(req)
    if (!identity) return send(401, { error: 'unauthorized' })
    if (!String(req.headers['content-type'] ?? '').includes('application/json')) return send(415, { error: 'application/json required' })
    let session
    const requestedSession = req.headers['mcp-session-id']
    if (requestedSession) {
      session = sessions.get(String(requestedSession))
      if (!sessionAlive(session)) return send(404, { error: 'session not found' })
      if (session.principalId !== identity.principal.id || session.workspaceId !== identity.workspaceId) return send(403, { error: 'session identity mismatch' })
    } else {
      session = defaultSession(identity)
    }
    const server = bindServer(session)
    if (!server) return send(403, { error: 'session principal is no longer trusted' })
    let body = ''
    for await (const chunk of req) {
      body += chunk
      if (Buffer.byteLength(body) > MAX_BODY) return send(413, { error: 'request too large' })
    }
    let message
    try { message = JSON.parse(body) } catch { return send(400, { error: 'parse error' }) }
    const response = await server.dispatch(message)
    session.initialized = server.initialized
    session.updatedAt = new Date().toISOString()
    persist()
    res.setHeader('mcp-session-id', session.id)
    if (!response) return send(202, { ok: true })
    if (String(req.headers.accept ?? '').includes('text/event-stream')) {
      res.statusCode = 200
      res.setHeader('content-type', 'text/event-stream; charset=utf-8')
      res.setHeader('cache-control', 'no-cache')
      res.end(`event: message\ndata: ${JSON.stringify(response)}\n\n`)
      return
    }
    return send(200, response)
  }
  const http = tls ? createHttpsServer(tls, handler) : createServer(handler)
  await new Promise((resolvePromise, reject) => {
    http.once('error', reject)
    http.listen(port, host, resolvePromise)
  })
  return {
    host,
    port: http.address().port,
    url: `${tls ? 'https' : 'http'}://${host}:${http.address().port}/mcp`,
    stateRoot: stateRoot ? resolve(stateRoot) : null,
    async close() { persist(); await new Promise((resolvePromise) => http.close(resolvePromise)) },
  }
}
