/**
 * MCP Streamable HTTP transport (P2).
 * - loopback-only by default; non-loopback binding is denied here
 * - bearer token(s) required by default; token can map to a trusted principal/workspace
 * - unauthenticated loopback mode requires an explicit development opt-in
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

function authorityUrl(scheme, host, port) {
  const urlHost = host.includes(':') ? `[${host}]` : host
  return new URL(`${scheme}//${urlHost}:${port}/`)
}

function parseAuthority(value, scheme) {
  if (typeof value !== 'string' || value.length === 0) return null
  try {
    const url = new URL(`${scheme}//${value}/`)
    if (url.origin === 'null' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null
    return url.host
  } catch {
    return null
  }
}

function parseOrigin(value) {
  if (typeof value !== 'string' || value.length === 0) return null
  try {
    const url = new URL(value)
    if (url.origin === 'null' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) return null
    return url
  } catch {
    return null
  }
}

export async function createMcpHttpServer({
  engine, principal, workspaceId, host = '127.0.0.1', port = 0,
  token = null, tokens = null, principals = null, tls = null,
  allowUnauthenticatedLoopback = false,
  stateRoot = null, sessionTtlMs = DEFAULT_TTL_MS,
} = {}) {
  if (!LOOPBACK.has(host)) throw new Error('HTTP MCP must bind loopback by default; remote binding is not enabled')
  if (!engine) throw new Error('engine is required')
  if (!principal?.id || !principal?.kind) throw new Error('trusted principal is required')
  if (!workspaceId) throw new Error('workspaceId is required')
  if (tls && (!tls.key || !tls.cert)) throw new Error('tls requires key and cert')
  if (typeof allowUnauthenticatedLoopback !== 'boolean') throw new Error('allowUnauthenticatedLoopback must be a boolean')
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
  const sessionsFile = stateRoot ? resolve(join(stateRoot, 'mcp-http-sessions.json')) : null
  if (sessionsFile && existsSync(sessionsFile)) {
    try {
      const stored = JSON.parse(readFileSync(sessionsFile, 'utf8'))
      for (const session of stored.sessions ?? []) {
        if (typeof session?.id === 'string' && typeof session.principalId === 'string' && typeof session.workspaceId === 'string') sessions.set(session.id, session)
      }
    } catch { /* a corrupt session file starts clean */ }
  }
  const persist = () => {
    if (!sessionsFile) return
    try {
      mkdirSync(resolve(stateRoot), { recursive: true })
      writeFileSync(sessionsFile, `${JSON.stringify({ schemaVersion: 'armorbreak.mcp-http-sessions/v1', sessions: [...sessions.values()] }, null, 2)}\n`)
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
    return allowUnauthenticatedLoopback ? defaultIdentity : null
  }
  const sessionAlive = (session) => Boolean(session) && Number.isFinite(Date.parse(session.updatedAt)) && Date.now() - Date.parse(session.updatedAt) <= sessionTtlMs
  const bindServer = (session) => {
    if (servers.has(session.id)) return servers.get(session.id)
    const found = knownPrincipals.find((item) => item.id === session.principalId)
    if (!found) return null
    const server = new McpServer({ engine, principal: found, workspaceId: session.workspaceId, connectionId: session.id })
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
    persist()
    return session
  }
  const handler = async (req, res) => {
    const send = (status, value) => {
      res.statusCode = status
      res.setHeader('content-type', 'application/json; charset=utf-8')
      res.end(JSON.stringify(value))
    }
    const scheme = tls ? 'https:' : 'http:'
    const localPort = req.socket.localPort
    const expectedOrigin = authorityUrl(scheme, host, localPort)
    const requestAuthority = parseAuthority(req.headers.host, scheme)
    if (!requestAuthority || requestAuthority !== expectedOrigin.host) return send(403, { error: 'host not allowed' })
    const origin = req.headers.origin
    if (origin !== undefined) {
      const parsedOrigin = parseOrigin(origin)
      if (!parsedOrigin || parsedOrigin.origin !== expectedOrigin.origin) return send(403, { error: 'origin not allowed' })
    }
    if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true })
    if (req.method !== 'POST' || req.url !== '/mcp') return send(404, { error: 'not found' })
    const identity = resolveIdentity(req)
    if (!identity) return send(401, { error: 'unauthorized' })
    if (!String(req.headers['content-type'] ?? '').includes('application/json')) return send(415, { error: 'application/json required' })
    let body = ''
    for await (const chunk of req) {
      body += chunk
      if (Buffer.byteLength(body) > MAX_BODY) return send(413, { error: 'request too large' })
    }
    let message
    try { message = JSON.parse(body) } catch { return send(400, { error: 'parse error' }) }
    let session
    const requestedSession = req.headers['mcp-session-id']
    if (requestedSession) {
      session = sessions.get(String(requestedSession))
      if (!sessionAlive(session)) return send(404, { error: 'session not found' })
      if (session.principalId !== identity.principal.id || session.workspaceId !== identity.workspaceId) return send(403, { error: 'session identity mismatch' })
    } else if (message?.method === 'initialize') {
      session = createSession(identity)
    } else {
      return send(400, { error: 'mcp-session-id required; initialize a new session first' })
    }
    const server = bindServer(session)
    if (!server) return send(403, { error: 'session principal is no longer trusted' })
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
