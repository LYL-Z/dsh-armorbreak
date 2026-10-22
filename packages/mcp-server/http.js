/**
 * Minimal MCP Streamable HTTP transport (P2 slice).
 * - loopback-only by default; non-loopback binding must be explicit and is denied here
 * - optional bearer token
 * - POST /mcp, JSON-RPC responses as application/json (no SSE in this slice)
 */
import { createServer } from 'node:http'
import { randomUUID, timingSafeEqual } from 'node:crypto'
import { McpServer } from './index.js'

const MAX_BODY = 1024 * 1024
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])

function bearerMatches(header, token) {
  const supplied = String(header ?? '').replace(/^Bearer\s+/i, '')
  const a = Buffer.from(supplied)
  const b = Buffer.from(token)
  return a.length === b.length && timingSafeEqual(a, b)
}

export async function createMcpHttpServer({ engine, principal, workspaceId, host = '127.0.0.1', port = 0, token = null } = {}) {
  if (!LOOPBACK.has(host)) throw new Error('HTTP MCP must bind loopback by default; remote binding is not enabled')
  if (!engine) throw new Error('engine is required')
  if (!principal?.id || !principal?.kind) throw new Error('trusted principal is required')
  if (!workspaceId) throw new Error('workspaceId is required')
  const mcp = new McpServer({ engine, principal, workspaceId })
  const sessionId = randomUUID()
  const http = createServer(async (req, res) => {
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
    if (token && !bearerMatches(req.headers.authorization, token)) return send(401, { error: 'unauthorized' })
    if (!String(req.headers['content-type'] ?? '').includes('application/json')) return send(415, { error: 'application/json required' })
    let body = ''
    for await (const chunk of req) {
      body += chunk
      if (Buffer.byteLength(body) > MAX_BODY) return send(413, { error: 'request too large' })
    }
    let message
    try { message = JSON.parse(body) } catch { return send(400, { error: 'parse error' }) }
    const response = await mcp.dispatch(message)
    res.setHeader('mcp-session-id', sessionId)
    if (!response) return send(202, { ok: true })
    if (String(req.headers.accept ?? '').includes('text/event-stream')) {
      res.statusCode = 200
      res.setHeader('content-type', 'text/event-stream; charset=utf-8')
      res.setHeader('cache-control', 'no-cache')
      res.end(`event: message\ndata: ${JSON.stringify(response)}\n\n`)
      return
    }
    return send(200, response)
  })
  await new Promise((resolve, reject) => {
    http.once('error', reject)
    http.listen(port, host, resolve)
  })
  return {
    host,
    port: http.address().port,
    url: `http://${host}:${http.address().port}/mcp`,
    async close() { await new Promise((resolve) => http.close(resolve)) },
  }
}
