#!/usr/bin/env node
/** Read-only ArmorBreak Workbench: local HTTP UI over acceptance artifacts. */
import { createServer } from 'node:http'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { isAbsolute } from 'node:path'
import { createEngine } from '../packages/engine-node/index.js'

const HERE = resolve(fileURLToPath(new URL('.', import.meta.url)))
const DEFAULT_ROOT = resolve(HERE, '..')
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const NATIVE_CAPABILITIES = Object.freeze(['host.health', 'host.diagnostics', 'configuration.preview', 'maintenance.plan', 'plugin.verify'])

async function boundedJson(req) {
  const chunks = []; let bytes = 0
  for await (const chunk of req) {
    bytes += chunk.length
    if (bytes > 4096) throw new Error('request exceeds 4096 bytes')
    chunks.push(chunk)
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)) || '{}')
}

function expectedAuthority(host, port) {
  const urlHost = host.includes(':') ? `[${host}]` : host
  return new URL(`http://${urlHost}:${port}/`)
}

function parseAuthority(value) {
  if (typeof value !== 'string' || value.length === 0) return null
  try {
    const url = new URL(`http://${value}/`)
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

function readJson(root, rel, fallback = null) {
  try { return JSON.parse(readFileSync(join(root, rel), 'utf8')) } catch { return fallback }
}

function frontmatter(text) {
  const match = /^---\n([\s\S]*?)\n---\n/.exec(text)
  if (!match) return {}
  const out = {}
  for (const line of match[1].split(/\r?\n/)) {
    const pair = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line)
    if (pair) out[pair[1]] = pair[2].replace(/^['"]|['"]$/g, '')
  }
  return out
}

function taskState(root) {
  const dir = join(root, 'docs/v2/tasks')
  if (!existsSync(dir)) return []
  return readdirSync(dir).filter((name) => /^ABU-\d+\.md$/.test(name)).sort().map((name) => {
    const meta = frontmatter(readFileSync(join(dir, name), 'utf8'))
    return { id: meta.id ?? name.replace('.md', ''), status: meta.status ?? 'UNKNOWN', acceptanceResult: meta.acceptanceResult ?? null, realEndpoint: meta.realEndpoint ?? null }
  })
}

function skillState(root) {
  const dir = join(root, 'skills')
  if (!existsSync(dir)) return []
  return readdirSync(dir, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => {
    try {
      const text = readFileSync(join(dir, entry.name, 'SKILL.md'), 'utf8')
      const meta = frontmatter(text)
      return { name: meta.name ?? entry.name, description: meta.description ?? '' }
    } catch { return null }
  }).filter(Boolean).sort((a, b) => a.name.localeCompare(b.name))
}

function providerVerification(kind) {
  return {
    'openai-compatible': 'MOCK + LOCAL_OLLAMA_REAL; PAID_OPENAI_BLOCKED_EXTERNAL',
    'openai-responses': 'MOCK_GOLDEN; REAL_OPENAI_BLOCKED_EXTERNAL',
    anthropic: 'MOCK_GOLDEN + STREAM_TOOL; REAL_ANTHROPIC_BLOCKED_EXTERNAL',
    gemini: 'MOCK_GOLDEN + STREAM_TOOL; REAL_GEMINI_BLOCKED_EXTERNAL',
    ollama: 'LIVE_LOCAL (qwen3.5:4b)',
    local: 'MOCK_ROUTER',
  }[kind] ?? 'UNKNOWN'
}

export function readState(root = DEFAULT_ROOT) {
  const matrix = readJson(root, 'docs/v2/acceptance/compatibility-matrix.json', { hosts: [] })
  const readiness = readJson(root, 'docs/v2/acceptance/v2.2-readiness.json', { ready: false, blockers: [], waived: [] })
  const providers = readJson(root, 'packages/provider-router/providers.example.json', { providers: [] })
  const artifact = readJson(root, 'docs/v2/acceptance/portable-artifact.json', null)
  const tasks = taskState(root)
  const skills = skillState(root)
  return {
    schemaVersion: 'armorbreak.workbench-state/v1',
    evidenceScope: 'HISTORICAL_ACCEPTANCE_RECORDS',
    generatedAt: new Date().toISOString(),
    readiness: { ready: Boolean(readiness.ready), releaseTag: Boolean(readiness.releaseTag), blockers: readiness.blockers ?? [], waived: readiness.waived ?? [], waiver: readiness.waiver ?? null },
    hosts: (matrix.hosts ?? []).map((host) => ({
      host: host.host, hostVersion: host.hostVersion, integrationMethod: host.integrationMethod,
      installState: host.installState, toolHandshake: host.toolHandshake, taskRunState: host.taskRunState,
      evidenceLevel: host.evidenceLevel, evidenceId: host.evidenceId, limitation: host.limitation,
    })),
    providers: (providers.providers ?? []).map((provider) => ({
      id: provider.id, kind: provider.kind, baseUrl: provider.baseUrl, models: provider.models ?? [],
      supportsTools: Boolean(provider.supportsTools), credentialEnv: provider.apiKeyEnv ?? null,
      credentialPresent: Boolean(provider.apiKeyEnv && process.env[provider.apiKeyEnv]),
      verification: providerVerification(provider.kind),
    })),
    artifact: artifact ? { version: artifact.version, signed: Boolean(artifact.signed), sha256: artifact.sha256 ?? null } : null,
    skills,
    tasks,
    evidence: [
      { title: 'Host model E2E', detail: 'Cursor, WorkBuddy and TRAE real L0 tasks; see docs/v2/acceptance/host-model-e2e-2026-10-22.json' },
      { title: 'Provider live Ollama', detail: 'Local chat, SSE and tool loop; see docs/v2/acceptance/provider-live-ollama.json' },
      { title: 'Test report', detail: 'Commit-bound raw TAP and test-report.json in docs/v2/acceptance' },
      { title: 'Release readiness', detail: `ready=${readiness.ready}; blockers=${(readiness.blockers ?? []).length}; waived=${(readiness.waived ?? []).length}` },
    ],
  }
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.statusCode = status
  res.setHeader('content-type', type)
  res.end(body)
}

export async function createWorkbenchServer({ root = DEFAULT_ROOT, host = '127.0.0.1', port = 0, native = null } = {}) {
  if (!LOOPBACK.has(host)) throw new Error('Workbench must bind loopback')
  let engine = null, ctx = null, busy = false
  const token = randomBytes(32).toString('hex')
  if (native) {
    if (!isAbsolute(native.workspaceId ?? '') || !isAbsolute(native.stateRoot ?? '')) throw new Error('native panel requires explicit absolute workspace and state root')
    const principal = { id: 'workbench-local', kind: 'local-user', workspaces: [native.workspaceId] }
    engine = await createEngine({ stateRoot: native.stateRoot, principals: [principal] })
    ctx = { principal, workspaceId: native.workspaceId, requestId: 'workbench', traceId: randomUUID() }
  }
  const server = createServer(async (req, res) => {
    res.setHeader('cache-control', 'no-store')
    res.setHeader('x-content-type-options', 'nosniff')
    res.setHeader('content-security-policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    const expectedOrigin = expectedAuthority(host, req.socket.localPort)
    const requestAuthority = parseAuthority(req.headers.host)
    if (!requestAuthority || requestAuthority !== expectedOrigin.host) {
      return send(res, 403, JSON.stringify({ error: 'host not allowed' }))
    }
    const origin = req.headers.origin
    if (origin !== undefined) {
      const parsedOrigin = parseOrigin(origin)
      if (!parsedOrigin || parsedOrigin.origin !== expectedOrigin.origin) {
        return send(res, 403, JSON.stringify({ error: 'origin not allowed' }))
      }
    }
    const url = new URL(req.url, `http://${req.headers.host ?? '127.0.0.1'}`)
    if (req.method === 'GET' && url.pathname === '/api/native/session') return send(res, 200, JSON.stringify({ enabled: Boolean(engine), csrf: engine ? token : null, capabilities: engine ? NATIVE_CAPABILITIES : [], state: 'READ_ONLY_CORE', evidenceScope: 'CURRENT_CALL_RESULTS_ONLY' }))
    if (url.pathname === '/api/native/run') {
      if (!engine) return send(res, 503, JSON.stringify({ error: 'native panel not configured' }))
      const provided = req.headers['x-armorbreak-session']
      if (req.method !== 'POST' || typeof provided !== 'string' || !/^[a-f0-9]{64}$/.test(provided) || !timingSafeEqual(Buffer.from(provided), Buffer.from(token)) || req.headers['content-type'] !== 'application/json') return send(res, 403, JSON.stringify({ error: 'session or method rejected' }))
      if (busy) return send(res, 429, JSON.stringify({ error: 'one Core request is already running' }))
      busy = true
      try {
        const input = await boundedJson(req)
        if (!input || Array.isArray(input) || Object.keys(input).some(key => !['capability', 'target', 'expectedVersion'].includes(key)) || !NATIVE_CAPABILITIES.includes(input.capability) || typeof input.target !== 'string' || input.target.length > 2048 || (input.expectedVersion !== undefined && (input.capability !== 'host.health' || typeof input.expectedVersion !== 'string'))) return send(res, 400, JSON.stringify({ error: 'invalid native request' }))
        const result = await engine.analyze({ ...ctx, requestId: randomUUID(), traceId: randomUUID() }, { capability: input.capability, target: input.target, options: input.expectedVersion === undefined ? {} : { expectedVersion: input.expectedVersion } })
        return send(res, 200, JSON.stringify({ taskId: result.taskId, data: result.data, evidenceIds: result.evidenceIds, reportAvailable: Boolean(result.reportPath), hostModified: false }))
      } catch {
        return send(res, 400, JSON.stringify({ error: 'CORE_REQUEST_REJECTED', detail: 'Check the scoped input and local Core audit. Raw paths and input values are not returned.' }))
      } finally { busy = false }
    }
    if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true }))
    if (req.method === 'GET' && url.pathname === '/api/state') return send(res, 200, JSON.stringify(readState(root)))
    if (req.method === 'POST' && url.pathname === '/api/diagnose') {
      let input
      try { input = await boundedJson(req) } catch { return send(res, 400, JSON.stringify({ error: 'invalid or oversized JSON' })) }
      if (input.host) {
        const state = readState(root)
        const row = state.hosts.find((item) => item.host === input.host)
        return send(res, row ? 200 : 404, JSON.stringify(row ? { status: row.taskRunState, handshake: row.toolHandshake, evidence: row.evidenceId, limitation: row.limitation } : { error: 'unknown host' }))
      }
      const state = readState(root)
      const provider = state.providers.find((item) => item.id === input.providerId)
      if (!provider) return send(res, 404, JSON.stringify({ error: 'unknown provider' }))
      const blocked = provider.credentialEnv && !provider.credentialPresent
      return send(res, 200, JSON.stringify({
        provider: provider.id,
        kind: provider.kind,
        status: blocked ? 'BLOCKED_EXTERNAL' : 'CONFIGURED',
        reason: blocked ? `credential env ${provider.credentialEnv} is missing` : 'configuration present; no live call performed by this read-only diagnostic',
        secretRendered: false,
      }))
    }
    if (req.method === 'GET' && ['/', '/index.html', '/app.js', '/style.css'].includes(url.pathname)) {
      const file = url.pathname === '/' || url.pathname === '/index.html' ? 'index.html' : url.pathname.slice(1)
      try {
        const body = readFileSync(join(HERE, file))
        const type = file.endsWith('.css') ? 'text/css; charset=utf-8' : file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/html; charset=utf-8'
        return send(res, 200, body, type)
      } catch { return send(res, 404, 'not found', 'text/plain') }
    }
    return send(res, 404, JSON.stringify({ error: 'not found' }))
  })
  try { await new Promise((resolvePromise, reject) => { server.once('error', reject); server.listen(port, host, resolvePromise) }) } catch (error) { await engine?.close(); throw error }
  return {
    host,
    port: server.address().port,
    url: `http://${host}:${server.address().port}`,
    close: async () => { await new Promise((resolvePromise) => server.close(resolvePromise)); await engine?.close() },
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const index = process.argv.indexOf('--port')
  const port = index >= 0 ? Number(process.argv[index + 1]) : 8787
  const workspaceIndex = process.argv.indexOf('--workspace'), stateIndex = process.argv.indexOf('--state-root')
  if ((workspaceIndex >= 0) !== (stateIndex >= 0)) throw new Error('provide both --workspace and --state-root')
  const native = workspaceIndex >= 0 ? { workspaceId: process.argv[workspaceIndex + 1], stateRoot: process.argv[stateIndex + 1] } : null
  const server = await createWorkbenchServer({ port, native })
  console.log(JSON.stringify({ url: server.url, port: server.port }))
}
