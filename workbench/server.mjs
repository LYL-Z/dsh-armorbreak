#!/usr/bin/env node
/** Read-only ArmorBreak Workbench: local HTTP UI over acceptance artifacts. */
import { createServer } from 'node:http'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = resolve(fileURLToPath(new URL('.', import.meta.url)))
const DEFAULT_ROOT = resolve(HERE, '..')
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])

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

export async function createWorkbenchServer({ root = DEFAULT_ROOT, host = '127.0.0.1', port = 0 } = {}) {
  if (!LOOPBACK.has(host)) throw new Error('Workbench must bind loopback')
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host ?? '127.0.0.1'}`)
    if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, JSON.stringify({ ok: true }))
    if (req.method === 'GET' && url.pathname === '/api/state') return send(res, 200, JSON.stringify(readState(root)))
    if (req.method === 'POST' && url.pathname === '/api/diagnose') {
      let body = ''
      for await (const chunk of req) body += chunk
      let input
      try { input = JSON.parse(body || '{}') } catch { return send(res, 400, JSON.stringify({ error: 'invalid JSON' })) }
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
  await new Promise((resolvePromise, reject) => { server.once('error', reject); server.listen(port, host, resolvePromise) })
  return {
    host,
    port: server.address().port,
    url: `http://${host}:${server.address().port}`,
    close: () => new Promise((resolvePromise) => server.close(resolvePromise)),
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const index = process.argv.indexOf('--port')
  const port = index >= 0 ? Number(process.argv[index + 1]) : 8787
  const server = await createWorkbenchServer({ port })
  console.log(JSON.stringify({ url: server.url, port: server.port }))
}
