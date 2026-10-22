#!/usr/bin/env node
/** Local overhead benchmark: CLI startup, Core capabilities, MCP HTTP roundtrip. */
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { cpus } from 'node:os'
import { createEngine } from '../../packages/engine-node/index.js'
import { createMcpHttpServer } from '../../packages/mcp-server/http.js'

const args = process.argv.slice(2)
const iterationIndex = args.indexOf('--iterations')
const iterations = Math.max(2, Math.min(20, Number(iterationIndex >= 0 ? args[iterationIndex + 1] : 5) || 5))
const stateRoot = await mkdtemp(join(tmpdir(), 'abm-bench-state-'))
const workspace = await mkdtemp(join(tmpdir(), 'abm-bench-ws-'))
const principal = { id: 'bench', kind: 'local-user', workspaces: [workspace] }
const pct = (values, p) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] }
const summarize = (values) => ({ p50: Number(pct(values, 50).toFixed(2)), p95: Number(pct(values, 95).toFixed(2)), min: Number(Math.min(...values).toFixed(2)), max: Number(Math.max(...values).toFixed(2)) })

const cli = []
const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace }
for (let i = 0; i < iterations; i += 1) {
  const start = performance.now()
  const result = spawnSync(process.execPath, ['packages/cli/index.js', 'capabilities', '--json'], { cwd: process.cwd(), env, encoding: 'utf8' })
  if (result.status !== 0) throw new Error(`CLI benchmark failed: ${result.stderr}`)
  cli.push(performance.now() - start)
}

const engine = await createEngine({ stateRoot, principals: [principal] })
const ctx = { principal: { id: 'bench', kind: 'local-user' }, workspaceId: workspace, requestId: 'bench', traceId: 'bench' }
const core = []
let payloadBytes = 0
for (let i = 0; i < iterations; i += 1) {
  const start = performance.now()
  const caps = await engine.capabilities(ctx)
  core.push(performance.now() - start)
  payloadBytes = Buffer.byteLength(JSON.stringify(caps))
}
const server = await createMcpHttpServer({ engine, principal, workspaceId: workspace })
const http = []
try {
  await fetch(server.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }) })
  for (let i = 0; i < iterations; i += 1) {
    const start = performance.now()
    const response = await fetch(server.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 10 + i, method: 'tools/call', params: { name: 'armorbreak_capabilities', arguments: {} } }) })
    if (!response.ok) throw new Error(`HTTP benchmark failed: ${response.status}`)
    http.push(performance.now() - start)
  }
} finally {
  await server.close()
  await engine.close()
  await rm(stateRoot, { recursive: true, force: true })
  await rm(workspace, { recursive: true, force: true })
}
const report = {
  schemaVersion: 'armorbreak.overhead-benchmark/v1',
  hardware: { platform: process.platform, arch: process.arch, cpu: cpus()[0]?.model ?? 'unknown', node: process.version },
  iterations,
  metrics: { cliStartupMs: summarize(cli), coreCapabilitiesMs: summarize(core), httpCapabilitiesMs: summarize(http), capabilitiesPayloadBytes: payloadBytes },
  realModelCalls: false,
  limitations: ['No provider/model calls; this measures local Core/CLI/MCP overhead only.', 'Timings vary by machine load and are not a cross-host benchmark.'],
}
console.log(JSON.stringify(report, null, 2))
