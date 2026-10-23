/** Independent local Core daemon with a stateRoot lock and MCP HTTP endpoint. */
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { randomBytes } from 'node:crypto'
import { createEngine } from '../engine-node/index.js'
import { createMcpHttpServer } from '../mcp-server/http.js'

function fail(code, message) { const error = new Error(message); error.code = code; return error }

function pidAlive(pid) {
  try { process.kill(pid, 0); return true } catch { return false }
}

export async function createCoreDaemon({ stateRoot, workspace, principal, host = '127.0.0.1', port = 0, mcpToken = null } = {}) {
  if (!stateRoot || !workspace) throw fail('DAEMON_INVALID', 'stateRoot and workspace are required')
  if (!principal?.id) throw fail('DAEMON_INVALID', 'trusted principal is required')
  if (mcpToken !== null && (typeof mcpToken !== 'string' || Buffer.byteLength(mcpToken) < 32)) {
    throw fail('DAEMON_INVALID', 'mcpToken must be at least 32 bytes when supplied')
  }
  const bearerToken = mcpToken ?? randomBytes(32).toString('base64url')
  const lockPath = join(resolve(stateRoot), 'daemon.json')
  if (existsSync(lockPath)) {
    let existing
    try { existing = JSON.parse(readFileSync(lockPath, 'utf8')) } catch { existing = null }
    if (existing?.pid && pidAlive(existing.pid)) throw fail('DAEMON_LOCKED', `daemon already running pid=${existing.pid}`)
    rmSync(lockPath, { force: true })
  }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  let server
  try {
    server = await createMcpHttpServer({ engine, principal, workspaceId: workspace, host, port, token: bearerToken, stateRoot })
  } catch (error) {
    await engine.close()
    throw error
  }
  const info = { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, url: server.url, host, port: server.port, stateRoot: resolve(stateRoot), workspace: resolve(workspace), startedAt: new Date().toISOString() }
  writeFileSync(lockPath, `${JSON.stringify(info, null, 2)}\n`)
  let stopped = false
  const daemon = {
    ...info,
    engine,
    server,
    async stop() {
      if (stopped) return
      stopped = true
      await server.close()
      await engine.close()
      rmSync(lockPath, { force: true })
    },
  }
  // Keep the bearer in memory for the trusted creator; never publish it in daemon.json or enumerable output.
  Object.defineProperty(daemon, 'mcpToken', { value: bearerToken, enumerable: false })
  return daemon
}
