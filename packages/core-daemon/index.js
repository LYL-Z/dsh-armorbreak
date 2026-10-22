/** Independent local Core daemon with a stateRoot lock and MCP HTTP endpoint. */
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { createEngine } from '../engine-node/index.js'
import { createMcpHttpServer } from '../mcp-server/http.js'

function fail(code, message) { const error = new Error(message); error.code = code; return error }

function pidAlive(pid) {
  try { process.kill(pid, 0); return true } catch { return false }
}

export async function createCoreDaemon({ stateRoot, workspace, principal, host = '127.0.0.1', port = 0 } = {}) {
  if (!stateRoot || !workspace) throw fail('DAEMON_INVALID', 'stateRoot and workspace are required')
  if (!principal?.id) throw fail('DAEMON_INVALID', 'trusted principal is required')
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
    server = await createMcpHttpServer({ engine, principal, workspaceId: workspace, host, port })
  } catch (error) {
    await engine.close()
    throw error
  }
  const info = { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, url: server.url, host, port: server.port, stateRoot: resolve(stateRoot), workspace: resolve(workspace), startedAt: new Date().toISOString() }
  writeFileSync(lockPath, `${JSON.stringify(info, null, 2)}\n`)
  let stopped = false
  return {
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
}
