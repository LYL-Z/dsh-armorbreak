/** Independent local Core daemon with a stateRoot lock and MCP HTTP endpoint. */
import { closeSync, fstatSync, fsyncSync, ftruncateSync, linkSync, lstatSync, mkdirSync, openSync, renameSync, rmSync, unlinkSync, writeSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { createEngine } from '../engine-node/index.js'
import { createMcpHttpServer } from '../mcp-server/http.js'
import { readSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

function fail(code, message) { const error = new Error(message); error.code = code; return error }

function pidAlive(pid) {
  try { process.kill(pid, 0); return true } catch { return false }
}

function writeLockDescriptor(descriptor, info) {
  const bytes = Buffer.from(`${JSON.stringify(info, null, 2)}\n`)
  ftruncateSync(descriptor, 0)
  let offset = 0
  while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset, offset)
  fsyncSync(descriptor)
}

function readLock(stateRoot, relativePath = 'daemon.json') {
  let bytes
  try { bytes = readSafeRepoFile(stateRoot, relativePath, { maxBytes: 64 * 1024 }) } catch (error) {
    if (error?.code === 'ENOENT') return null
    throw fail('DAEMON_LOCK_UNSAFE', `daemon lock cannot be read safely: ${error.message}`)
  }
  let parsed
  try { parsed = JSON.parse(bytes.toString('utf8')) } catch {
    throw fail('DAEMON_LOCK_INVALID', 'daemon lock is not valid JSON; refusing to replace it')
  }
  if (!Number.isSafeInteger(parsed?.pid) || parsed.pid < 1) throw fail('DAEMON_LOCK_INVALID', 'daemon lock has no valid process id; refusing to replace it')
  return parsed
}

function acquireLock(stateRoot, lockPath) {
  try { return openSync(lockPath, 'wx+', 0o600) } catch (error) {
    if (error?.code !== 'EEXIST') throw error
  }

  const existing = readLock(stateRoot)
  if (!existing) {
    try { return openSync(lockPath, 'wx+', 0o600) } catch (error) {
      if (error?.code === 'EEXIST') throw fail('DAEMON_LOCKED', 'another daemon acquired the lock during startup')
      throw error
    }
  }
  if (pidAlive(existing.pid)) throw fail('DAEMON_LOCKED', `daemon already running pid=${existing.pid}`)

  // Move the verified stale entry out of the acquisition name before deleting it.
  // A second starter can then win the exclusive create, but cannot be overwritten.
  const staleName = `daemon.json.${process.pid}.${randomUUID()}.stale`
  const stalePath = join(stateRoot, staleName)
  try { renameSync(lockPath, stalePath) } catch (error) {
    if (error?.code === 'ENOENT') throw fail('DAEMON_LOCKED', 'daemon lock changed during stale-lock recovery; retry startup')
    throw error
  }
  const moved = readLock(stateRoot, staleName)
  if (!moved || moved.pid !== existing.pid || moved.startedAt !== existing.startedAt || pidAlive(moved.pid)) {
    throw fail('DAEMON_LOCKED', 'daemon lock changed during stale-lock recovery; refusing to replace it')
  }
  rmSync(stalePath)
  try { return openSync(lockPath, 'wx+', 0o600) } catch (error) {
    if (error?.code === 'EEXIST') throw fail('DAEMON_LOCKED', 'another daemon acquired the lock during startup')
    throw error
  }
}

function removeOwnedLock(lockPath, descriptor, identity) {
  const tombstone = `${lockPath}.${process.pid}.${randomUUID()}.stopped`
  try {
    renameSync(lockPath, tombstone)
  } catch (error) {
    if (error?.code === 'ENOENT') return
    throw error
  }
  try {
    const moved = lstatSync(tombstone, { bigint: true })
    const opened = fstatSync(descriptor, { bigint: true })
    if (moved.isSymbolicLink() || !moved.isFile() || moved.nlink !== 1n
      || moved.dev !== identity.dev || moved.ino === 0n || moved.ino !== identity.ino
      || opened.dev !== identity.dev || opened.ino !== identity.ino) {
      try {
        // linkSync fails atomically if another daemon already owns lockPath.
        linkSync(tombstone, lockPath)
        unlinkSync(tombstone)
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error
      }
      return
    }
    unlinkSync(tombstone)
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
}

export async function createCoreDaemon({ stateRoot, workspace, principal, host = '127.0.0.1', port = 0, mcpToken = null } = {}) {
  if (!stateRoot || !workspace) throw fail('DAEMON_INVALID', 'stateRoot and workspace are required')
  if (!principal?.id) throw fail('DAEMON_INVALID', 'trusted principal is required')
  if (mcpToken !== null && (typeof mcpToken !== 'string' || Buffer.byteLength(mcpToken) < 32)) {
    throw fail('DAEMON_INVALID', 'mcpToken must be at least 32 bytes when supplied')
  }
  const bearerToken = mcpToken ?? randomBytes(32).toString('base64url')
  const stateDirectory = resolve(stateRoot)
  mkdirSync(stateDirectory, { recursive: true })
  const lockPath = join(stateDirectory, 'daemon.json')
  const lockDescriptor = acquireLock(stateDirectory, lockPath)
  const lockIdentity = fstatSync(lockDescriptor, { bigint: true })
  const startedAt = new Date().toISOString()
  let engine
  let server
  try {
    writeLockDescriptor(lockDescriptor, { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, stateRoot: stateDirectory, workspace: resolve(workspace), startedAt, status: 'starting' })
    engine = await createEngine({ stateRoot: stateDirectory, principals: [principal] })
    server = await createMcpHttpServer({ engine, principal, workspaceId: workspace, host, port, token: bearerToken, stateRoot: stateDirectory })
    const info = { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, url: server.url, host, port: server.port, stateRoot: stateDirectory, workspace: resolve(workspace), startedAt }
    writeLockDescriptor(lockDescriptor, info)
  } catch (error) {
    if (server) await server.close().catch(() => {})
    if (engine) await engine.close().catch(() => {})
    removeOwnedLock(lockPath, lockDescriptor, lockIdentity)
    closeSync(lockDescriptor)
    throw error
  }
  const info = { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, url: server.url, host, port: server.port, stateRoot: stateDirectory, workspace: resolve(workspace), startedAt }
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
      removeOwnedLock(lockPath, lockDescriptor, lockIdentity)
      closeSync(lockDescriptor)
    },
  }
  // Keep the bearer in memory for the trusted creator; never publish it in daemon.json or enumerable output.
  Object.defineProperty(daemon, 'mcpToken', { value: bearerToken, enumerable: false })
  return daemon
}
