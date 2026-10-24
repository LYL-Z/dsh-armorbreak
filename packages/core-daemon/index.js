/** Independent local Core daemon with a stateRoot lock and MCP HTTP endpoint. */
import { closeSync, fstatSync, fsyncSync, ftruncateSync, linkSync, lstatSync, mkdirSync, openSync, readdirSync, realpathSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { basename, dirname, join, parse, resolve, sep } from 'node:path'
import { randomBytes, randomUUID } from 'node:crypto'
import { createEngine } from '../engine-node/index.js'
import { createMcpHttpServer } from '../mcp-server/http.js'
import { readSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

function fail(code, message) { const error = new Error(message); error.code = code; return error }

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

function sameDirectoryIdentity(left, right) {
  return left.dev === right.dev && left.ino !== 0n && left.ino === right.ino
}

function ensureRealStateDirectory(stateRoot) {
  const absolute = resolve(stateRoot)
  const root = parse(absolute).root
  const identities = [{ path: root, info: lstatSync(root, { bigint: true }) }]
  let current = root

  for (const part of absolute.slice(root.length).split(sep).filter(Boolean)) {
    const next = join(current, part)
    const parentBefore = lstatSync(current, { bigint: true })
    let info
    try {
      info = lstatSync(next, { bigint: true })
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
      try { mkdirSync(next) } catch (mkdirError) {
        if (mkdirError?.code !== 'EEXIST') throw mkdirError
      }
      const parentAfter = lstatSync(current, { bigint: true })
      if (parentAfter.isSymbolicLink() || !sameDirectoryIdentity(parentBefore, parentAfter)) {
        throw fail('DAEMON_PATH_UNSAFE', `daemon state parent changed while creating: ${current}`)
      }
      info = lstatSync(next, { bigint: true })
    }

    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state path contains a symlink, junction, or non-directory: ${next}`)
    }
    let canonical
    try { canonical = realpathSync(next) } catch (error) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state directory cannot be resolved safely: ${error.message}`)
    }
    if (!samePath(canonical, next)) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state directory resolves through a symlink or junction: ${next}`)
    }
    identities.push({ path: next, info })
    current = next
  }

  return { path: absolute, identities }
}

function assertStateDirectoryStable(snapshot) {
  for (const prior of snapshot.identities) {
    let latest
    try { latest = lstatSync(prior.path, { bigint: true }) } catch (error) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state path changed during startup: ${error.message}`)
    }
    if (latest.isSymbolicLink() || !latest.isDirectory() || !sameDirectoryIdentity(prior.info, latest)) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state path changed during startup: ${prior.path}`)
    }
    let canonical
    try { canonical = realpathSync(prior.path) } catch (error) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state path cannot be resolved during startup: ${error.message}`)
    }
    if (!samePath(canonical, prior.path)) {
      throw fail('DAEMON_PATH_UNSAFE', `daemon state path resolves through a symlink or junction: ${prior.path}`)
    }
  }
}

function assertLockDescriptorAtPath(lockPath, descriptor, identity) {
  let pathInfo
  try { pathInfo = lstatSync(lockPath, { bigint: true }) } catch (error) {
    throw fail('DAEMON_LOCK_UNSAFE', `daemon lock path changed during startup: ${error.message}`)
  }
  const opened = fstatSync(descriptor, { bigint: true })
  if (pathInfo.isSymbolicLink() || !pathInfo.isFile() || pathInfo.nlink !== 1n
    || !sameDirectoryIdentity(pathInfo, identity) || !sameDirectoryIdentity(opened, identity)) {
    throw fail('DAEMON_LOCK_UNSAFE', 'daemon lock path no longer names the exclusively opened lock file')
  }
}

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

  // Replacing a stale lock by path would let a swapped stateRoot redirect the
  // rename/delete to a different directory after readLock validated the old one.
  // Require explicit operator recovery until we have a platform-safe,
  // directory-handle-relative stale-lock operation.
  throw fail('DAEMON_LOCK_STALE', 'stale daemon lock found; automatic replacement is disabled; verify no daemon is running before removing the lock')
}

function removeOwnedLock(lockPath, descriptor, identity) {
  const opened = fstatSync(descriptor, { bigint: true })
  let source
  try {
    source = lstatSync(lockPath, { bigint: true })
  } catch (error) {
    if (error?.code === 'ENOENT') return
    throw error
  }
  if (source.isSymbolicLink() || !source.isFile() || source.nlink !== 1n
    || source.dev !== identity.dev || source.ino === 0n || source.ino !== identity.ino
    || opened.dev !== identity.dev || opened.ino !== identity.ino) return

  const tombstone = `${lockPath}.${process.pid}.${randomUUID()}.stopped`
  try {
    renameSync(lockPath, tombstone)
  } catch (error) {
    if (error?.code === 'ENOENT') return
    throw error
  }
  try {
    let movedPath = tombstone
    let moved
    try {
      moved = lstatSync(movedPath, { bigint: true })
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
      // On WSL DrvFS, renaming through a parent junction can move the entry
      // while making the junction-relative tombstone temporarily unresolvable.
      // The source path was checked against the open descriptor immediately
      // before the atomic rename. Readdir confirms the unique tombstone entry
      // exists, then the link at that canonical path is removed.
      const canonicalParent = realpathSync(dirname(lockPath))
      movedPath = join(canonicalParent, basename(tombstone))
      if (!readdirSync(canonicalParent).includes(basename(tombstone))) return
      unlinkSync(movedPath)
      return
    }
    if (moved.isSymbolicLink() || !moved.isFile() || moved.nlink !== 1n
      || moved.dev !== identity.dev || moved.ino === 0n || moved.ino !== identity.ino
      || opened.dev !== identity.dev || opened.ino !== identity.ino) {
      try {
        // linkSync fails atomically if another daemon already owns lockPath.
        linkSync(movedPath, lockPath)
        unlinkSync(movedPath)
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error
      }
      return
    }
    unlinkSync(movedPath)
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
  const stateSnapshot = ensureRealStateDirectory(stateRoot)
  const stateDirectory = stateSnapshot.path
  const lockPath = join(stateDirectory, 'daemon.json')
  const lockDescriptor = acquireLock(stateDirectory, lockPath)
  const lockIdentity = fstatSync(lockDescriptor, { bigint: true })
  const startedAt = new Date().toISOString()
  let engine
  let server
  try {
    // The lock is created with an exclusive file open. Re-check the complete
    // stateRoot chain and the opened lock pathname before writing workspace
    // metadata or initializing any state below it. This closes the junction
    // swap window between initial path validation and lock creation.
    assertStateDirectoryStable(stateSnapshot)
    assertLockDescriptorAtPath(lockPath, lockDescriptor, lockIdentity)
    writeLockDescriptor(lockDescriptor, { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, stateRoot: stateDirectory, workspace: resolve(workspace), startedAt, status: 'starting' })
    assertStateDirectoryStable(stateSnapshot)
    assertLockDescriptorAtPath(lockPath, lockDescriptor, lockIdentity)
    engine = await createEngine({ stateRoot: stateDirectory, principals: [principal] })
    assertStateDirectoryStable(stateSnapshot)
    server = await createMcpHttpServer({ engine, principal, workspaceId: workspace, host, port, token: bearerToken, stateRoot: stateDirectory })
    const info = { schemaVersion: 'armorbreak.core-daemon/v1', pid: process.pid, url: server.url, host, port: server.port, stateRoot: stateDirectory, workspace: resolve(workspace), startedAt }
    assertStateDirectoryStable(stateSnapshot)
    assertLockDescriptorAtPath(lockPath, lockDescriptor, lockIdentity)
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
