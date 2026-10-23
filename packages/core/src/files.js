/**
 * Policy-gated file access for the ArmorBreak preset.
 *
 * The strict research mode does not mount the generic fs/web/shell tools: every
 * read goes through this bounded reader, which asks ScopePolicy.checkFile first
 * (workspace containment, authorized paths, sensitive-path denial) and marks
 * truncation explicitly. Writes are intentionally not implemented: analysis
 * results are written by the runtime, not by the model.
 * @module dsh-armorbreak/lib/core/files
 */
import { constants } from 'node:fs'
import { lstat, open, readdir, stat } from 'node:fs/promises'
import { realpathSync } from 'node:fs'
import { extname, resolve } from 'node:path'
import { sha256 } from './util.js'

export const FILE_TOOL_LIMITS = Object.freeze({
  maxReadBytes: 262_144,
  maxListEntries: 200,
  maxSearchFiles: 200,
  maxSearchResults: 50,
  maxDepth: 6,
})

/** Extensions considered textual for bounded search. */
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.md', '.txt', '.log', '.xml', '.yml', '.yaml', '.html', '.htm', '.css', '.csv', '.ini', '.conf', '.properties', '.sql', '.py', '.go', '.rs', '.java', '.c', '.h', '.cpp', '.hpp', '.cs', '.php', '.rb', '.sh', '.ps1', '.kt', '.swift', '.toml'])

/** @param {string} p */
function realpathOrResolved(p) {
  try {
    return realpathSync.native(p)
  } catch {
    try {
      return realpathSync(p)
    } catch {
      return resolve(p)
    }
  }
}

/** Reject path forms that have ambiguous or device semantics on Windows. */
export function isUnsafePathForm(value) {
  const text = String(value ?? '')
  if (text.includes('\u0000')) return true
  if (/^\\\\[?.]\\/.test(text)) return true // \\?\ and \\.\ device/namespace paths
  if (/^\\\\[^\\]/.test(text)) return true // UNC \\server\share
  if (/^\/\/[^/]/.test(text)) return true // UNC //server/share (POSIX form)
  return false
}

/**
 * Check a path against the policy and return the resolved real path.
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {string} workspaceRoot
 * @param {string} targetPath
 */
async function authorizePath(scope, workspaceRoot, targetPath) {
  if (isUnsafePathForm(targetPath)) {
    return { allowed: false, code: 'INVALID_PATH_FORM', reason: `refusing ambiguous/device path: ${String(targetPath).slice(0, 200)}` }
  }
  const check = await scope.checkFile({ taskId: 'file-tool', targetPath, workspaceRoot })
  if (!check.allowed) return check
  return { ...check, resolved: check.resolved ?? realpathOrResolved(targetPath) }
}

/** Compare canonical paths without relying on case sensitivity on Windows. */
function samePath(left, right) {
  const a = resolve(left)
  const b = resolve(right)
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b
}

/** Compare the stable file identity exposed by the platform. */
function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino !== 0n && left.ino === right.ino
}

/**
 * Open the path authorized by ScopePolicy and bind later reads to that handle.
 * Reauthorization plus path/handle identity comparison catches path replacement
 * around the open; O_NOFOLLOW additionally rejects a final-component symlink
 * where the platform supports it. Hard links are rejected because their other
 * names cannot be proven to stay inside the authorized tree.
 */
async function openAuthorizedFile(scope, workspaceRoot, targetPath) {
  const auth = await authorizePath(scope, workspaceRoot, targetPath)
  if (!auth.allowed) return { error: auth }

  let handle
  try {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
    handle = await open(auth.resolved, flags)
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile()) {
      await handle.close()
      return { error: { allowed: false, code: 'NOT_A_FILE', reason: `not a regular file: ${auth.resolved}` } }
    }
    if (opened.nlink > 1n) {
      await handle.close()
      return { error: { allowed: false, code: 'HARDLINK_NOT_ALLOWED', reason: 'refusing a file with multiple hard links because its other path cannot be verified' } }
    }

    const finalEntry = await lstat(auth.resolved, { bigint: true })
    if (finalEntry.isSymbolicLink() || !sameFileIdentity(opened, finalEntry)) {
      await handle.close()
      return { error: { allowed: false, code: 'PATH_CHANGED', reason: 'file identity changed while opening the authorized path' } }
    }

    const currentAuth = await authorizePath(scope, workspaceRoot, targetPath)
    if (!currentAuth.allowed) {
      await handle.close()
      return { error: currentAuth }
    }
    if (!samePath(auth.resolved, currentAuth.resolved)) {
      await handle.close()
      return { error: { allowed: false, code: 'PATH_CHANGED', reason: 'path resolved to a different file after authorization' } }
    }

    const currentEntry = await stat(auth.resolved, { bigint: true })
    if (!sameFileIdentity(opened, currentEntry)) {
      await handle.close()
      return { error: { allowed: false, code: 'PATH_CHANGED', reason: 'opened file no longer matches the authorized path' } }
    }
    return { handle, info: opened, resolved: auth.resolved, authorization: auth }
  } catch (error) {
    await handle?.close().catch(() => {})
    const code = error?.code === 'ELOOP' ? 'PATH_CHANGED' : 'FILE_OPEN_FAILED'
    return { error: { allowed: false, code, reason: `could not safely open authorized file: ${error?.message ?? error}` } }
  }
}

/** Read at most `maxBytes + 1` bytes from an already verified handle. */
async function readBoundedHandle(handle, maxBytes) {
  const buffer = Buffer.alloc(maxBytes + 1)
  const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
  return buffer.subarray(0, bytesRead)
}

/** Recheck a directory around enumeration; file contents are opened separately. */
async function readAuthorizedDirectory(scope, workspaceRoot, targetPath, options) {
  const auth = await authorizePath(scope, workspaceRoot, targetPath)
  if (!auth.allowed) return { error: auth }
  try {
    const currentAuth = await authorizePath(scope, workspaceRoot, targetPath)
    if (!currentAuth.allowed) return { error: currentAuth }
    if (!samePath(auth.resolved, currentAuth.resolved)) {
      return { error: { allowed: false, code: 'PATH_CHANGED', reason: 'directory resolved to a different location after authorization' } }
    }
    const before = await lstat(auth.resolved, { bigint: true })
    if (before.isSymbolicLink() || !before.isDirectory()) {
      return { error: { allowed: false, code: 'NOT_A_DIRECTORY', reason: `not a real directory: ${auth.resolved}` } }
    }
    const entries = await readdir(auth.resolved, options)
    const after = await lstat(auth.resolved, { bigint: true })
    const afterAuth = await authorizePath(scope, workspaceRoot, targetPath)
    if (!afterAuth.allowed) return { error: afterAuth }
    if (!samePath(auth.resolved, afterAuth.resolved) || !after.isDirectory() || !sameFileIdentity(before, after)) {
      return { error: { allowed: false, code: 'PATH_CHANGED', reason: 'directory identity changed during enumeration' } }
    }
    return { entries, resolved: auth.resolved }
  } catch (error) {
    return { error: { allowed: false, code: 'DIRECTORY_READ_FAILED', reason: `could not safely enumerate authorized directory: ${error?.message ?? error}` } }
  }
}

/**
 * List one directory (non-recursive).
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {{workspaceRoot: string, path?: string}} input
 */
export async function listDirectory(scope, input) {
  const targetPath = String(input.path ?? input.workspaceRoot)
  const listed = await readAuthorizedDirectory(scope, input.workspaceRoot, targetPath, { withFileTypes: true })
  if (listed.error) return listed.error
  const entries = listed.entries
  const items = entries
    .slice(0, FILE_TOOL_LIMITS.maxListEntries)
    .map((entry) => ({ name: entry.name, kind: entry.isDirectory() ? 'directory' : entry.isSymbolicLink() ? 'symlink' : 'file' }))
    .sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'directory' ? -1 : 1))
  return {
    allowed: true,
    resolved: listed.resolved,
    data: { path: listed.resolved, entries: items, truncated: entries.length > FILE_TOOL_LIMITS.maxListEntries },
  }
}

/**
 * Read a bounded file and hash exactly the bytes that were read.
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {{workspaceRoot: string, path: string, maxBytes?: number}} input
 */
export async function readFileBounded(scope, input) {
  const opened = await openAuthorizedFile(scope, input.workspaceRoot, input.path)
  if (opened.error) return opened.error
  const maxBytes = Math.max(1024, Math.min(Number(input.maxBytes ?? FILE_TOOL_LIMITS.maxReadBytes), FILE_TOOL_LIMITS.maxReadBytes))
  try {
    const analyzed = await readBoundedHandle(opened.handle, maxBytes)
    const binary = looksBinary(analyzed.subarray(0, maxBytes))
    const truncated = opened.info.size > BigInt(analyzed.length) || analyzed.length > maxBytes
    const bytes = analyzed.subarray(0, maxBytes)
    return {
      allowed: true,
      resolved: opened.resolved,
      data: {
        path: opened.resolved,
        totalBytes: Number(opened.info.size),
        analyzedBytes: bytes.length,
        truncated,
        hashScope: truncated ? 'analyzed-range' : 'full-file',
        fullFileSha256: truncated ? null : sha256(bytes),
        analyzedRangeSha256: sha256(bytes),
        binary,
        text: binary ? null : bytes.toString('utf8'),
      },
    }
  } catch (error) {
    return { allowed: false, code: 'FILE_READ_FAILED', reason: `could not read authorized file handle: ${error?.message ?? error}` }
  } finally {
    await opened.handle.close().catch(() => {})
  }
}

/**
 * Stat one path (bounded metadata, no content).
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {{workspaceRoot: string, path: string}} input
 */
export async function statPath(scope, input) {
  const auth = await authorizePath(scope, input.workspaceRoot, input.path)
  if (!auth.allowed) return auth
  let info
  if ((await stat(auth.resolved)).isFile()) {
    const opened = await openAuthorizedFile(scope, input.workspaceRoot, input.path)
    if (opened.error) return opened.error
    info = opened.info
    await opened.handle.close()
  } else {
    const currentAuth = await authorizePath(scope, input.workspaceRoot, input.path)
    if (!currentAuth.allowed) return currentAuth
    if (!samePath(auth.resolved, currentAuth.resolved)) return { allowed: false, code: 'PATH_CHANGED', reason: 'path resolved to a different location after authorization' }
    const finalEntry = await lstat(auth.resolved)
    if (finalEntry.isSymbolicLink()) return { allowed: false, code: 'PATH_CHANGED', reason: 'refusing a symlinked path' }
    info = await stat(auth.resolved)
  }
  return {
    allowed: true,
    resolved: auth.resolved,
    data: {
      path: auth.resolved,
      kind: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other',
      size: Number(info.size),
      mtime: new Date(Number(info.mtimeMs)).toISOString(),
      mode: Number(info.mode),
    },
  }
}

/**
 * Bounded textual search inside the workspace / authorized paths. No symlinks
 * are followed and only text-like extensions are read.
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {{workspaceRoot: string, path?: string, pattern: string, maxResults?: number}} input
 */
export async function searchFiles(scope, input) {
  const root = String(input.path ?? input.workspaceRoot)
  const auth = await authorizePath(scope, input.workspaceRoot, root)
  if (!auth.allowed) return auth
  let expression
  try {
    expression = new RegExp(String(input.pattern), 'i')
  } catch (error) {
    return { allowed: false, code: 'INVALID_PATTERN', reason: `invalid regular expression: ${error?.message ?? error}` }
  }
  const maxResults = Math.max(1, Math.min(Number(input.maxResults ?? FILE_TOOL_LIMITS.maxSearchResults), FILE_TOOL_LIMITS.maxSearchResults))
  /** @type {{file: string, line: number, text: string}[]} */
  const matches = []
  let scanned = 0
  let truncated = false
  /** @param {string} dir @param {number} depth */
  const walk = async (dir, depth) => {
    if (matches.length >= maxResults || truncated) return
    const listed = await readAuthorizedDirectory(scope, input.workspaceRoot, dir, { withFileTypes: true }).catch(() => ({ error: true }))
    if (!listed || listed.error) return
    const entries = listed.entries
    for (const entry of entries) {
      if (matches.length >= maxResults || scanned >= FILE_TOOL_LIMITS.maxSearchFiles) {
        truncated = true
        return
      }
      const full = `${dir}${dir.endsWith('\\') || dir.endsWith('/') ? '' : '/'}${entry.name}`
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) {
        if (depth < FILE_TOOL_LIMITS.maxDepth) await walk(full, depth + 1)
        continue
      }
      if (!entry.isFile() || !TEXT_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue
      const opened = await openAuthorizedFile(scope, input.workspaceRoot, full).catch(() => ({ error: true }))
      if (!opened || opened.error) continue
      let buffer
      try {
        if (opened.info.size > BigInt(FILE_TOOL_LIMITS.maxReadBytes)) continue
        buffer = await readBoundedHandle(opened.handle, FILE_TOOL_LIMITS.maxReadBytes)
      } catch {
        continue
      } finally {
        await opened.handle.close().catch(() => {})
      }
      if (!buffer || buffer.length > FILE_TOOL_LIMITS.maxReadBytes || looksBinary(buffer)) continue
      scanned += 1
      const lines = buffer.toString('utf8').split(/\r?\n/)
      for (let index = 0; index < lines.length; index += 1) {
        if (expression.test(lines[index])) {
          matches.push({ file: full, line: index + 1, text: lines[index].slice(0, 300) })
          if (matches.length >= maxResults) {
            truncated = true
            break
          }
        }
      }
      if (truncated) return
    }
  }
  await walk(auth.resolved, 0)
  return {
    allowed: true,
    data: {
      root: auth.resolved,
      pattern: String(input.pattern),
      matches,
      scannedFiles: scanned,
      truncated: truncated || scanned >= FILE_TOOL_LIMITS.maxSearchFiles,
    },
  }
}

/** @param {Buffer} buffer */
function looksBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192))
  if (sample.includes(0)) return true
  let printable = 0
  for (const byte of sample) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) || byte >= 128) printable += 1
  }
  return sample.length > 0 && printable / sample.length < 0.85
}
