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
import { readdir, readFile, stat } from 'node:fs/promises'
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

/**
 * List one directory (non-recursive).
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {{workspaceRoot: string, path?: string}} input
 */
export async function listDirectory(scope, input) {
  const targetPath = String(input.path ?? input.workspaceRoot)
  const auth = await authorizePath(scope, input.workspaceRoot, targetPath)
  if (!auth.allowed) return auth
  const info = await stat(auth.resolved)
  if (!info.isDirectory()) return { allowed: false, code: 'NOT_A_DIRECTORY', reason: `not a directory: ${auth.resolved}` }
  const entries = await readdir(auth.resolved, { withFileTypes: true })
  const items = entries
    .slice(0, FILE_TOOL_LIMITS.maxListEntries)
    .map((entry) => ({ name: entry.name, kind: entry.isDirectory() ? 'directory' : entry.isSymbolicLink() ? 'symlink' : 'file' }))
    .sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'directory' ? -1 : 1))
  return {
    allowed: true,
    resolved: auth.resolved,
    data: { path: auth.resolved, entries: items, truncated: entries.length > FILE_TOOL_LIMITS.maxListEntries },
  }
}

/**
 * Read a bounded file and hash exactly the bytes that were read.
 * @param {import('./scope.js').ScopePolicy} scope
 * @param {{workspaceRoot: string, path: string, maxBytes?: number}} input
 */
export async function readFileBounded(scope, input) {
  const auth = await authorizePath(scope, input.workspaceRoot, input.path)
  if (!auth.allowed) return auth
  const info = await stat(auth.resolved)
  if (!info.isFile()) return { allowed: false, code: 'NOT_A_FILE', reason: `not a regular file: ${auth.resolved}` }
  const maxBytes = Math.max(1024, Math.min(Number(input.maxBytes ?? FILE_TOOL_LIMITS.maxReadBytes), FILE_TOOL_LIMITS.maxReadBytes))
  const buffer = await readFile(auth.resolved, { encoding: null })
  const analyzed = buffer.subarray(0, maxBytes)
  const binary = looksBinary(analyzed)
  return {
    allowed: true,
    resolved: auth.resolved,
    data: {
      path: auth.resolved,
      totalBytes: buffer.length,
      analyzedBytes: analyzed.length,
      truncated: buffer.length > analyzed.length,
      hashScope: buffer.length > analyzed.length ? 'analyzed-range' : 'full-file',
      fullFileSha256: buffer.length <= maxBytes ? sha256(buffer) : null,
      analyzedRangeSha256: sha256(analyzed),
      binary,
      text: binary ? null : analyzed.toString('utf8'),
    },
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
  const info = await stat(auth.resolved)
  return {
    allowed: true,
    resolved: auth.resolved,
    data: {
      path: auth.resolved,
      kind: info.isDirectory() ? 'directory' : info.isFile() ? 'file' : 'other',
      size: info.size,
      mtime: info.mtime.toISOString(),
      mode: info.mode,
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
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
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
      const info = await stat(full).catch(() => null)
      if (!info || info.size > FILE_TOOL_LIMITS.maxReadBytes) continue
      const buffer = await readFile(full).catch(() => null)
      if (!buffer || looksBinary(buffer)) continue
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
