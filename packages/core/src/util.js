/**
 * ArmorBreak core utilities: ids, time, atomic files, JSONL, redaction, paths, bytes.
 * Zero dependencies; Node builtins only.
 * @module dsh-armorbreak/lib/core/util
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { mkdir, lstat, open, readFile, realpath, rename, stat, writeFile } from 'node:fs/promises'
import { constants } from 'node:fs'
import { dirname, isAbsolute, join, normalize, relative, resolve, sep } from 'node:path'
import { homedir } from 'node:os'

/** Minutes in ms. */
export const MINUTE = 60_000
/** Hours in ms. */
export const HOUR = 60 * MINUTE
/** MiB in bytes. */
export const MiB = 1024 * 1024

/** ISO timestamp for now. */
export function nowIso() {
  return new Date().toISOString()
}

/**
 * Create a prefixed, sortable, collision-resistant id.
 * @param {string} prefix
 * @returns {string}
 */
export function newId(prefix) {
  const stamp = Date.now().toString(36)
  const rand = randomBytes(4).toString('hex')
  return `${prefix}_${stamp}_${rand}`
}

/**
 * SHA-256 hex digest of bytes or a string.
 * @param {Buffer|Uint8Array|string} input
 * @returns {string}
 */
export function sha256(input) {
  return createHash('sha256').update(input).digest('hex')
}

/**
 * Stable JSON serialization (sorted object keys) used for hashing.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  return JSON.stringify(sortValue(value))
}

/** @param {unknown} value @returns {unknown} */
function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue)
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {}
    for (const key of Object.keys(value).sort()) out[key] = sortValue(/** @type {any} */ (value)[key])
    return out
  }
  return value
}

/** @param {string} file */
export async function ensureDir(file) {
  await mkdir(file, { recursive: true })
}

/**
 * Windows occasionally holds a just-written destination (AV/indexer); retry
 * transient rename failures instead of turning a successful write into a task
 * failure. Non-transient errors still surface immediately.
 */
async function renameWithRetry(from, to) {
  let lastError = null
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      await rename(from, to)
      return
    } catch (error) {
      lastError = error
      const code = /** @type {any} */ (error)?.code
      if (!['EPERM', 'EACCES', 'EBUSY', 'ENOTEMPTY'].includes(code)) throw error
      await new Promise((resolve) => setTimeout(resolve, 20 * (attempt + 1)))
    }
  }
  throw lastError
}

/**
 * Write JSON atomically (temp sibling + rename).
 * @param {string} file
 * @param {unknown} value
 */
export async function writeJsonAtomic(file, value) {
  await mkdir(dirname(file), { recursive: true })
  const tmp = `${file}.${randomBytes(4).toString('hex')}.tmp`
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8')
  await renameWithRetry(tmp, file)
}

/**
 * Read JSON, returning fallback when the file is absent or unreadable.
 * @param {string} file
 * @param {any} fallback
 */
export async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(file, 'utf8'))
  } catch {
    return fallback
  }
}

/**
 * Append one JSON record as a line.
 * @param {string} file
 * @param {unknown} record
 */
export async function appendJsonl(file, record) {
  await mkdir(dirname(file), { recursive: true })
  const { appendFile } = await import('node:fs/promises')
  await appendFile(file, `${JSON.stringify(record)}\n`, 'utf8')
}

/** Per-file in-process mutex chain (serializes read-tail → append critical sections). */
const FILE_MUTEXES = new Map()

/**
 * Run one critical section exclusively for a file path inside this process.
 * The audit/evidence stores perform a read-tail → compute-hash → append cycle;
 * without serialization two overlapping appends would fork the hash chain.
 * @template T
 * @param {string} file
 * @param {() => Promise<T>} task
 * @returns {Promise<T>}
 */
export async function withFileMutex(file, task) {
  const key = normalize(file)
  const prior = FILE_MUTEXES.get(key) ?? Promise.resolve()
  /** @type {() => void} */
  let release = () => {}
  const gate = new Promise((resolveGate) => {
    release = () => resolveGate(undefined)
  })
  const tail = prior.then(() => gate)
  FILE_MUTEXES.set(key, tail)
  await prior.catch(() => {})
  try {
    return await task()
  } finally {
    release()
    if (FILE_MUTEXES.get(key) === tail) FILE_MUTEXES.delete(key)
  }
}

/**
 * Read JSONL records with a bounded count (latest N).
 * @param {string} file
 * @param {{limit?: number}} [opts]
 * @returns {Promise<any[]>}
 */
export async function readJsonl(file, opts = {}) {
  const limit = opts.limit ?? 500
  let text = ''
  try {
    text = await readFile(file, 'utf8')
  } catch {
    return []
  }
  const lines = text.split('\n').filter((line) => line.trim() !== '')
  const sliced = lines.length > limit ? lines.slice(lines.length - limit) : lines
  /** @type {any[]} */
  const out = []
  for (const line of sliced) {
    try {
      out.push(JSON.parse(line))
    } catch {
      /* a torn line must not invalidate the rest of the log */
    }
  }
  return out
}

/**
 * Read at most maxBytes of a file (never loads larger than the cap).
 * @param {string} file
 * @param {number} maxBytes
 * @param {{authorize?: (path: string) => Promise<{allowed: boolean, resolved?: string, code?: string, reason?: string}>}} [options]
 * @returns {Promise<{buffer: Buffer, truncated: boolean, size: number}>}
 */
export async function readBounded(file, maxBytes, options = {}) {
  const targetPath = resolve(file)
  const canonicalPath = await realpath(targetPath)
  const authorize = async () => {
    if (!options.authorize) return
    const decision = await options.authorize(targetPath)
    if (!decision?.allowed) {
      const error = new Error(decision?.reason ?? 'file path is outside the authorized scope')
      error.code = decision?.code ?? 'FILE_SCOPE_DENIED'
      throw error
    }
    if (decision.resolved) {
      const authorizedPath = resolve(decision.resolved)
      const sameAuthorizedPath = process.platform === 'win32'
        ? authorizedPath.toLowerCase() === canonicalPath.toLowerCase()
        : authorizedPath === canonicalPath
      if (!sameAuthorizedPath) {
        const error = new Error('file resolved to a different path than the one authorized')
        error.code = 'PATH_CHANGED'
        throw error
      }
    }
  }
  await authorize()
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
  const handle = await open(canonicalPath, flags)
  try {
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile()) throw new Error('refusing to read a non-regular file')
    if (opened.nlink > 1n) throw new Error('refusing to read a file with multiple hard links')

    const pathEntry = await lstat(canonicalPath, { bigint: true })
    if (pathEntry.isSymbolicLink() || pathEntry.dev !== opened.dev || pathEntry.ino === 0n || pathEntry.ino !== opened.ino) {
      throw new Error('file identity changed while opening the path')
    }
    const currentCanonicalPath = await realpath(targetPath)
    const sameCanonicalPath = process.platform === 'win32'
      ? currentCanonicalPath.toLowerCase() === canonicalPath.toLowerCase()
      : currentCanonicalPath === canonicalPath
    if (!sameCanonicalPath) throw new Error('path resolved to a different file after opening')
    const currentPathEntry = await stat(canonicalPath, { bigint: true })
    if (currentPathEntry.dev !== opened.dev || currentPathEntry.ino !== opened.ino) {
      throw new Error('opened file no longer matches the authorized path')
    }
    await authorize()

    const limit = Number.isFinite(Number(maxBytes)) ? Math.max(0, Math.floor(Number(maxBytes))) : 0
    const buffer = Buffer.alloc(limit + 1)
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
    const truncated = opened.size > BigInt(bytesRead) || bytesRead > limit
    return { buffer: buffer.subarray(0, Math.min(bytesRead, limit)), truncated, size: Number(opened.size) }
  } finally {
    await handle.close()
  }
}

/**
 * Resolve the DSH home directory.
 * @returns {string}
 */
export function resolveDshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

/**
 * Root directory for ArmorBreak process-level state (authorizations, caches).
 * Per-workspace task data lives inside the analyzed workspace instead.
 * @returns {string}
 */
export function resolveStateRoot() {
  return process.env.ARMORBREAK_HOME || join(resolveDshHome(), 'armorbreak')
}

/**
 * Normalize a user-supplied path against a base directory.
 * @param {string} input
 * @param {string} [base]
 * @returns {string}
 */
export function resolvePath(input, base = process.cwd()) {
  if (!input || typeof input !== 'string') throw new Error('path must be a non-empty string')
  return normalize(isAbsolute(input) ? input : resolve(base, input))
}

/**
 * True when `child` is inside `parent` (case-insensitive on Windows, path-boundary safe).
 * @param {string} parent
 * @param {string} child
 * @returns {boolean}
 */
export function isPathInside(parent, child) {
  const rel = relative(normalize(parent), normalize(child))
  if (rel === '') return true
  if (rel.startsWith('..')) return false
  return !isAbsolute(rel) && !rel.split(/[\\/]/).includes('..')
}

/**
 * Strip control characters (except newline/tab), collapse excessive whitespace, cap length.
 * @param {unknown} value
 * @param {number} [max]
 * @returns {string}
 */
export function sanitizeText(value, max = 4000) {
  let text = typeof value === 'string' ? value : String(value ?? '')
  text = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
  text = text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
  text = text.replace(/[ \t]{6,}/g, '    ')
  text = text.replace(/\n{4,}/g, '\n\n\n')
  if (text.length > max) text = `${text.slice(0, max)}\n…[truncated ${text.length - max} chars]`
  return text
}

/** Keys whose values must never reach logs, reports, or the model verbatim. */
const SENSITIVE_KEY = /(authorization|cookie|set-cookie|api[_-]?key|secret|token|passw(or)?d|passwd|private[_-]?key|credential|session[_-]?id|jwt|bearer)/i
/** Common literal secret shapes. */
const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED PRIVATE KEY]'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/g, '[REDACTED JWT]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED AWS ACCESS KEY]'],
  [/\bbearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, 'Bearer [REDACTED]'],
  [/\b(ghp|gho|ghs|ghu)_[A-Za-z0-9]{20,}\b/g, '[REDACTED GITHUB TOKEN]'],
  [/\bsk-[A-Za-z0-9]{16,}\b/g, '[REDACTED API KEY]'],
]

/**
 * Redact likely credentials from a text excerpt.
 * @param {string} text
 * @returns {string}
 */
export function redactText(text) {
  let out = String(text ?? '')
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement)
  out = out.replace(
    /\b(authorization|cookie|set-cookie|api[_-]?key|secret|token|password|passwd|private[_-]?key|credential)\b(\s*[:=]\s*)("?)([^\s"'&;]{3,})/gi,
    (_m, key, sep, quote) => `${key}${sep}${quote}[REDACTED]`,
  )
  return out
}

/**
 * Deep-redact sensitive object keys for audit/report payloads.
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {unknown}
 */
export function redactDeep(value, depth = 0) {
  if (depth > 8) return '[depth-limit]'
  if (Array.isArray(value)) return value.slice(0, 200).map((item) => redactDeep(item, depth + 1))
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {}
    for (const [key, inner] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key)) {
        out[key] = typeof inner === 'string' ? '[REDACTED]' : '[REDACTED]'
      } else {
        out[key] = redactDeep(inner, depth + 1)
      }
    }
    return out
  }
  if (typeof value === 'string') return redactText(sanitizeText(value, 800))
  return value
}

/**
 * Shannon entropy in bits/byte for a buffer slice.
 * @param {Buffer|Uint8Array} buffer
 * @returns {number}
 */
export function shannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < buffer.length; i += 1) counts[buffer[i]] += 1
  let entropy = 0
  const total = buffer.length
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue
    const p = counts[i] / total
    entropy -= p * Math.log2(p)
  }
  return Math.round(entropy * 1000) / 1000
}

/**
 * Human-readable byte count.
 * @param {number} bytes
 */
export function humanBytes(bytes) {
  if (!Number.isFinite(bytes)) return 'n/a'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`
}

/** @param {number} ms */
export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return 'n/a'
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.floor(ms / 60_000)} min ${Math.round((ms % 60_000) / 1000)} s`
}

/**
 * Escape text for embedding in generated HTML.
 * @param {unknown} value
 */
export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/**
 * Cumulative HMAC-free hash chain helper: hash of (prevHash + canonical payload).
 * @param {string} prevHash
 * @param {unknown} payload
 */
export function chainHash(prevHash, payload) {
  return sha256(`${prevHash}\n${canonicalJson(payload)}`)
}

/**
 * Detect whether a buffer looks textual (mostly printable ASCII/UTF-8).
 * @param {Buffer|Uint8Array} buffer
 * @param {number} [sample]
 */
export function looksTextual(buffer, sample = 4096) {
  const end = Math.min(buffer.length, sample)
  if (end === 0) return true
  let printable = 0
  for (let i = 0; i < end; i += 1) {
    const byte = buffer[i]
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127) || byte >= 0x80) printable += 1
  }
  return printable / end > 0.85
}

/**
 * Decode bytes as UTF-8 while replacing invalid sequences.
 * @param {Buffer|Uint8Array} buffer
 */
export function textOf(buffer) {
  return Buffer.from(buffer).toString('utf8')
}

/**
 * Guard against path names that escape the workspace prefix.
 * @param {string} root
 * @param {string} candidate
 * @returns {{ok: boolean, resolved: string, reason?: string}}
 */
export function assertInside(root, candidate) {
  const resolvedRoot = resolve(root)
  const resolved = resolve(candidate)
  if (!isPathInside(resolvedRoot, resolved)) {
    return { ok: false, resolved, reason: `path escapes root: ${resolved} is outside ${resolvedRoot}` }
  }
  return { ok: true, resolved }
}

/** Path separator used by the host platform. */
export const PATH_SEP = sep
