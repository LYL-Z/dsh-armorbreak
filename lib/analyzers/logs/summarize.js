/**
 * Offline workspace log summary. Reads one regular UTF-8 file, counts level
 * tokens, and redacts secret-shaped text before any excerpt leaves this module.
 * No process tailing, sockets, or file execution.
 */
import { open, realpath } from 'node:fs/promises'
import { isAbsolute, resolve } from 'node:path'
import { isFilesystemPathWithin } from '../../core/pathBoundary.js'

export const MAX_LOG_BYTES = 1024 * 1024
const MAX_EXCERPTS = 12
const MAX_EXCERPT_CHARS = 500

const LEVELS = ['ERROR', 'WARN', 'INFO', 'DEBUG']
const LIVE_KEY = /tail|follow|live|watch|stream|attach/
const NETWORK_KEY = /socket|network|connect|endpoint|listen/
const EXECUTE_KEY = /execute|exec|spawn|shell|command/

function fail(message) {
  throw new Error(`diagnostics.log_summary ${message}`)
}

function foldKey(key) {
  return String(key).replace(/[_-]/g, '').toLowerCase()
}

function rejectOptions(options) {
  if (options == null) return
  if (typeof options !== 'object' || Array.isArray(options)) fail('refuses malformed options')
  const entries = Object.entries(options)
  if (entries.length === 0) return
  for (const [key, value] of entries) {
    const folded = foldKey(key)
    if (LIVE_KEY.test(folded) || ['pid', 'process'].includes(folded)) fail('refuses to tail a live process')
    if (NETWORK_KEY.test(folded) || ['socket', 'network', 'host', 'port', 'url', 'dns', 'tcp', 'udp'].includes(folded)) {
      fail('refuses to open a network socket')
    }
    if (EXECUTE_KEY.test(folded) || folded === 'run' || folded === 'eval') fail('refuses to execute the file')
    if (typeof value === 'string') {
      const text = value.toLowerCase()
      if (/\b(tail|follow)\b/.test(text)) fail('refuses to tail a live process')
      if (/\b(socket|connect|netcat)\b/.test(text)) fail('refuses to open a network socket')
      if (/\b(execute|exec|spawn|shell)\b/.test(text)) fail('refuses to execute the file')
    }
  }
  fail('accepts no options')
}

export function redactLogText(text) {
  let out = String(text ?? '')
  out = out.replace(/\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA)[A-Z0-9]{16}\b/g, '[REDACTED]')
  out = out.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g, '[REDACTED]')
  out = out.replace(/\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b/g, '[REDACTED]')
  out = out.replace(/\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]')
  out = out.replace(/\b(password|passwd|pwd|token|api[_-]?key|access[_-]?key|secret|authorization|aws_secret_access_key|aws_secret_key|aws_session_token)\b(\s*[:=]\s*)(['"]?)([^\s'"]+)/gi, (_match, key, sep, quote) => `${key}${sep}${quote}[REDACTED]`)
  return out
}

function splitLines(text) {
  if (text.length === 0) return []
  const lines = text.split('\n')
  if (lines[lines.length - 1] === '') lines.pop()
  return lines.map((line) => (line.endsWith('\r') ? line.slice(0, -1) : line))
}

function countLevels(line) {
  const counts = { ERROR: 0, WARN: 0, INFO: 0, DEBUG: 0 }
  for (const match of line.matchAll(/\b(ERROR|WARN|INFO|DEBUG)\b/gi)) counts[match[1].toUpperCase()] += 1
  return counts
}

function clip(line) {
  const redacted = redactLogText(line)
  return redacted.length > MAX_EXCERPT_CHARS ? `${redacted.slice(0, MAX_EXCERPT_CHARS)}…` : redacted
}

export function summarizeLogText(text) {
  const lines = splitLines(text)
  const levels = { ERROR: 0, WARN: 0, INFO: 0, DEBUG: 0 }
  const excerpts = []
  for (const line of lines) {
    const counts = countLevels(line)
    let matched = false
    for (const level of LEVELS) {
      levels[level] += counts[level]
      if (counts[level] > 0) matched = true
    }
    if (matched && excerpts.length < MAX_EXCERPTS) excerpts.push(clip(line))
  }
  return { lineCount: lines.length, levels, excerpts }
}

async function readCapped(file) {
  const handle = await open(file, 'r')
  try {
    const info = await handle.stat()
    if (!info.isFile()) fail('requires a regular file inside the workspace')
    if (info.size > MAX_LOG_BYTES) fail(`refuses oversize input (${info.size} bytes exceeds ${MAX_LOG_BYTES} bytes)`)
    const buf = Buffer.alloc(info.size)
    let offset = 0
    while (offset < buf.length) {
      const { bytesRead } = await handle.read(buf, offset, buf.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    if (offset > MAX_LOG_BYTES) fail(`refuses oversize input (${offset} bytes exceeds ${MAX_LOG_BYTES} bytes)`)
    return buf.subarray(0, offset)
  } finally {
    await handle.close()
  }
}

function decodeLog(bytes) {
  if (bytes.includes(0)) fail('refuses binary input')
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text
  } catch {
    fail('refuses binary input')
  }
}

async function readWorkspaceLog(input) {
  const workspaceRoot = input?.env?.workspaceRoot
  if (typeof workspaceRoot !== 'string' || workspaceRoot.trim() === '') fail('requires a workspace root')
  const requested = input?.targetPath
  if (typeof requested !== 'string' || requested.trim() === '') fail('requires a file inside the workspace')
  const lexicalWorkspace = resolve(workspaceRoot)
  const lexicalTarget = isAbsolute(requested) ? resolve(requested) : resolve(lexicalWorkspace, requested)
  if (!isFilesystemPathWithin(lexicalWorkspace, lexicalTarget)) fail('refuses a path outside the workspace')
  let workspaceReal
  let targetReal
  try {
    workspaceReal = await realpath(lexicalWorkspace)
    targetReal = await realpath(lexicalTarget)
  } catch {
    fail('requires a readable file inside the workspace')
  }
  if (!isFilesystemPathWithin(workspaceReal, targetReal)) fail('refuses a path outside the workspace')
  if (input?.env?.targetTruncated === true || (Number.isFinite(input?.env?.targetSize) && input.env.targetSize > MAX_LOG_BYTES)) {
    fail(`refuses oversize input (${input.env.targetSize ?? 'unknown'} bytes exceeds ${MAX_LOG_BYTES} bytes)`)
  }
  return readCapped(targetReal)
}

export async function summarizeLocalLog(input) {
  rejectOptions(input?.options)
  const bytes = await readWorkspaceLog(input)
  const summary = summarizeLogText(decodeLog(bytes))
  const excerpts = summary.excerpts.map((line) => redactLogText(line))
  const data = {
    lineCount: summary.lineCount,
    levels: summary.levels,
    excerpts,
    bytes: bytes.length,
    redacted: true,
  }
  const excerpt = redactLogText(excerpts.join('\n'))
  const body = redactLogText(JSON.stringify(data, null, 2))
  return {
    summary: `Local log: ${data.lineCount} lines; ERROR ${data.levels.ERROR}, WARN ${data.levels.WARN}, INFO ${data.levels.INFO}, DEBUG ${data.levels.DEBUG}`,
    data,
    evidence: [{ kind: 'log-summary', title: 'Redacted log excerpts', excerpt }],
    artifacts: [{ name: 'log-summary.json', contentType: 'application/json', content: body }],
  }
}
