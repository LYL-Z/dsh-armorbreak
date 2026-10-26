/**
 * Bounded, read-only artifact intake and archive indexing.
 * No target payload is executed and archive members are never written to disk.
 */
import { createHash } from 'node:crypto'
import { gunzipSync, inflateRawSync } from 'node:zlib'
import { extname } from 'node:path'
import { byteStats, sanitizeText } from '../binary/util.js'

export const DETECTOR_VERSION = 'armorbreak-artifact-intake/0.1.0'

const ZIP_EOCD = 0x06054b50
const ZIP_CENTRAL = 0x02014b50
const ZIP_LOCAL = 0x04034b50
const TAR_BLOCK = 512
const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i += 1) {
    let value = i
    for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
    table[i] = value >>> 0
  }
  return table
})()

const SOURCE_EXTENSIONS = new Map(Object.entries({
  '.c': 'C', '.h': 'C/C++ header', '.cc': 'C++', '.cpp': 'C++', '.cxx': 'C++', '.hpp': 'C++',
  '.rs': 'Rust', '.go': 'Go', '.java': 'Java', '.kt': 'Kotlin', '.kts': 'Kotlin', '.js': 'JavaScript',
  '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.jsx': 'JavaScript', '.ts': 'TypeScript', '.mts': 'TypeScript',
  '.cts': 'TypeScript', '.tsx': 'TypeScript', '.cs': 'C#', '.swift': 'Swift', '.py': 'Python', '.pyw': 'Python',
  '.php': 'PHP', '.rb': 'Ruby', '.lua': 'Lua', '.sh': 'Shell', '.bash': 'Shell', '.zsh': 'Shell',
  '.ps1': 'PowerShell', '.dart': 'Dart', '.ets': 'ArkTS', '.sql': 'SQL', '.html': 'HTML', '.htm': 'HTML',
  '.css': 'CSS', '.scss': 'SCSS', '.graphql': 'GraphQL', '.gql': 'GraphQL', '.yaml': 'YAML', '.yml': 'YAML',
  '.json': 'JSON', '.toml': 'TOML', '.xml': 'XML', '.tf': 'HCL', '.nix': 'Nix', '.v': 'Verilog',
  '.sv': 'SystemVerilog', '.vhd': 'VHDL', '.vhdl': 'VHDL', '.glsl': 'GLSL', '.wgsl': 'WGSL',
  '.hlsl': 'HLSL', '.sol': 'Solidity', '.move': 'Move', '.wasm': 'WebAssembly', '.class': 'JVM bytecode',
  '.dex': 'DEX bytecode', '.pyc': 'Python bytecode', '.hap': 'HarmonyOS package', '.aab': 'Android App Bundle',
  '.ipa': 'iOS application package', '.apk': 'Android package', '.jar': 'JVM package', '.war': 'JVM package',
}))

const FIXED_MAGIC = [
  { bytes: Buffer.from('%PDF-', 'ascii'), type: 'pdf', category: 'document', confidence: 0.99 },
  { bytes: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), type: 'png', category: 'image', confidence: 0.99 },
  { bytes: Buffer.from([0xff, 0xd8, 0xff]), type: 'jpeg', category: 'image', confidence: 0.99 },
  { bytes: Buffer.from('GIF87a', 'ascii'), type: 'gif', category: 'image', confidence: 0.99 },
  { bytes: Buffer.from('GIF89a', 'ascii'), type: 'gif', category: 'image', confidence: 0.99 },
  { bytes: Buffer.from('SQLite format 3\0', 'binary'), type: 'sqlite', category: 'database', confidence: 0.99 },
]

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function startsWith(buffer, bytes, offset = 0) {
  return Buffer.isBuffer(buffer) && buffer.length >= offset + bytes.length && buffer.subarray(offset, offset + bytes.length).equals(bytes)
}

function addCandidate(candidates, type, category, confidence, reason, details = {}) {
  if (!candidates.some((item) => item.type === type && item.reason === reason)) {
    candidates.push({ type, category, confidence, reason, ...details })
  }
}

function printableFragmentCount(buffer, minLength = 4) {
  let count = 0
  let run = 0
  for (const byte of buffer) {
    const printable = (byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d
    if (printable) run += 1
    else {
      if (run >= minLength) count += 1
      run = 0
    }
  }
  if (run >= minLength) count += 1
  return count
}

function hasUtf8Text(buffer) {
  if (!buffer.length || buffer.includes(0)) return null
  const sample = buffer.subarray(0, Math.min(buffer.length, 256 * 1024))
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(sample)
    const controls = (text.match(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g) || []).length
    return controls / Math.max(1, text.length) <= 0.02 ? text : null
  } catch {
    return null
  }
}

function isMachOFat(buffer) {
  if (buffer.length < 28) return false
  const magic = buffer.subarray(0, 4).toString('hex')
  const little = magic === 'bebafeca' || magic === 'bfbafeca'
  const wide = magic === 'cafebabf' || magic === 'bfbafeca'
  if (!['cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'].includes(magic)) return false
  const count = little ? buffer.readUInt32LE(4) : buffer.readUInt32BE(4)
  if (count < 1 || count > 64) return false
  const entrySize = wide ? 32 : 20
  if (8 + count * entrySize > buffer.length) return false
  for (let i = 0; i < count; i += 1) {
    const offset = 8 + i * entrySize
    const sliceOffset = wide
      ? Number(little ? buffer.readBigUInt64LE(offset + 8) : buffer.readBigUInt64BE(offset + 8))
      : (little ? buffer.readUInt32LE(offset + 8) : buffer.readUInt32BE(offset + 8))
    const sliceSize = wide
      ? Number(little ? buffer.readBigUInt64LE(offset + 16) : buffer.readBigUInt64BE(offset + 16))
      : (little ? buffer.readUInt32LE(offset + 12) : buffer.readUInt32BE(offset + 12))
    if (!Number.isSafeInteger(sliceOffset) || !Number.isSafeInteger(sliceSize) || sliceOffset < 8 + count * entrySize || sliceSize < 4 || sliceOffset + sliceSize > buffer.length) return false
  }
  return true
}

function parseTarNumber(buffer, offset, width) {
  if (offset + width > buffer.length) return null
  const raw = buffer.subarray(offset, offset + width)
  if (raw[0] & 0x80) return null // base-256 numbers are deliberately unsupported
  const value = raw.toString('ascii').replace(/\0.*$/s, '').trim()
  if (!value) return 0
  if (!/^[0-7]+$/.test(value)) return null
  const parsed = Number.parseInt(value, 8)
  return Number.isSafeInteger(parsed) ? parsed : null
}

function isTarHeader(buffer, offset = 0) {
  if (buffer.length < offset + TAR_BLOCK) return false
  const stored = parseTarNumber(buffer, offset + 148, 8)
  if (stored === null) return false
  let sum = 0
  for (let i = 0; i < TAR_BLOCK; i += 1) sum += (i >= 148 && i < 156) ? 0x20 : buffer[offset + i]
  const magic = buffer.subarray(offset + 257, offset + 263).toString('ascii')
  return sum === stored && (magic === 'ustar\0' || magic === 'ustar ' || stored > 0)
}

function decodeZipName(raw, utf8) {
  if (!utf8) return raw.toString('latin1')
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(raw)
  } catch {
    return null
  }
}

function safeArchivePath(rawName) {
  if (typeof rawName !== 'string' || rawName.length === 0 || rawName.includes('\0')) return { safe: false, reason: 'EMPTY_OR_NUL_PATH' }
  if (rawName.includes('\\')) return { safe: false, reason: 'BACKSLASH_PATH' }
  if (rawName.startsWith('/') || rawName.startsWith('//') || /^[A-Za-z]:/.test(rawName)) return { safe: false, reason: 'ABSOLUTE_PATH' }
  if (/^[A-Za-z]:/.test(rawName) || /(^|\/)[^/]*:[^/]*(\/|$)/.test(rawName)) return { safe: false, reason: 'WINDOWS_ADS_OR_DRIVE_PATH' }
  if (/[\u0001-\u001f\u007f]/.test(rawName)) return { safe: false, reason: 'CONTROL_CHARACTER_PATH' }
  const directory = rawName.endsWith('/')
  const parts = rawName.split('/')
  if (directory) parts.pop()
  const normalized = []
  for (const part of parts) {
    if (part === '' || part === '.') {
      if (part === '' && normalized.length > 0) return { safe: false, reason: 'EMPTY_PATH_COMPONENT' }
      continue
    }
    if (part === '..') return { safe: false, reason: 'PARENT_PATH_COMPONENT' }
    if (/[. ]$/.test(part)) return { safe: false, reason: 'WINDOWS_ALIAS_COMPONENT' }
    if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part)) return { safe: false, reason: 'WINDOWS_RESERVED_NAME' }
    normalized.push(part.normalize('NFC'))
  }
  if (!normalized.length) return { safe: false, reason: 'EMPTY_NORMALIZED_PATH' }
  return { safe: true, path: normalized.join('/'), isDirectory: directory }
}

function collisionKey(path) {
  return path.normalize('NFC').toLocaleLowerCase('en-US')
}

function collisionReason(path, seen, isDirectory = false) {
  const key = collisionKey(path)
  if (seen.has(key)) return 'CASE_OR_UNICODE_COLLISION'
  for (const [prior, details] of seen) {
    if (key.startsWith(`${prior}/`) && !details.isDirectory) return 'FILE_DIRECTORY_COLLISION'
    if (prior.startsWith(`${key}/`) && !isDirectory) return 'FILE_DIRECTORY_COLLISION'
  }
  seen.set(key, { path, isDirectory })
  return null
}

function findZipEocd(buffer) {
  const start = Math.max(0, buffer.length - 65_557)
  for (let offset = buffer.length - 22; offset >= start; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== ZIP_EOCD) continue
    const commentLength = buffer.readUInt16LE(offset + 20)
    if (offset + 22 + commentLength === buffer.length) return offset
  }
  return -1
}

/** Parse central-directory metadata only; no decompression occurs here. */
export function readZipIndex(buffer, maxEntries = 1000) {
  const out = { ok: false, status: 'MALFORMED', entries: [], warnings: [], declaredEntries: null, complete: false, centralOffset: null }
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) {
    out.warnings.push('ZIP is shorter than the minimum end record.')
    return out
  }
  const eocd = findZipEocd(buffer)
  if (eocd < 0) {
    out.warnings.push('ZIP end record is absent or the archive is truncated.')
    return out
  }
  const disk = buffer.readUInt16LE(eocd + 4)
  const centralDisk = buffer.readUInt16LE(eocd + 6)
  const diskCount = buffer.readUInt16LE(eocd + 8)
  const totalCount = buffer.readUInt16LE(eocd + 10)
  const centralSize = buffer.readUInt32LE(eocd + 12)
  const centralOffset = buffer.readUInt32LE(eocd + 16)
  out.declaredEntries = totalCount
  out.centralOffset = centralOffset
  if (totalCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    out.status = 'UNSUPPORTED_ZIP64'
    out.warnings.push('ZIP64 is recognized but is not expanded by this bounded intake parser.')
    return out
  }
  if (disk !== 0 || centralDisk !== 0 || diskCount !== totalCount) {
    out.status = 'UNSUPPORTED_MULTIDISK'
    out.warnings.push('Multi-disk ZIP archives are not traversed.')
    return out
  }
  const centralEnd = centralOffset + centralSize
  if (centralOffset < 0 || centralEnd > eocd || centralEnd < centralOffset) {
    out.warnings.push('Central directory bounds are inconsistent with the end record.')
    return out
  }
  const seen = new Map()
  let offset = centralOffset
  const limit = Math.min(totalCount, Math.max(1, Math.min(10_000, Math.floor(maxEntries))))
  for (let index = 0; index < limit; index += 1) {
    if (offset + 46 > centralEnd || buffer.readUInt32LE(offset) !== ZIP_CENTRAL) {
      out.status = 'PARTIAL_MALFORMED'
      out.warnings.push(`Central directory record ${index} is truncated or has an invalid signature.`)
      break
    }
    const madeBy = buffer.readUInt16LE(offset + 4)
    const flags = buffer.readUInt16LE(offset + 8)
    const method = buffer.readUInt16LE(offset + 10)
    const crc32 = buffer.readUInt32LE(offset + 16)
    const compressedSize = buffer.readUInt32LE(offset + 20)
    const uncompressedSize = buffer.readUInt32LE(offset + 24)
    const nameLength = buffer.readUInt16LE(offset + 28)
    const extraLength = buffer.readUInt16LE(offset + 30)
    const commentLength = buffer.readUInt16LE(offset + 32)
    const diskStart = buffer.readUInt16LE(offset + 34)
    const externalAttributes = buffer.readUInt32LE(offset + 38)
    const localHeaderOffset = buffer.readUInt32LE(offset + 42)
    const recordEnd = offset + 46 + nameLength + extraLength + commentLength
    if (recordEnd > centralEnd || nameLength === 0) {
      out.status = 'PARTIAL_MALFORMED'
      out.warnings.push(`Central directory record ${index} has invalid variable fields.`)
      break
    }
    const rawName = buffer.subarray(offset + 46, offset + 46 + nameLength)
    const name = decodeZipName(rawName, Boolean(flags & 0x0800))
    const os = madeBy >>> 8
    const unixMode = externalAttributes >>> 16
    const unixType = unixMode & 0xf000
    const dosReparse = Boolean(externalAttributes & 0x400)
    let typeStatus = 'OK'
    let isDirectory = Boolean(name?.endsWith('/'))
    if (!name) typeStatus = 'INVALID_UTF8_NAME'
    if (os === 3 && unixType === 0xa000) typeStatus = 'REJECTED_SYMLINK'
    else if (os === 3 && unixType && unixType !== 0x8000 && unixType !== 0x4000) typeStatus = 'REJECTED_SPECIAL_FILE'
    else if (dosReparse) typeStatus = 'REJECTED_REPARSE_POINT'
    if (os === 3 && unixType === 0x4000) isDirectory = true
    const pathInfo = safeArchivePath(name ?? '')
    let pathStatus = pathInfo.safe ? null : pathInfo.reason
    if (pathInfo.safe) pathStatus = collisionReason(pathInfo.path, seen, isDirectory || pathInfo.isDirectory)
    if (diskStart !== 0 && typeStatus === 'OK') typeStatus = 'UNSUPPORTED_MULTIDISK_ENTRY'
    out.entries.push({
      index,
      name: name ?? `<invalid-utf8-${index}>`,
      path: pathInfo.safe ? pathInfo.path : null,
      pathStatus,
      typeStatus,
      isDirectory,
      flags,
      method,
      crc32,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      rawName,
      centralOs: os,
    })
    offset = recordEnd
  }
  if (out.status === 'MALFORMED' && totalCount <= limit && offset !== centralEnd) {
    out.status = 'PARTIAL_MALFORMED'
    out.warnings.push('Central directory size does not match the declared entry records.')
  }
  if (out.status === 'MALFORMED') {
    out.ok = true
  }
  if (out.ok && totalCount > limit) {
    out.status = 'ENTRY_LIMIT'
    out.warnings.push(`Archive declares ${totalCount} entries; indexed ${limit} within the entry budget.`)
  } else if (out.ok) {
    out.status = 'OK'
  }
  out.complete = out.status === 'OK' && out.entries.length === totalCount
  return out
}

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function zipEntryBytes(buffer, entry, centralOffset, budget) {
  if (entry.pathStatus || entry.typeStatus !== 'OK') return { status: entry.pathStatus ? `REJECTED_${entry.pathStatus}` : entry.typeStatus, bytes: null }
  if (entry.isDirectory) return { status: 'DIRECTORY', bytes: Buffer.alloc(0) }
  if (entry.flags & (0x0001 | 0x0040 | 0x2000)) return { status: 'UNSUPPORTED_ENCRYPTED', bytes: null }
  const supportedFlags = 0x0808 | (entry.method === 8 ? 0x0006 : 0)
  if (entry.flags & ~supportedFlags) return { status: 'UNSUPPORTED_FLAGS', bytes: null }
  if (entry.uncompressedSize > budget.maxEntryBytes) return { status: 'ENTRY_SIZE_LIMIT', bytes: null }
  if (entry.uncompressedSize > budget.maxExpandedBytes - budget.expandedBytes) return { status: 'EXPANSION_BUDGET', bytes: null }
  const ratio = entry.compressedSize === 0 ? (entry.uncompressedSize === 0 ? 1 : Infinity) : entry.uncompressedSize / entry.compressedSize
  if (ratio > budget.maxExpansionRatio) return { status: 'EXPANSION_RATIO_LIMIT', bytes: null }
  const local = entry.localHeaderOffset
  if (local < 0 || local + 30 > centralOffset || buffer.readUInt32LE(local) !== ZIP_LOCAL) return { status: 'LOCAL_HEADER_INVALID', bytes: null }
  const localFlags = buffer.readUInt16LE(local + 6)
  const localMethod = buffer.readUInt16LE(local + 8)
  const localNameLength = buffer.readUInt16LE(local + 26)
  const localExtraLength = buffer.readUInt16LE(local + 28)
  const dataStart = local + 30 + localNameLength + localExtraLength
  const dataEnd = dataStart + entry.compressedSize
  if (localMethod !== entry.method || localFlags !== entry.flags || localNameLength !== entry.rawName.length || dataStart > centralOffset || dataEnd > centralOffset || dataEnd < dataStart) return { status: 'LOCAL_CENTRAL_MISMATCH', bytes: null }
  if (!buffer.subarray(local + 30, local + 30 + localNameLength).equals(entry.rawName)) return { status: 'LOCAL_NAME_MISMATCH', bytes: null }
  const compressed = buffer.subarray(dataStart, dataEnd)
  let expanded
  try {
    if (entry.method === 0) expanded = Buffer.from(compressed)
    else if (entry.method === 8) expanded = inflateRawSync(compressed, { maxOutputLength: Math.max(1, Math.min(budget.maxEntryBytes, budget.maxExpandedBytes - budget.expandedBytes)) })
    else return { status: 'UNSUPPORTED_COMPRESSION_METHOD', bytes: null }
  } catch {
    return { status: 'DECOMPRESSION_FAILED', bytes: null }
  }
  if (expanded.length !== entry.uncompressedSize || crc32(expanded) !== entry.crc32) return { status: 'CONTENT_INTEGRITY_MISMATCH', bytes: null }
  budget.expandedBytes += expanded.length
  return { status: 'OK', bytes: expanded, ratio }
}

function parseZipForInventory(buffer, budget) {
  const index = readZipIndex(buffer, budget.remainingEntries())
  const entries = []
  for (const entry of index.entries) {
    if (budget.entryCount >= budget.maxEntries) {
      budget.limitsApplied.push('maxEntries')
      break
    }
    budget.entryCount += 1
    const payload = zipEntryBytes(buffer, entry, index.centralOffset ?? buffer.length, budget)
    entries.push({ ...entry, payloadStatus: payload.status, payload: payload.bytes, compressionRatio: payload.ratio ?? null })
    if (payload.status !== 'OK' && payload.status !== 'DIRECTORY') budget.warnings.push(`${displayPath(entry.name)}: ${payload.status}`)
  }
  if (!index.complete) budget.warnings.push(...index.warnings)
  if (index.status === 'ENTRY_LIMIT') budget.limitsApplied.push('maxEntriesPerArchive')
  return { ...index, entries }
}

function displayPath(value) {
  return sanitizeText(String(value).replace(/[\u0000-\u001f\u007f]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`), 500)
}

function classifyZip(index, extension) {
  const names = index.entries.filter((entry) => !entry.pathStatus && entry.typeStatus === 'OK').map((entry) => entry.path.toLowerCase())
  const has = (pattern) => names.some((name) => pattern.test(name))
  if (has(/(^|\/)bundleconfig\.pb$/i) && has(/(^|\/)base\/manifest\/androidmanifest\.xml$/i)) return { type: 'aab', confidence: 0.99, reason: 'zip contains Android App Bundle structure' }
  if (has(/^payload\/[^/]+\.app\/info\.plist$/i)) return { type: 'ipa', confidence: 0.99, reason: 'zip contains iOS Payload application structure' }
  if (has(/^androidmanifest\.xml$/i) || has(/^classes(?:\d+)?\.dex$/i)) return { type: 'apk', confidence: 0.99, reason: 'zip root contains Android manifest or DEX member' }
  if (has(/(^|\/)meta-inf\/manifest\.mf$/i) && has(/\.class$/i)) return { type: 'jar', confidence: 0.98, reason: 'zip contains JVM manifest and class files' }
  if (has(/(^|\/)module\.json$/i) && (extension === '.hap' || has(/(^|\/)ets\//i))) return { type: 'hap-candidate', confidence: 0.9, reason: 'zip contains HarmonyOS module metadata and matching package evidence' }
  return null
}

function isZip(buffer) {
  return startsWith(buffer, Buffer.from([0x50, 0x4b, 0x03, 0x04])) || startsWith(buffer, Buffer.from([0x50, 0x4b, 0x05, 0x06])) || startsWith(buffer, Buffer.from([0x50, 0x4b, 0x07, 0x08]))
}

/** Detect format candidates from content first and filename only as a hint. */
export function identifyArtifact(buffer, fileName = '') {
  const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0)
  const candidates = []
  const extension = extname(String(fileName)).toLowerCase()
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    const peOffset = bytes.length >= 0x40 ? bytes.readUInt32LE(0x3c) : -1
    if (peOffset >= 0x40 && peOffset + 4 <= bytes.length && bytes.subarray(peOffset, peOffset + 4).toString('ascii') === 'PE\0\0') addCandidate(candidates, 'pe', 'native', 0.99, 'MZ header with PE signature', { architectureMetadata: 'available through binary parser' })
    else addCandidate(candidates, 'mz-executable-candidate', 'native', 0.65, 'MZ header without a validated PE signature')
  }
  if (bytes.length >= 16 && startsWith(bytes, Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    const elfClass = bytes[4]
    const endian = bytes[5]
    if ([1, 2].includes(elfClass) && [1, 2].includes(endian)) addCandidate(candidates, 'elf', 'native', 0.99, 'ELF magic and valid class/endianness bytes', { bits: elfClass === 1 ? 32 : 64, endianness: endian === 1 ? 'little' : 'big' })
    else addCandidate(candidates, 'elf-candidate', 'native', 0.7, 'ELF magic with invalid identity fields')
  }
  const machoMagic = new Set(['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe'])
  if (bytes.length >= 4 && machoMagic.has(bytes.subarray(0, 4).toString('hex'))) addCandidate(candidates, 'macho', 'native', 0.99, 'Mach-O thin magic')
  else if (isMachOFat(bytes)) addCandidate(candidates, 'macho-fat', 'native', 0.99, 'Mach-O universal header and in-bounds architecture table')
  if (isZip(bytes)) {
    const index = readZipIndex(bytes, 1000)
    const packageInfo = index.complete ? classifyZip(index, extension) : null
    if (packageInfo) addCandidate(candidates, packageInfo.type, 'application-package', packageInfo.confidence, packageInfo.reason)
    else if (index.ok) addCandidate(candidates, 'zip', 'archive', 0.99, 'ZIP local/end signature and bounded central directory')
    else addCandidate(candidates, 'zip-candidate', 'archive', 0.65, 'ZIP signature present but central directory is not safely validated')
    const packageHint = new Map([['.apk', 'apk-candidate'], ['.aab', 'aab-candidate'], ['.ipa', 'ipa-candidate'], ['.hap', 'hap-candidate'], ['.jar', 'jar-candidate'], ['.war', 'jvm-package-candidate']]).get(extension)
    if (packageHint && !packageInfo) addCandidate(candidates, packageHint, 'application-package', 0.55, 'package extension hint only; internal package structure not confirmed')
  }
  if (isTarHeader(bytes)) addCandidate(candidates, 'tar', 'archive', 0.99, 'valid TAR header checksum')
  if (startsWith(bytes, Buffer.from([0x1f, 0x8b, 0x08]))) addCandidate(candidates, 'gzip', 'archive', 0.99, 'gzip signature')
  if (startsWith(bytes, Buffer.from('dex\n', 'ascii'))) addCandidate(candidates, 'dex', 'bytecode', 0.99, 'DEX magic')
  if (startsWith(bytes, Buffer.from([0x00, 0x61, 0x73, 0x6d]))) {
    const version = bytes.length >= 8 ? bytes.readUInt32LE(4) : null
    addCandidate(candidates, 'wasm', 'bytecode', version === 1 ? 0.99 : 0.8, version === 1 ? 'WebAssembly v1 magic and version' : 'WebAssembly magic with unsupported or absent version')
  }
  if (bytes.length >= 10 && startsWith(bytes, Buffer.from([0xca, 0xfe, 0xba, 0xbe])) && !isMachOFat(bytes)) {
    const major = bytes.readUInt16BE(6)
    if (major >= 45 && major <= 100) addCandidate(candidates, 'jvm-class', 'bytecode', 0.98, 'JVM class magic and plausible class-file version', { majorVersion: major })
  }
  for (const magic of FIXED_MAGIC) if (startsWith(bytes, magic.bytes)) addCandidate(candidates, magic.type, magic.category, magic.confidence, 'format magic bytes')
  if (startsWith(bytes, Buffer.from('RIFF', 'ascii')) && bytes.length >= 12 && bytes.subarray(8, 12).toString('ascii') === 'WEBP') addCandidate(candidates, 'webp', 'image', 0.99, 'RIFF/WEBP signature')

  const text = hasUtf8Text(bytes)
  if (text !== null) {
    const firstLine = text.trimStart().split(/\r?\n/, 1)[0] || ''
    const shebang = /^#!\s*([^\s]+)/.exec(firstLine)?.[1]
    const extensionLanguage = SOURCE_EXTENSIONS.get(extension)
    if (shebang) addCandidate(candidates, 'script', 'source', 0.96, 'content begins with a shebang', { language: /python/i.test(shebang) ? 'Python' : /node|deno|bun/i.test(shebang) ? 'JavaScript' : 'Shell' })
    else if (extensionLanguage) addCandidate(candidates, ['JSON','YAML','TOML','XML','HTML','CSS','GraphQL','SQL'].includes(extensionLanguage) ? 'structured-text' : 'source', ['JSON','YAML','TOML','XML','HTML','CSS','GraphQL','SQL'].includes(extensionLanguage) ? 'document' : 'source', 0.72, 'filename extension hint; no language parser executed', { language: extensionLanguage, evidence: 'extension_only' })
    if (!candidates.length && (/^\s*(?:<!doctype\s+html|<html[\s>])/i.test(text) || /^\s*<\?xml\s/i.test(text))) addCandidate(candidates, 'markup', 'document', 0.85, 'content resembles HTML/XML markup')
    if (!candidates.length && /^[\s\S]*$/.test(text)) addCandidate(candidates, 'text', 'text', 0.8, 'valid bounded UTF-8 text')
  }
  candidates.sort((a, b) => b.confidence - a.confidence || a.type.localeCompare(b.type))
  const stats = byteStats(bytes, Math.min(bytes.length, 4 * 1024 * 1024))
  return {
    detector: DETECTOR_VERSION,
    sha256: sha256(bytes),
    bytes: bytes.length,
    format: candidates[0]?.type ?? 'unknown',
    category: candidates[0]?.category ?? 'unknown',
    confidence: candidates[0]?.confidence ?? 0,
    candidates,
    structuralFacts: {
      analyzedBytes: stats.analyzedBytes,
      zeroByteRatio: stats.zeroByteRatio,
      printableRatio: stats.printableRatio,
      uniqueByteCount: stats.uniqueByteCount,
      printableFragmentCount: printableFragmentCount(bytes),
      truncatedStructuralScan: bytes.length > stats.analyzedBytes,
    },
    status: candidates.length ? 'IDENTIFIED' : 'UNKNOWN',
  }
}

function parseTar(buffer, budget) {
  const entries = []
  const seen = new Map()
  const warnings = []
  let offset = 0
  let status = 'OK'
  let metadataAffectsNext = false
  let ended = false
  while (offset + TAR_BLOCK <= buffer.length && budget.entryCount < budget.maxEntries) {
    if (buffer.subarray(offset, offset + TAR_BLOCK).every((byte) => byte === 0)) {
      const trailerEnd = offset + 2 * TAR_BLOCK
      if (trailerEnd > buffer.length || !buffer.subarray(offset, trailerEnd).every((byte) => byte === 0)) {
        status = 'PARTIAL_MISSING_TERMINATOR'
        warnings.push('TAR is missing the required pair of zero end-of-archive blocks.')
      } else if (!buffer.subarray(trailerEnd).every((byte) => byte === 0)) {
        status = 'PARTIAL_TRAILING_DATA'
        warnings.push('Non-zero data follows the TAR end-of-archive blocks and was not indexed.')
      } else ended = true
      break
    }
    if (!isTarHeader(buffer, offset)) {
      status = 'PARTIAL_MALFORMED'
      warnings.push(`TAR header at offset ${offset} failed checksum or structural validation.`)
      break
    }
    const name = buffer.subarray(offset, offset + 100).toString('utf8').replace(/\0.*$/s, '')
    const prefix = buffer.subarray(offset + 345, offset + 500).toString('utf8').replace(/\0.*$/s, '')
    const fullName = prefix ? `${prefix}/${name}` : name
    const size = parseTarNumber(buffer, offset + 124, 12)
    const type = String.fromCharCode(buffer[offset + 156] || 48)
    const linkName = buffer.subarray(offset + 157, offset + 257).toString('utf8').replace(/\0.*$/s, '')
    if (size === null || size < 0) {
      status = 'PARTIAL_MALFORMED'
      warnings.push(`TAR size at offset ${offset} is invalid.`)
      break
    }
    const dataStart = offset + TAR_BLOCK
    const dataEnd = dataStart + size
    const next = dataStart + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK
    const pathInfo = safeArchivePath(fullName)
    let pathStatus = pathInfo.safe ? null : pathInfo.reason
    const directory = type === '5' || (pathInfo.safe && pathInfo.isDirectory)
    if (pathInfo.safe) pathStatus = collisionReason(pathInfo.path, seen, directory)
    let entryStatus = 'OK'
    let payload = null
    const metadataRecord = ['x', 'g', 'L', 'K'].includes(type)
    if (metadataAffectsNext && !metadataRecord) entryStatus = 'UNSUPPORTED_METADATA_TARGET'
    else if (type === '1' || type === '2') entryStatus = 'REJECTED_LINK'
    else if (!['0', '\0', '5', '7'].includes(type)) entryStatus = 'REJECTED_SPECIAL_FILE'
    else if (pathStatus) entryStatus = `REJECTED_${pathStatus}`
    else if (dataEnd > buffer.length || next > buffer.length) entryStatus = 'TRUNCATED_DATA'
    else if (!directory && size > budget.maxEntryBytes) entryStatus = 'ENTRY_SIZE_LIMIT'
    else if (!directory && size > budget.maxExpandedBytes - budget.expandedBytes) entryStatus = 'EXPANSION_BUDGET'
    else if (!directory) {
      payload = Buffer.from(buffer.subarray(dataStart, dataEnd))
      budget.expandedBytes += payload.length
    }
    budget.entryCount += 1
    entries.push({ index: entries.length, name: displayPath(fullName), path: pathInfo.safe ? pathInfo.path : null, pathStatus, typeStatus: entryStatus, isDirectory: directory, linkTarget: type === '1' || type === '2' ? displayPath(linkName) : null, physicalBytes: size, logicalBytes: size, payload })
    if (entryStatus !== 'OK') warnings.push(`${displayPath(fullName)}: ${entryStatus}`)
    if (entryStatus === 'TRUNCATED_DATA') status = 'PARTIAL_TRUNCATED'
    if (metadataRecord) metadataAffectsNext = true
    else if (metadataAffectsNext) metadataAffectsNext = false
    if (type === 'g') {
      status = 'UNSUPPORTED_GLOBAL_METADATA'
      warnings.push('Global TAR PAX metadata changes effective member paths; remaining members are not indexed.')
      break
    }
    if (next <= offset || next > buffer.length) {
      if (next > buffer.length && dataEnd <= buffer.length) {
        status = 'PARTIAL_MISSING_PADDING'
        warnings.push(`${displayPath(fullName)}: TAR member padding is truncated.`)
      }
      break
    } else offset = next
  }
  if (budget.entryCount >= budget.maxEntries) {
    budget.limitsApplied.push('maxEntries')
    status = status === 'OK' ? 'ENTRY_LIMIT' : status
  }
  if (status === 'OK' && !ended && budget.entryCount < budget.maxEntries) {
    status = 'PARTIAL_MISSING_TERMINATOR'
    warnings.push('TAR reached end of input without the required pair of zero end-of-archive blocks.')
  }
  return { ok: true, status, complete: status === 'OK', entries, warnings }
}

function decompressionBudget(buffer, options, state) {
  return {
    maxEntryBytes: options.maxEntryBytes,
    maxExpandedBytes: options.maxExpandedBytes,
    maxExpansionRatio: options.maxExpansionRatio,
    get expandedBytes() { return state.expandedBytes },
    set expandedBytes(value) { state.expandedBytes = value },
    get entryCount() { return state.entryCount },
    set entryCount(value) { state.entryCount = value },
    maxEntries: options.maxEntries,
    limitsApplied: state.limitsApplied,
    warnings: state.warnings,
    remainingEntries: () => Math.max(1, options.maxEntries - state.entryCount),
  }
}

function containerMembers(buffer, format, options, state) {
  const budget = decompressionBudget(buffer, options, state)
  if (format === 'zip' || format === 'zip-candidate' || format === 'apk' || format === 'jar' || format === 'aab' || format === 'ipa' || format === 'hap-candidate') return parseZipForInventory(buffer, budget)
  if (format === 'tar') return parseTar(buffer, budget)
  return null
}

function boundedGzip(buffer, options, state) {
  const remaining = options.maxExpandedBytes - state.expandedBytes
  if (remaining <= 0) return { status: 'EXPANSION_BUDGET', bytes: null }
  const cap = Math.min(options.maxEntryBytes, remaining)
  const compressedBytes = Math.max(1, buffer.length)
  if (cap / compressedBytes > options.maxExpansionRatio && cap < options.maxEntryBytes) return { status: 'EXPANSION_RATIO_LIMIT', bytes: null }
  try {
    const expanded = gunzipSync(buffer, { maxOutputLength: cap })
    const ratio = expanded.length / compressedBytes
    if (ratio > options.maxExpansionRatio) return { status: 'EXPANSION_RATIO_LIMIT', bytes: null }
    state.expandedBytes += expanded.length
    return { status: 'OK', bytes: expanded, ratio }
  } catch {
    return { status: 'DECOMPRESSION_FAILED_OR_LIMITED', bytes: null }
  }
}

function boundedOptions(inputOptions, limits) {
  const int = (value, fallback, min, max) => {
    const parsed = Number(value)
    return Number.isFinite(parsed) ? Math.max(min, Math.min(max, Math.floor(parsed))) : fallback
  }
  return {
    maxFiles: int(inputOptions.maxFiles, 300, 1, Math.min(5000, limits.maxItems)),
    maxScanBytes: int(inputOptions.maxScanBytes, Math.min(16 * 1024 * 1024, limits.maxInputBytes), 1024, limits.maxInputBytes),
    maxFileBytes: int(inputOptions.maxFileBytes, Math.min(4 * 1024 * 1024, limits.maxFileReadBytes), 1, limits.maxFileReadBytes),
    maxEntries: int(inputOptions.maxEntries, Math.min(300, limits.maxItems), 1, Math.min(10_000, limits.maxItems)),
    maxDepth: int(inputOptions.maxDepth, 5, 0, 10),
    maxEntryBytes: int(inputOptions.maxEntryBytes, Math.min(4 * 1024 * 1024, limits.maxFileReadBytes), 1, Math.min(8 * 1024 * 1024, limits.maxFileReadBytes)),
    maxExpandedBytes: int(inputOptions.maxExpandedBytes, 32 * 1024 * 1024, 1024, 64 * 1024 * 1024),
    maxExpansionRatio: int(inputOptions.maxExpansionRatio, 100, 1, 1000),
  }
}

/** Build a deterministic artifact graph from bytes already read by Core. */
export function inventoryFiles(files, options = {}) {
  const bounded = options.bounded
  const state = { expandedBytes: 0, entryCount: 0, limitsApplied: [], warnings: [], totalInputBytes: 0, nodeCount: 0 }
  const maxNodes = bounded.maxEntries
  const nodes = []
  const edges = []
  const addNode = (data) => {
    if (nodes.length >= maxNodes) {
      if (!state.limitsApplied.includes('maxEntries')) state.limitsApplied.push('maxEntries')
      return null
    }
    const id = `artifact-${String(++state.nodeCount).padStart(6, '0')}`
    nodes.push({ id, ...data })
    return id
  }
  const rootId = addNode({ type: 'workspace', path: '.', sha256: null, physicalBytes: null, logicalBytes: null, status: 'INDEXED' })
  const indexContainer = (buffer, format, path, parentId, depth) => {
    const parent = nodes.find((node) => node.id === parentId)
    if (!parent) return
    if (depth >= bounded.maxDepth) {
      parent.containerStatus = 'DEPTH_LIMIT'
      state.limitsApplied.push('maxDepth')
      return
    }
    const parsed = containerMembers(buffer, format, bounded, state)
    if (!parsed) return
    parent.containerStatus = parsed.status
    if (parsed.warnings.length) state.warnings.push(...parsed.warnings)
    for (const entry of parsed.entries) {
      if (nodes.length >= maxNodes) {
        if (!state.limitsApplied.includes('maxEntries')) state.limitsApplied.push('maxEntries')
        break
      }
      const payload = entry.payload
      const digest = payload ? sha256(payload) : null
      const pathName = entry.path ?? entry.name
      const memberIdentity = payload ? identifyArtifact(payload, entry.path ?? entry.name) : null
      const nodeId = addNode({
        type: entry.isDirectory ? 'directory-entry' : 'artifact',
        sourceKind: 'archive-member',
        path: `${displayPath(path)}!/${displayPath(pathName)}`,
        sha256: digest,
        sha256Scope: payload ? 'complete_member_after_integrity_check' : null,
        inputCompleteness: payload ? 'complete' : 'not_read',
        physicalBytes: entry.physicalBytes ?? entry.compressedSize ?? null,
        logicalBytes: entry.logicalBytes ?? entry.uncompressedSize ?? null,
        format: memberIdentity?.format ?? null,
        status: entry.payloadStatus ?? entry.typeStatus ?? 'NOT_READ',
        pathStatus: entry.pathStatus,
        typeStatus: entry.typeStatus,
        compressionRatio: entry.compressionRatio ?? null,
        depth: depth + 1,
      })
      if (!nodeId) break
      edges.push({ from: parentId, to: nodeId, type: 'contains' })
      if (!payload || entry.isDirectory || !memberIdentity) continue
      if (memberIdentity.format === 'gzip') {
        const expanded = boundedGzip(payload, bounded, state)
        if (expanded.status !== 'OK') {
          nodes.find((node) => node.id === nodeId).containerStatus = expanded.status
          state.warnings.push(`${displayPath(pathName)}: ${expanded.status}`)
          continue
        }
        const childIdentity = identifyArtifact(expanded.bytes, `${pathName}#gzip-payload`)
        const childId = addNode({ type: 'artifact', sourceKind: 'derived-member', path: `${displayPath(path)}!/${displayPath(pathName)}#gzip-payload`, sha256: childIdentity.sha256, sha256Scope: 'complete_member_after_integrity_check', inputCompleteness: 'complete', physicalBytes: payload.length, logicalBytes: expanded.bytes.length, compressionRatio: expanded.ratio, format: childIdentity.format, category: childIdentity.category, confidence: childIdentity.confidence, status: childIdentity.status, candidates: childIdentity.candidates.slice(0, 8), depth: depth + 2 })
        if (childId) edges.push({ from: nodeId, to: childId, type: 'derived_from' })
        if (childId && ['tar', 'zip', 'zip-candidate', 'apk', 'jar', 'aab', 'ipa', 'hap-candidate'].includes(childIdentity.format)) indexContainer(expanded.bytes, childIdentity.format, `${pathName}#gzip-payload`, childId, depth + 2)
      } else if (['zip', 'zip-candidate', 'apk', 'jar', 'aab', 'ipa', 'hap-candidate', 'tar'].includes(memberIdentity.format)) {
        indexContainer(payload, memberIdentity.format, `${path}!/${pathName}`, nodeId, depth + 1)
      }
    }
  }
  const processBytes = (buffer, path, parentId, depth, sourceKind = 'file', inputInfo = {}) => {
    if (nodes.length >= maxNodes) return
    const identity = identifyArtifact(buffer, path)
    const id = addNode({
      type: 'artifact',
      sourceKind,
      path: displayPath(path),
      sha256: identity.sha256,
      sha256Scope: inputInfo.sha256Scope ?? 'complete_input',
      inputCompleteness: inputInfo.inputCompleteness ?? 'complete',
      physicalBytes: inputInfo.physicalBytes ?? buffer.length,
      logicalBytes: buffer.length,
      format: identity.format,
      category: identity.category,
      confidence: identity.confidence,
      status: identity.status,
      candidates: identity.candidates.slice(0, 8),
      structuralFacts: identity.structuralFacts,
      depth,
    })
    if (id === null) return
    if (parentId) edges.push({ from: parentId, to: id, type: sourceKind === 'archive-member' ? 'contains' : 'contains' })
    if (identity.format === 'gzip') {
      if (depth >= bounded.maxDepth) {
        state.limitsApplied.push('maxDepth')
        return
      }
      const expanded = boundedGzip(buffer, bounded, state)
      if (expanded.status !== 'OK') {
        state.warnings.push(`${displayPath(path)}: ${expanded.status}`)
        nodes.find((node) => node.id === id).containerStatus = expanded.status
        return
      }
      const childIdentity = identifyArtifact(expanded.bytes, `${path}#gzip-payload`)
      const childId = addNode({ type: 'artifact', sourceKind: 'derived-member', path: `${displayPath(path)}#gzip-payload`, sha256: childIdentity.sha256, physicalBytes: buffer.length, logicalBytes: expanded.bytes.length, compressionRatio: expanded.ratio, format: childIdentity.format, category: childIdentity.category, confidence: childIdentity.confidence, status: childIdentity.status, candidates: childIdentity.candidates.slice(0, 8), depth: depth + 1 })
      if (childId) edges.push({ from: id, to: childId, type: 'derived_from' })
      if (childId && ['tar', 'zip', 'zip-candidate', 'apk', 'jar', 'aab', 'ipa', 'hap-candidate'].includes(childIdentity.format)) indexContainer(expanded.bytes, childIdentity.format, `${path}#gzip-payload`, childId, depth + 1)
      return
    }
    if (['zip', 'zip-candidate', 'apk', 'jar', 'aab', 'ipa', 'hap-candidate', 'tar'].includes(identity.format)) indexContainer(buffer, identity.format, path, id, depth)
  }

  for (const file of files) {
    if (nodes.length >= maxNodes) {
      state.limitsApplied.push('maxEntries')
      break
    }
    if (!Buffer.isBuffer(file.bytes)) continue
    if (file.inputCompleteness && file.inputCompleteness !== 'complete') state.warnings.push(`${displayPath(file.path)}: input bytes are ${file.inputCompleteness}; any digest covers observed bytes only.`)
    state.totalInputBytes += file.bytes.length
    processBytes(file.bytes, file.path, rootId, 0, 'workspace-file', {
      sha256Scope: file.sha256Scope ?? (file.inputCompleteness === 'complete' ? 'complete_input' : 'observed_bytes_only'),
      inputCompleteness: file.inputCompleteness ?? 'complete',
      physicalBytes: file.physicalBytes ?? null,
    })
  }
  const uniqueLimits = [...new Set(state.limitsApplied)]
  return {
    schemaVersion: 'armorbreak.artifact-graph/v1',
    detector: DETECTOR_VERSION,
    summary: {
      filesProvided: files.length,
      filesListed: files.length,
      filesRead: files.filter((file) => Buffer.isBuffer(file.bytes)).length,
      unreadableFiles: files.filter((file) => file.inputCompleteness === 'unreadable').length,
      truncatedOrCappedFiles: files.filter((file) => file.inputCompleteness && !['complete', 'unreadable'].includes(file.inputCompleteness)).length,
      nodes: nodes.length,
      edges: edges.length,
      bytesRead: state.totalInputBytes,
      expandedBytes: state.expandedBytes,
      suspiciousEntries: nodes.filter((node) => node.pathStatus || (node.typeStatus && node.typeStatus !== 'OK') || (node.status && !['INDEXED', 'IDENTIFIED', 'OK', 'DIRECTORY'].includes(node.status))).length,
    },
    nodes,
    edges,
    analysis: {
      level: 'S1',
      status: uniqueLimits.length || state.warnings.length ? 'PARTIAL' : 'COMPLETE',
      warnings: [...new Set(state.warnings)].slice(0, 100),
      limitsApplied: uniqueLimits,
      coverageNotes: ['Directory traversal is limited to paths returned by Core env.listFiles; hidden entries, symbolic links, and Core skip directories are not inventoried.'],
      extraction: 'IN_MEMORY_ONLY_NO_FILES_WRITTEN',
    },
  }
}

/** Preserve a valid, internally consistent graph when the Core result-byte cap is reached. */
export function fitArtifactGraphToResultBudget(graph, maxBytes = 256 * 1024) {
  const cap = Math.max(1024, Math.min(256 * 1024, Math.floor(Number(maxBytes) || 256 * 1024)))
  const encodedBytes = (value) => Buffer.byteLength(JSON.stringify(value), 'utf8')
  if (encodedBytes(graph) <= cap) return graph
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : []
  const edges = Array.isArray(graph.edges) ? graph.edges : []
  const build = (nodeCount) => {
    const keptNodes = nodes.slice(0, nodeCount)
    const ids = new Set(keptNodes.map((node) => node.id))
    const keptEdges = edges.filter((edge) => ids.has(edge.from) && ids.has(edge.to))
    const omittedNodes = nodes.length - keptNodes.length
    const omittedEdges = edges.length - keptEdges.length
    const warning = `Result-byte budget omitted ${omittedNodes} node(s) and ${omittedEdges} edge(s); inspect a smaller scope for the complete graph.`
    return {
      ...graph,
      summary: {
        ...graph.summary,
        nodes: keptNodes.length,
        edges: keptEdges.length,
        suspiciousEntries: keptNodes.filter((node) => node.pathStatus || (node.typeStatus && node.typeStatus !== 'OK') || (node.status && !['INDEXED', 'IDENTIFIED', 'OK', 'DIRECTORY'].includes(node.status))).length,
        resultTruncated: true,
        omittedNodes,
        omittedEdges,
      },
      nodes: keptNodes,
      edges: keptEdges,
      analysis: {
        ...graph.analysis,
        status: 'PARTIAL',
        limitsApplied: [...new Set([...(graph.analysis.limitsApplied ?? []), 'maxResultBytes'])],
        warnings: [...new Set([...(graph.analysis.warnings ?? []), warning])].slice(0, 100),
        coverageNotes: [...new Set([...(graph.analysis.coverageNotes ?? []), 'The serialized graph was reduced to Core maxResultBytes; summary counts reflect only returned nodes and edges.'])],
      },
    }
  }
  let low = 1
  let high = Math.max(1, nodes.length - 1)
  let best = build(1)
  while (low <= high) {
    const middle = Math.floor((low + high) / 2)
    const candidate = build(middle)
    if (encodedBytes(candidate) <= cap) {
      best = candidate
      low = middle + 1
    } else high = middle - 1
  }
  return best
}

export { boundedOptions, sha256 as artifactSha256 }
