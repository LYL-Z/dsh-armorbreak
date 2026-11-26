/**
 * Independent, read-only DSH Desktop disk-layout probe.
 *
 * Conceptual references (fixed snapshots):
 *   mmparko/dsh-purge@033e6bd lib/surface.js
 *   kingcharleslzy-ai/dsh-purge@411f98c lib/host-layout.js, lib/next-host.js
 *
 * This does NOT import either upstream implementation or execute host code.
 * Disk layout, package metadata, and loaded process state are separate facts.
 */
import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { isAbsolute, join, parse, resolve, sep } from 'node:path'
import { readBoundedRanges } from '../../packages/core/src/util.js'

const MAX_PACKAGE_BYTES = 64 * 1024
const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/
const OFFICIAL_PACKAGE = '@deepseek-ai/dsh-desktop-host'
const NEXT_PACKAGE = 'dsh-desktop-next'
const SCHEMA_VERSION = 'armorbreak.dsh-runtime-layout/v1'
const MAX_ARCHIVE_HEADER = 8 * 1024 * 1024
const PACKED_LOCATIONS = [
  { path: ['dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host', 'package.json'], label: 'official-asar', family: 'official' },
  { path: ['package.json'], label: 'next-asar', family: 'next' },
]

function packageIdentity(bytes) {
  if (bytes.byteLength > MAX_PACKAGE_BYTES || bytes.includes(0)) return { status: 'INVALID_METADATA' }
  const raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  if (!raw || Array.isArray(raw) || typeof raw !== 'object') return { status: 'INVALID_METADATA' }
  return {
    status: 'PARSED',
    family: raw.name === OFFICIAL_PACKAGE ? 'official' : raw.name === NEXT_PACKAGE && typeof raw.main === 'string' && raw.main.length > 0 && raw.main.length <= 255 ? 'next' : null,
    version: typeof raw.version === 'string' && SAFE_VERSION.test(raw.version) ? raw.version : null,
  }
}

async function packedIdentities({ size, read }) {
  const prefix = await read(0, 16)
  const header = prefix.readUInt32LE(4), payload = prefix.readUInt32LE(8), jsonLength = prefix.readUInt32LE(12)
  const dataStart = 8 + header
  if (prefix.readUInt32LE(0) !== 4 || header > MAX_ARCHIVE_HEADER || header !== payload + 4
      || jsonLength === 0 || Math.ceil(jsonLength / 4) * 4 + 4 !== payload || dataStart > size) {
    throw new Error('invalid ASAR header')
  }
  const tree = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await read(16, jsonLength)))
  if (!tree?.files || Array.isArray(tree.files) || typeof tree.files !== 'object') throw new Error('invalid ASAR index')
  const found = []
  for (const { path, label, family } of PACKED_LOCATIONS) {
    let entry = tree
    for (const part of path) {
      if (entry?.link !== undefined || entry?.unpacked === true) { entry = undefined; break }
      entry = entry?.files && Object.hasOwn(entry.files, part) ? entry.files[part] : undefined
    }
    if (!entry || entry.unpacked === true || entry.link !== undefined) continue
    if (!Number.isSafeInteger(entry.size) || entry.size < 1 || entry.size > MAX_PACKAGE_BYTES
        || typeof entry.offset !== 'string' || !/^\d{1,16}$/.test(entry.offset)) throw new Error('invalid packed metadata bounds')
    const offset = dataStart + Number(entry.offset)
    if (!Number.isSafeInteger(offset) || offset > size - entry.size) throw new Error('ASAR metadata outside archive')
    const result = packageIdentity(await read(offset, entry.size))
    if (result.status === 'PARSED' && result.family === family) found.push({ family, version: result.version, source: label })
  }
  return found
}

function failure(error) {
  return error?.code === 'ENOENT' ? 'MISSING' : 'UNREADABLE'
}

// Validate every existing parent before reading known, bounded locations.
// Does not claim to prevent an adversarial concurrent path-swap; the caller
// must select a trusted local installation root.
async function inspectPath(path, kind) {
  const root = parse(path).root
  let current = root
  const parts = path.slice(root.length).split(sep).filter(Boolean)
  try {
    for (let i = 0; i < parts.length; i += 1) {
      current = join(current, parts[i])
      const stat = await lstat(current)
      if (stat.isSymbolicLink()) return { status: 'SYMLINK_NOT_FOLLOWED' }
      if (i !== parts.length - 1 && !stat.isDirectory()) return { status: 'NOT_DIRECTORY' }
      if (i === parts.length - 1) {
        if (kind === 'directory') return { status: stat.isDirectory() ? 'PRESENT' : 'NOT_DIRECTORY' }
        if (!stat.isFile()) return { status: 'NOT_REGULAR_FILE' }
        if (stat.size > MAX_PACKAGE_BYTES && kind === 'package') return { status: 'TOO_LARGE' }
        return { status: 'PRESENT', stat }
      }
    }
    return { status: 'NOT_INSPECTED' }
  } catch (error) {
    return { status: failure(error) }
  }
}

async function readMetadata(path, readFile) {
  const probe = await inspectPath(path, 'package')
  if (probe.status !== 'PRESENT') return { status: probe.status }
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const stat = await handle.stat()
    if (!stat.isFile()) return { status: 'NOT_REGULAR_FILE' }
    if (stat.dev !== probe.stat.dev || stat.ino !== probe.stat.ino) return { status: 'CHANGED_DURING_INSPECTION' }
    if (stat.size > MAX_PACKAGE_BYTES) return { status: 'TOO_LARGE' }
    // Never read an unbounded file after a concurrent growth. Core's reader
    // performs its own authorization/identity checks when called by a task.
    const buffer = Buffer.alloc(MAX_PACKAGE_BYTES + 1)
    const bytes = readFile
      ? await readFile(path, MAX_PACKAGE_BYTES + 1)
      : buffer.subarray(0, (await handle.read(buffer, 0, buffer.length, 0)).bytesRead)
    return packageIdentity(bytes)
  } catch {
    return { status: 'UNREADABLE_OR_INVALID' }
  } finally {
    await handle?.close()
  }
}

/** Inspect only the exact, explicitly selected Desktop resources directory. */
export async function inspectDshRuntimeLayout({ resources, readFile, inspectHostArchive } = {}) {
  if (typeof resources !== 'string' || !isAbsolute(resources) || resources.includes('\0') || resources.length > 4096) {
    throw new Error('host layout requires an absolute --resources directory')
  }
  const base = resolve(resources)
  const resource = await inspectPath(base, 'directory')
  const report = {
    schemaVersion: SCHEMA_VERSION,
    mode: 'READ_ONLY',
    target: { resources: base },
    directory: resource.status,
    disk: { archive: 'NOT_INSPECTED', unpacked: 'NOT_INSPECTED', archiveCompanion: 'NOT_INSPECTED' },
    archiveMetadata: 'NOT_INSPECTED',
    identity: { family: 'UNVERIFIED', version: null, evidence: 'NONE' },
    runtime: 'NOT_VERIFIED',
    patch: 'NOT_ASSESSED',
    status: 'INCOMPLETE',
    note: 'Disk contents do not establish a running host, model injection, patch activation or compatibility.',
  }
  if (resource.status !== 'PRESENT') return report

  const archive = await inspectPath(join(base, 'app.asar'), 'file')
  const unpacked = await inspectPath(join(base, 'app'), 'directory')
  const companion = await inspectPath(join(base, 'app.asar.unpacked'), 'directory')
  report.disk = { archive: archive.status, unpacked: unpacked.status, archiveCompanion: companion.status }

  const locations = [
    { label: 'official-unpacked', file: join(base, 'app', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host', 'package.json'), family: 'official' },
    { label: 'official-archive-companion', file: join(base, 'app.asar.unpacked', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host', 'package.json'), family: 'official' },
    { label: 'next-unpacked', file: join(base, 'app', 'package.json'), family: 'next' },
    { label: 'next-archive-companion', file: join(base, 'app.asar.unpacked', 'package.json'), family: 'next' },
  ]
  const observations = []
  if (archive.status === 'PRESENT' && (inspectHostArchive || !readFile)) {
    const archivePath = join(base, 'app.asar')
    try {
      const packed = inspectHostArchive
        ? await inspectHostArchive(archivePath, packedIdentities)
        : await readBoundedRanges(archivePath, MAX_ARCHIVE_HEADER + 2 * MAX_PACKAGE_BYTES + 16, {}, packedIdentities)
      observations.push(...packed)
      report.archiveMetadata = packed.length ? 'PACKAGE_FOUND' : 'NO_RECOGNIZED_PACKAGE'
    } catch {
      report.archiveMetadata = 'UNREADABLE_OR_INVALID'
    }
  }
  let blocked = false
  for (const entry of locations) {
    const result = await readMetadata(entry.file, readFile)
    if (result.status === 'PARSED' && result.family === entry.family) {
      observations.push({ family: result.family, version: result.version, source: entry.label })
    } else if (!['MISSING', 'PARSED'].includes(result.status)) {
      blocked = true
    }
  }
  const families = new Set(observations.map(x => x.family))
  if (families.size > 1) {
    report.status = 'CONFLICTING_IDENTITIES'
    report.identity.evidence = 'CONFLICT'
  } else if (observations.length > 0 && !blocked) {
    const versions = new Set(observations.map(x => x.version).filter(Boolean))
    report.identity = {
      family: observations[0].family === 'official' ? 'OFFICIAL_DISK_PACKAGE' : 'NEXT_DISK_PACKAGE',
      version: versions.size === 1 ? [...versions][0] : null,
      evidence: observations.map(x => x.source).sort().join(','),
    }
    report.status = versions.size > 1 ? 'CONFLICTING_VERSIONS' : 'DISK_PACKAGE_FOUND'
  } else {
    report.status = blocked ? 'INCOMPLETE' : 'NO_VERIFIED_PACKAGE'
  }
  if (['SYMLINK_NOT_FOLLOWED', 'UNREADABLE', 'NOT_REGULAR_FILE', 'NOT_DIRECTORY'].some(x => Object.values(report.disk).includes(x))) {
    report.status = 'INCOMPLETE'
  }
  return report
}
