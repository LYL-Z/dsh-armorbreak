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

const MAX_PACKAGE_BYTES = 64 * 1024
const SAFE_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/
const OFFICIAL_PACKAGE = '@deepseek-ai/dsh-desktop-host'
const NEXT_PACKAGE = 'dsh-desktop-next'
const SCHEMA_VERSION = 'armorbreak.dsh-runtime-layout/v1'

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

async function readMetadata(path) {
  const probe = await inspectPath(path, 'package')
  if (probe.status !== 'PRESENT') return { status: probe.status }
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const stat = await handle.stat()
    if (!stat.isFile()) return { status: 'NOT_REGULAR_FILE' }
    if (stat.dev !== probe.stat.dev || stat.ino !== probe.stat.ino) return { status: 'CHANGED_DURING_INSPECTION' }
    if (stat.size > MAX_PACKAGE_BYTES) return { status: 'TOO_LARGE' }
    const bytes = await handle.readFile()
    if (bytes.byteLength > MAX_PACKAGE_BYTES || bytes.includes(0)) return { status: 'INVALID_METADATA' }
    const raw = JSON.parse(bytes.toString('utf8'))
    if (!raw || Array.isArray(raw) || typeof raw !== 'object') return { status: 'INVALID_METADATA' }
    // Never expose raw fields: package.json can include private registry URLs,
    // scripts, tokens, author addresses and other sensitive material.
    const version = typeof raw.version === 'string' && SAFE_VERSION.test(raw.version) ? raw.version : null
    return {
      status: 'PARSED',
      family: raw.name === OFFICIAL_PACKAGE ? 'official' : raw.name === NEXT_PACKAGE && typeof raw.main === 'string' && raw.main.length > 0 && raw.main.length <= 255 ? 'next' : null,
      version,
    }
  } catch {
    return { status: 'UNREADABLE_OR_INVALID' }
  } finally {
    await handle?.close()
  }
}

/** Inspect only the exact, explicitly selected Desktop resources directory. */
export async function inspectDshRuntimeLayout({ resources } = {}) {
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
  let blocked = false
  for (const entry of locations) {
    const result = await readMetadata(entry.file)
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
