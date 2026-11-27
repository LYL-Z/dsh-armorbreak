import { createHash } from 'node:crypto'
import { join, relative, sep } from 'node:path'
import { maintenancePath } from '../../packages/installer/maintenancePlan.js'
import { ExecutionError } from '../../packages/core/src/runner.js'

const ID = /^[0-9TZa-f-]{15,80}$/
const DIGEST = /^[a-f0-9]{64}$/
const MAX_FILE = 1024 * 1024
const MAX_TOTAL = 32 * 1024 * 1024

export function isBackupSnapshotId(value) {
  return typeof value === 'string' && ID.test(value)
}

function digestMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid backup digest map')
  const entries = Object.entries(value)
  if (entries.length > 128) throw new Error('backup digest entry limit exceeded')
  const names = new Set()
  const map = new Map()
  for (const [path, digest] of entries) {
    maintenancePath(path)
    const folded = path.toLowerCase()
    if (folded === 'manifest.json' || names.has(folded) || typeof digest !== 'string' || !DIGEST.test(digest)) throw new Error('invalid or duplicate backup file declaration')
    names.add(folded)
    map.set(path, digest)
  }
  return map
}

/** Compare a copied snapshot with its own declarations. This does not establish trust or restore readiness. */
export async function verifyBackupSnapshot(input, id) {
  return inspectSnapshot(input, id)
}

// For the trusted synthetic recovery adapter. This is not a capability result.
export async function readVerifiedSnapshotFiles(input, id) {
  const files = new Map()
  await inspectSnapshot(input, id, files)
  return files
}

async function inspectSnapshot({ targetPath, env }, id, files) {
  if (!isBackupSnapshotId(id)) throw new Error('a valid backup snapshot ID is required')
  if (!env?.listFiles || !env.readFile) throw new Error('backup verification requires Core readers')
  const snapshot = join(targetPath, 'backups', id)
  const manifest = join(snapshot, 'manifest.json')
  const inventory = async () => (await env.listFiles(targetPath, { maxFiles: 1500, maxDepth: 8, strict: true })).sort()
  const paths = await inventory()
  if (!paths.includes(manifest)) throw new ExecutionError('BACKUP_SNAPSHOT_MANIFEST_MISSING', 'backup manifest is missing from the selected copy')
  let remaining = MAX_TOTAL
  const read = async (path, limit) => {
    const cap = Math.min(limit, remaining)
    const bytes = await env.readFile(path, cap + 1)
    if (bytes.length > cap || env.targetTruncated) throw new Error('backup verification read limit exceeded')
    remaining -= bytes.length
    return bytes
  }
  const manifestBytes = await read(manifest, 64 * 1024)
  let metadata
  try {
    const { parseStrictConfigurationData } = await import('./configFormats.js')
    metadata = parseStrictConfigurationData(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes), true)
  }
  catch { throw new Error('invalid backup manifest JSON') }
  if (![1, 2].includes(metadata?.schema) || metadata.id !== id || metadata.complete !== true) throw new Error('snapshot manifest is incomplete or identifies a different snapshot')
  const sums = digestMap(metadata.sums)
  const blobs = digestMap(metadata.blobs ?? {})
  if (sums.size + blobs.size === 0) throw new Error('backup manifest declares no files')
  const snapshotPrefix = snapshot + sep
  const actual = paths.filter(path => path.startsWith(snapshotPrefix) && path !== manifest)
  if (actual.length !== sums.size || actual.some(path => !sums.has(relative(snapshot, path).split(sep).join('/')))) {
    throw new Error('backup files differ from the declared file set')
  }
  const installedObjects = new Set(paths.filter(path => path.startsWith(join(targetPath, 'objects') + sep)))
  const requiredObjects = new Set()
  const inlinePaths = new Set([...sums.keys()].map(path => path.toLowerCase()))
  for (const [path, digest] of blobs) {
    // Purge stores larger files only in objects/. The same destination cannot
    // legitimately appear as both an inline file and an object reference.
    if (inlinePaths.has(path.toLowerCase())) throw new Error('backup file is declared both inline and as an object')
    requiredObjects.add(digest)
  }
  for (const path of actual) {
    const bytes = await read(path, MAX_FILE)
    const name = relative(snapshot, path).split(sep).join('/')
    if (createHash('sha256').update(bytes).digest('hex') !== sums.get(name)) {
      throw new ExecutionError('BACKUP_SNAPSHOT_CONTENT_MISMATCH', 'backup file content does not match its declaration')
    }
    files?.set(name, bytes)
  }
  const objectBytes = files && new Map()
  for (const digest of requiredObjects) {
    const path = join(targetPath, 'objects', digest)
    if (!installedObjects.has(path)) throw new Error('a referenced backup object is missing')
    const bytes = await read(path, MAX_FILE)
    if (createHash('sha256').update(bytes).digest('hex') !== digest) {
      throw new ExecutionError('BACKUP_SNAPSHOT_CONTENT_MISMATCH', 'backup object content does not match its declaration')
    }
    objectBytes?.set(digest, bytes)
  }
  if (files) for (const [name, digest] of blobs) files.set(name, objectBytes.get(digest))
  const finalPaths = await inventory()
  if (paths.length !== finalPaths.length || paths.some((path, index) => finalPaths[index] !== path)
      || !(await read(manifest, 64 * 1024)).equals(manifestBytes)) throw new Error('backup inventory changed during verification')
  return {
    schema: 'armorbreak.backup-snapshot-verification/v1', status: 'DECLARED_CONTENT_MATCH',
    snapshotFiles: actual.length, referencedObjects: requiredObjects.size, bytesRead: MAX_TOTAL - remaining,
    manifestAuthenticated: false, liveProfileBound: false, restoreVerified: false, changesApplied: false,
  }
}
