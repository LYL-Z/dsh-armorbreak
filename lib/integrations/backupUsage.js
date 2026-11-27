import { join, relative, sep } from 'node:path'

const SNAPSHOT_ID = /^[0-9TZa-f-]{15,80}$/
const MANIFEST_LIMIT = 64 * 1024

/** Inspect an explicitly selected copy of a Purge maintenance store. */
export async function inspectBackupUsage(input) {
  const { targetPath, env } = input
  if (!targetPath || !env?.listFiles || !env.readFile || !env.measureBackupFile) {
    throw new Error('backup usage requires the Core inventory readers')
  }
  const inventory = async () => (await env.listFiles(targetPath, { maxFiles: 1500, maxDepth: 8, strict: true })).sort()
  const files = await inventory()
  const snapshots = new Map()
  const objects = []
  let ignoredFiles = 0
  for (const file of files) {
    const [store, id, ...remaining] = relative(targetPath, file).split(sep)
    if (store === 'backups' && SNAPSHOT_ID.test(id ?? '') && remaining.length) {
      if (!snapshots.has(id)) snapshots.set(id, [])
      snapshots.get(id).push(file)
    } else if (store === 'objects' && id) objects.push(file)
    else ignoredFiles += 1
  }

  async function sum(paths) {
    let bytes = 0
    for (const file of paths) {
      bytes += await env.measureBackupFile(file)
      if (!Number.isSafeInteger(bytes)) throw new Error('backup byte count exceeds safe integer range')
    }
    return bytes
  }

  let complete = 0
  let unconfirmed = 0
  let snapshotsBytes = 0
  for (const [id, paths] of snapshots) {
    const manifest = join(targetPath, 'backups', id, 'manifest.json')
    if (!paths.includes(manifest)) { unconfirmed += 1; continue }
    // Only consume the completeness flag. Names, reasons, config values and
    // plugin metadata are never emitted or used to choose further files.
    const bytes = await env.readFile(manifest, MANIFEST_LIMIT + 1)
    if (bytes.length > MANIFEST_LIMIT) { unconfirmed += 1; continue }
    let metadata
    try { metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) }
    catch { unconfirmed += 1; continue }
    if (metadata?.complete !== true) { unconfirmed += 1; continue }
    complete += 1
    snapshotsBytes += await sum(paths)
  }
  const objectsBytes = await sum(objects)
  const total = snapshotsBytes + objectsBytes
  if (!Number.isSafeInteger(total)) throw new Error('backup byte count exceeds safe integer range')
  const after = await inventory()
  if (historyChanged(files, after)) throw new Error('backup inventory changed while measuring; retry against a stable copy')
  return {
    schema: 'armorbreak.backup-usage/v1',
    status: snapshots.size || objects.length ? 'MEASURED' : 'NO_RECOGNIZED_FILES',
    count: complete, bytes: total, snapshots: snapshotsBytes, objects: objectsBytes,
    unconfirmedSnapshots: unconfirmed, ignoredFiles, objectFiles: objects.length,
    scope: 'CALLER_SELECTED_WORKSPACE_COPY',
    sizeMeaning: 'LOGICAL_BYTES_OF_COMPLETE_DECLARED_SNAPSHOTS_AND_OBJECT_FILES',
    restoreVerified: false, changesApplied: false,
  }
}

function historyChanged(before, after) {
  return before.length !== after.length || before.some((name, index) => name !== after[index])
}
