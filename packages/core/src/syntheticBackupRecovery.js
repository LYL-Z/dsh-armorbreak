import { join } from 'node:path'
import { isBackupSnapshotId, readVerifiedSnapshotFiles } from '../../../lib/integrations/backupSnapshotVerification.js'
import { createSyntheticMaintenance } from './syntheticMaintenance.js'

const LAB_NAME = /^[a-z][a-z0-9_-]{0,48}\.txt$/
const DIGEST = /^[a-f0-9]{64}$/
const LIMIT = 65536
const MAX_FILES = 16

function entries(record) {
  if (!record || ![null, Object.prototype].includes(Object.getPrototypeOf(record))) {
    throw new Error('BACKUP_RECOVERY_LAB_RECORD_INVALID')
  }
  const result = Object.entries(record)
  if (result.length > MAX_FILES) throw new Error('BACKUP_RECOVERY_LAB_LIMIT')
  return result
}

/** Build an approval-bound recovery rehearsal from data supplied by a trusted caller. */
export async function planSyntheticBackupRecovery(runtime, { operator, sessionId, snapshotId, manifestJson, inline, objects = {}, seeds }) {
  if (!isBackupSnapshotId(snapshotId) || typeof manifestJson !== 'string' || Buffer.byteLength(manifestJson) > LIMIT) {
    throw new Error('BACKUP_RECOVERY_LAB_MANIFEST_INVALID')
  }
  const targetPath = 'synthetic-backup'
  const folder = join(targetPath, 'backups', snapshotId)
  const inputs = new Map([[join(folder, 'manifest.json'), Buffer.from(manifestJson)]])
  for (const [data, parent, validName] of [[inline, folder, LAB_NAME], [objects, join(targetPath, 'objects'), DIGEST]]) {
    for (const [name, bytes] of entries(data)) {
      if (!validName.test(name) || !Buffer.isBuffer(bytes) || bytes.length > LIMIT) {
        throw new Error('BACKUP_RECOVERY_LAB_FILE_INVALID')
      }
      inputs.set(join(parent, name), Buffer.from(bytes))
    }
  }
  const providedSeeds = entries(seeds)
  if (providedSeeds.some(([name, value]) => !LAB_NAME.test(name) || typeof value !== 'string' || Buffer.byteLength(value) > LIMIT)) {
    throw new Error('BACKUP_RECOVERY_LAB_SEED_INVALID')
  }
  const env = {
    listFiles: async () => [...inputs.keys()],
    readFile: async (path, bytes) => inputs.get(path).subarray(0, bytes),
  }
  const files = await readVerifiedSnapshotFiles({ targetPath, env }, snapshotId)
  if (files.size !== providedSeeds.length || providedSeeds.some(([name]) => !files.has(name))) {
    throw new Error('BACKUP_RECOVERY_LAB_FILE_SET_MISMATCH')
  }
  const lab = await createSyntheticMaintenance(runtime, { operator, sessionId, seeds: Object.fromEntries(providedSeeds) })
  const plan = await lab.plan([...files].map(([name, content]) => ({ name, content })))
  return { lab, plan }
}
