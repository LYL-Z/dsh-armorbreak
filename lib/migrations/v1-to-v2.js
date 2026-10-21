/**
 * AB2-M1-08 v1 -> v2 task migration.
 *
 * Migration is metadata-only: task JSON gets schemaVersion v2, evidence/report
 * bytes are untouched. Every target is backed up and a `prepared` manifest is
 * written before any task file is replaced, so a crash leaves recoverable state.
 */
import { createHash } from 'node:crypto'
import { copyFile, mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { toTaskV2, validateTaskV2 } from '../schemas/v2/index.js'

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

async function taskFiles(workspaceRoot) {
  const tasksDir = join(workspaceRoot, '.armorbreak', 'tasks')
  let entries
  try {
    entries = await readdir(tasksDir, { withFileTypes: true })
  } catch {
    return []
  }
  const files = []
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    const file = join(tasksDir, entry.name, 'task.json')
    try {
      await readFile(file)
      files.push(file)
    } catch {
      /* task without task.json is ignored */
    }
  }
  return files.sort()
}

async function atomicWrite(file, content) {
  const tmp = `${file}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`
  await writeFile(tmp, content)
  await rename(tmp, file)
}

export async function planMigration({ workspaceRoot }) {
  const files = await taskFiles(workspaceRoot)
  const items = []
  for (const file of files) {
    const text = await readFile(file, 'utf8')
    let task
    try {
      task = JSON.parse(text)
    } catch (error) {
      items.push({ file, taskId: null, needsMigration: false, beforeSha256: sha256(text), error: `invalid JSON: ${String(error?.message ?? error)}` })
      continue
    }
    const v2 = validateTaskV2(task, { allowV1: true })
    items.push({
      file,
      taskId: task.id ?? null,
      needsMigration: task.schemaVersion !== 'armorbreak/v2',
      beforeSha256: sha256(text),
      validV2: v2.valid,
      errors: v2.valid ? [] : v2.errors,
    })
  }
  return {
    schemaVersion: 'armorbreak.migration-plan/v1',
    workspaceRoot,
    taskCount: items.length,
    needsMigration: items.filter((item) => item.needsMigration).length,
    invalid: items.filter((item) => item.errors?.length > 0).length,
    items,
  }
}

/**
 * @param {{workspaceRoot:string, onBeforeReplace?: (index:number, item:any) => Promise<void>|void}} input
 */
export async function applyMigration({ workspaceRoot, onBeforeReplace }) {
  const plan = await planMigration({ workspaceRoot })
  if (plan.invalid > 0) throw new Error(`migration refused: ${plan.invalid} task(s) have invalid/ambiguous data; inspect the plan first`)
  const targets = plan.items.filter((item) => item.needsMigration)
  if (targets.length === 0) return { plan, manifestPath: null, backupRoot: null, migrated: 0 }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const backupRoot = join(workspaceRoot, '.armorbreak', 'migrations', `v2-${stamp}-${process.pid}`)
  await mkdir(join(backupRoot, 'tasks'), { recursive: true })
  const manifest = { schemaVersion: 'armorbreak.migration/v1', status: 'prepared', createdAt: new Date().toISOString(), workspaceRoot, items: [] }
  for (const item of targets) {
    const text = await readFile(item.file, 'utf8')
    const relative = item.file.slice(workspaceRoot.length + 1)
    const backup = join(backupRoot, 'tasks', relative.replace(/[\\/]/g, '__'))
    await copyFile(item.file, backup)
    manifest.items.push({ file: item.file, backup, beforeSha256: sha256(text), afterSha256: null, taskId: item.taskId })
  }
  const manifestPath = join(backupRoot, 'manifest.json')
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  for (const [index, item] of manifest.items.entries()) {
    if (typeof onBeforeReplace === 'function') await onBeforeReplace(index, item)
    const text = await readFile(item.file, 'utf8')
    const task = toTaskV2(JSON.parse(text))
    const after = `${JSON.stringify(task, null, 2)}\n`
    await atomicWrite(item.file, after)
    item.afterSha256 = sha256(after)
  }
  manifest.status = 'completed'
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  return { plan, manifestPath, backupRoot, migrated: manifest.items.length }
}

export async function rollbackMigration({ manifestPath }) {
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  if (manifest.schemaVersion !== 'armorbreak.migration/v1') throw new Error('unsupported migration manifest')
  let restored = 0
  for (const item of manifest.items) {
    const backup = await readFile(item.backup)
    if (sha256(backup) !== item.beforeSha256) throw new Error(`backup hash mismatch for ${item.file}`)
    await atomicWrite(item.file, backup)
    restored += 1
  }
  return { manifestPath, restored }
}

/** Recover any migration with a prepared (not completed) manifest. */
export async function recoverInterruptedMigrations({ workspaceRoot }) {
  const root = join(workspaceRoot, '.armorbreak', 'migrations')
  let dirs
  try {
    dirs = await readdir(root, { withFileTypes: true })
  } catch {
    return { recovered: 0, manifests: [] }
  }
  const manifests = []
  let recovered = 0
  for (const dir of dirs) {
    if (!dir.isDirectory()) continue
    const manifestPath = join(root, dir.name, 'manifest.json')
    let manifest
    try {
      manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
    } catch {
      continue
    }
    if (manifest.status === 'completed') continue
    const result = await rollbackMigration({ manifestPath })
    manifest.status = 'rolled-back'
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
    manifests.push({ manifestPath, restored: result.restored })
    recovered += result.restored
  }
  return { recovered, manifests }
}
