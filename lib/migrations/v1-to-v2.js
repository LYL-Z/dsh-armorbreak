/**
 * AB2-M1-08 v1 -> v2 task migration.
 *
 * Migration is metadata-only: task JSON gets schemaVersion v2, evidence/report
 * bytes are untouched. Every target is backed up and a `prepared` manifest is
 * written before any task file is replaced, so a crash leaves recoverable state.
 */
import { createHash } from 'node:crypto'
import { copyFile, lstat, mkdir, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path'
import { toTaskV2, validateTaskV2 } from '../schemas/v2/index.js'

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function isWithin(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate))
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

function pathsEqual(left, right) {
  const a = resolve(left)
  const b = resolve(right)
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b
}

/**
 * Reject symlinks and Windows junctions before touching migration paths.
 * This is a preflight check; concurrent reparse-point replacement between the
 * check and the filesystem operation is still a platform-specific residual risk.
 */
async function assertNoReparseComponents(path) {
  const absolute = resolve(path)
  const volumeRoot = parse(absolute).root
  let current = volumeRoot
  for (const part of relative(volumeRoot, absolute).split(sep).filter(Boolean)) {
    current = join(current, part)
    try {
      const info = await lstat(current)
      if (info.isSymbolicLink()) throw new Error(`migration path contains a symlink or junction: ${current}`)
    } catch (error) {
      if (error?.code === 'ENOENT') break
      throw error
    }
  }
}

async function canonicalWorkspaceRoot(workspaceRoot) {
  if (typeof workspaceRoot !== 'string' || workspaceRoot.trim() === '') throw new Error('migration workspaceRoot is required')
  const absolute = resolve(workspaceRoot)
  try {
    return await realpath(absolute)
  } catch (error) {
    if (error?.code === 'ENOENT') return absolute
    throw error
  }
}

function assertUnder(root, candidate, label) {
  if (!isWithin(root, candidate)) throw new Error(`${label} is outside its allowed migration root`)
}

function migrationLayout(manifestPath) {
  const absolute = resolve(manifestPath)
  const migrationDir = dirname(absolute)
  const migrationsDir = dirname(migrationDir)
  const metadataDir = dirname(migrationsDir)
  const workspaceRoot = dirname(metadataDir)
  if (basename(absolute) !== 'manifest.json' || basename(migrationsDir) !== 'migrations' || basename(metadataDir) !== '.armorbreak') {
    throw new Error('migration manifest must be under <workspace>/.armorbreak/migrations/<id>/manifest.json')
  }
  const migrationId = basename(migrationDir)
  if (!/^[A-Za-z0-9._-]{1,120}$/.test(migrationId) || migrationId === '.' || migrationId === '..') {
    throw new Error('invalid migration directory name')
  }
  return { absolute, workspaceRoot, migrationDir, migrationsDir, migrationId }
}

async function validateManifestPaths(manifest, layout, expectedWorkspaceRoot) {
  const workspaceRoot = await canonicalWorkspaceRoot(expectedWorkspaceRoot ?? layout.workspaceRoot)
  if (!pathsEqual(workspaceRoot, layout.workspaceRoot)) throw new Error('migration manifest is outside the requested workspace')
  if (typeof manifest.workspaceRoot !== 'string' || !pathsEqual(await canonicalWorkspaceRoot(manifest.workspaceRoot), workspaceRoot)) {
    throw new Error('migration manifest workspaceRoot does not match its location')
  }
  if (manifest.schemaVersion !== 'armorbreak.migration/v1') throw new Error('unsupported migration manifest')
  if (!['prepared', 'completed', 'rolled-back'].includes(manifest.status)) throw new Error('invalid migration manifest status')
  if (!Array.isArray(manifest.items)) throw new Error('invalid migration manifest items')

  const tasksRoot = join(workspaceRoot, '.armorbreak', 'tasks')
  const backupRoot = join(layout.migrationDir, 'tasks')
  await assertNoReparseComponents(layout.absolute)
  await assertNoReparseComponents(tasksRoot)
  await assertNoReparseComponents(backupRoot)

  for (const item of manifest.items) {
    if (!item || typeof item.file !== 'string' || typeof item.backup !== 'string') throw new Error('invalid migration manifest item paths')
    const target = resolve(item.file)
    const taskDir = dirname(target)
    if (!pathsEqual(basename(target), 'task.json') || !pathsEqual(dirname(taskDir), tasksRoot)) {
      throw new Error('migration target must be a task.json directly under the workspace task root')
    }
    assertUnder(tasksRoot, target, 'migration target')
    const backup = resolve(item.backup)
    if (!pathsEqual(dirname(backup), backupRoot) || basename(backup) === '' || basename(backup) === '.' || basename(backup) === '..') {
      throw new Error('migration backup must be a direct child of its migration backup root')
    }
    assertUnder(layout.migrationDir, backup, 'migration backup')
    if (typeof item.beforeSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(item.beforeSha256)) throw new Error('invalid migration backup hash')
    await assertNoReparseComponents(target)
    await assertNoReparseComponents(backup)
  }
  return workspaceRoot
}

async function taskFiles(workspaceRoot) {
  const tasksDir = join(workspaceRoot, '.armorbreak', 'tasks')
  await assertNoReparseComponents(tasksDir)
  let entries
  try {
    entries = await readdir(tasksDir, { withFileTypes: true })
  } catch {
    return []
  }
  const files = []
  for (const entry of entries) {
    const taskDir = join(tasksDir, entry.name)
    const taskInfo = await lstat(taskDir)
    if (taskInfo.isSymbolicLink()) throw new Error(`task directory is a symlink or junction: ${taskDir}`)
    if (!taskInfo.isDirectory()) continue
    const file = join(taskDir, 'task.json')
    await assertNoReparseComponents(file)
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
  await assertNoReparseComponents(file)
  await writeFile(tmp, content, { flag: 'wx' })
  try {
    await assertNoReparseComponents(file)
    await rename(tmp, file)
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => {})
    throw error
  }
}

export async function planMigration({ workspaceRoot }) {
  const root = await canonicalWorkspaceRoot(workspaceRoot)
  const files = await taskFiles(root)
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
    workspaceRoot: root,
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
  const root = await canonicalWorkspaceRoot(workspaceRoot)
  const plan = await planMigration({ workspaceRoot: root })
  if (plan.invalid > 0) throw new Error(`migration refused: ${plan.invalid} task(s) have invalid/ambiguous data; inspect the plan first`)
  const targets = plan.items.filter((item) => item.needsMigration)
  if (targets.length === 0) return { plan, manifestPath: null, backupRoot: null, migrated: 0 }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const backupRoot = join(root, '.armorbreak', 'migrations', `v2-${stamp}-${process.pid}`)
  await assertNoReparseComponents(root)
  await assertNoReparseComponents(dirname(backupRoot))
  await assertNoReparseComponents(backupRoot)
  await mkdir(join(backupRoot, 'tasks'), { recursive: true })
  const manifest = { schemaVersion: 'armorbreak.migration/v1', status: 'prepared', createdAt: new Date().toISOString(), workspaceRoot: root, items: [] }
  for (const item of targets) {
    await assertNoReparseComponents(item.file)
    const text = await readFile(item.file, 'utf8')
    const relativePath = relative(root, item.file)
    const backup = join(backupRoot, 'tasks', relativePath.replace(/[\\/]/g, '__'))
    assertUnder(join(root, '.armorbreak', 'tasks'), item.file, 'migration target')
    await assertNoReparseComponents(backup)
    await copyFile(item.file, backup)
    manifest.items.push({ file: item.file, backup, beforeSha256: sha256(text), afterSha256: null, taskId: item.taskId })
  }
  const manifestPath = join(backupRoot, 'manifest.json')
  await assertNoReparseComponents(manifestPath)
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  for (const [index, item] of manifest.items.entries()) {
    if (typeof onBeforeReplace === 'function') await onBeforeReplace(index, item)
    await assertNoReparseComponents(item.file)
    const text = await readFile(item.file, 'utf8')
    const task = toTaskV2(JSON.parse(text))
    const after = `${JSON.stringify(task, null, 2)}\n`
    await atomicWrite(item.file, after)
    item.afterSha256 = sha256(after)
  }
  manifest.status = 'completed'
  await assertNoReparseComponents(manifestPath)
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  return { plan, manifestPath, backupRoot, migrated: manifest.items.length }
}

export async function rollbackMigration({ manifestPath, workspaceRoot: expectedWorkspaceRoot }) {
  const layout = migrationLayout(manifestPath)
  await assertNoReparseComponents(layout.absolute)
  const manifest = JSON.parse(await readFile(layout.absolute, 'utf8'))
  const workspaceRoot = await validateManifestPaths(manifest, layout, expectedWorkspaceRoot)
  let restored = 0
  for (const item of manifest.items) {
    await assertNoReparseComponents(item.backup)
    await assertNoReparseComponents(item.file)
    const backup = await readFile(item.backup)
    if (sha256(backup) !== item.beforeSha256) throw new Error(`backup hash mismatch for ${item.file}`)
    await assertNoReparseComponents(item.file)
    assertUnder(join(workspaceRoot, '.armorbreak', 'tasks'), item.file, 'migration target')
    await atomicWrite(item.file, backup)
    restored += 1
  }
  return { manifestPath, restored }
}

/** Recover any migration with a prepared (not completed) manifest. */
export async function recoverInterruptedMigrations({ workspaceRoot }) {
  const workspace = await canonicalWorkspaceRoot(workspaceRoot)
  const root = join(workspace, '.armorbreak', 'migrations')
  await assertNoReparseComponents(root)
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
    await assertNoReparseComponents(manifestPath)
    let manifest
    try {
      manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
    } catch {
      continue
    }
    if (manifest.status === 'completed') continue
    const result = await rollbackMigration({ manifestPath, workspaceRoot: workspace })
    manifest.status = 'rolled-back'
    await assertNoReparseComponents(manifestPath)
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
    manifests.push({ manifestPath, restored: result.restored })
    recovered += result.restored
  }
  return { recovered, manifests }
}
