/** Old V2 task read-only inspection and copy-on-migrate/rollback drill helpers. */
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join, relative, resolve, sep } from 'node:path'

export function sha256File(path) { return createHash('sha256').update(readFileSync(path)).digest('hex') }

function within(root, target) {
  const base = resolve(root)
  const next = resolve(target)
  return next === base || next.startsWith(base + sep)
}

export function inspectTask(taskDir) {
  const root = resolve(taskDir)
  const taskPath = join(root, 'task.json')
  if (!existsSync(taskPath)) throw new Error(`task.json missing in ${root}`)
  const task = JSON.parse(readFileSync(taskPath, 'utf8'))
  if (task.schemaVersion !== 'armorbreak/v2') throw new Error(`unsupported task schema: ${task.schemaVersion}`)
  for (const key of ['id', 'state', 'workspace', 'targetPath']) if (!task[key]) throw new Error(`task is missing ${key}`)
  const reportPath = task.report?.path ? resolve(task.report.path) : null
  if (!reportPath || !within(root, reportPath)) throw new Error('task report is missing or outside the task directory')
  if (!existsSync(reportPath)) throw new Error('task report file is missing')
  const reportSha256 = sha256File(reportPath)
  if (task.report.sha256 && task.report.sha256 !== reportSha256) throw new Error('task report hash mismatch')
  const evidencePath = join(root, 'evidence.jsonl')
  let evidenceLines = 0
  if (existsSync(evidencePath)) {
    for (const line of readFileSync(evidencePath, 'utf8').split(/\r?\n/).filter(Boolean)) { JSON.parse(line); evidenceLines += 1 }
  }
  return {
    id: task.id, state: task.state, schemaVersion: task.schemaVersion, workspace: task.workspace,
    targetPath: task.targetPath, reportSha256, evidenceLines,
    evidenceSha256: existsSync(evidencePath) ? sha256File(evidencePath) : null,
    taskSha256: sha256File(taskPath),
    files: readdirSync(root, { recursive: true }).filter((name) => statSync(join(root, name)).isFile()).sort(),
  }
}

export function snapshotTask(taskDir) {
  const root = resolve(taskDir)
  const files = {}
  for (const name of readdirSync(root, { recursive: true }).filter((entry) => statSync(join(root, entry)).isFile()).sort()) {
    const full = join(root, name)
    files[relative(root, full).replaceAll('\\', '/')] = { sha256: sha256File(full), size: statSync(full).size }
  }
  return { root, files }
}

export function migrateTask(source, target, { fault = null } = {}) {
  const from = resolve(source)
  const to = resolve(target)
  if (!existsSync(from)) throw new Error('migration source does not exist')
  if (existsSync(to)) throw new Error('migration target already exists')
  const before = snapshotTask(from)
  const tmp = `${to}.tmp-${process.pid}`
  rmSync(tmp, { recursive: true, force: true })
  mkdirSync(dirname(tmp), { recursive: true })
  cpSync(from, tmp, { recursive: true })
  writeFileSync(join(tmp, 'migration.json'), `${JSON.stringify({ schemaVersion: 'armorbreak.old-data-migration/v1', source: from, migratedAt: new Date().toISOString() }, null, 2)}\n`)
  if (fault === 'after-copy') {
    rmSync(tmp, { recursive: true, force: true })
    throw new Error('injected migration fault after copy')
  }
  cpSync(tmp, to, { recursive: true })
  rmSync(tmp, { recursive: true, force: true })
  const afterSource = snapshotTask(from)
  if (JSON.stringify(before.files) !== JSON.stringify(afterSource.files)) throw new Error('source task changed during migration')
  return { source: from, target: to, sourceUnchanged: true, targetFiles: Object.keys(snapshotTask(to).files).length }
}

export function rollbackMigration(target) {
  const to = resolve(target)
  if (!existsSync(to)) throw new Error('rollback target does not exist')
  const before = snapshotTask(to)
  rmSync(to, { recursive: true, force: true })
  return { target: to, removed: !existsSync(to), removedFiles: Object.keys(before.files).length }
}
