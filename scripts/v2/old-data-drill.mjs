#!/usr/bin/env node
/** Read-only old V2 task drill + copy migration/fault/rollback exercise. */
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { inspectTask, migrateTask, rollbackMigration, snapshotTask } from '../../packages/migration/oldData.js'

const root = resolve(new URL('../..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const taskRoot = join(root, '.armorbreak', 'tasks')
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const entries = existsSync(taskRoot) ? readdirSync(taskRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => join(taskRoot, entry.name)) : []
const tasks = []
for (const dir of entries) {
  try {
    const task = inspectTask(dir)
    if (task.state === 'COMPLETED') tasks.push({ dir, ...task })
    if (tasks.length >= 3) break
  } catch { /* skip non-V2 or incomplete tasks */ }
}
if (tasks.length === 0) throw new Error('no completed old V2 tasks found')

const before = tasks.map((task) => snapshotTask(task.dir))
const after = tasks.map((task) => snapshotTask(task.dir))
const readOnly = before.every((snapshot, index) => JSON.stringify(snapshot.files) === JSON.stringify(after[index].files))

const tempRoot = mkdtempSync(join(tmpdir(), 'abm-old-drill-'))
const migrationTarget = join(tempRoot, 'migrated')
const faultTarget = join(tempRoot, 'faulted')
let migration
let fault
try {
  migration = migrateTask(tasks[0].dir, migrationTarget)
  fault = (() => {
    try { migrateTask(tasks[0].dir, faultTarget, { fault: 'after-copy' }); return { injected: false, targetExists: existsSync(faultTarget) } } catch (error) { return { injected: true, message: String(error.message), targetExists: existsSync(faultTarget) } }
  })()
  const rolled = rollbackMigration(migrationTarget)
  migration = { ...migration, rollback: rolled }
} finally {
  rmSync(tempRoot, { recursive: true, force: true })
}

const report = {
  schemaVersion: 'armorbreak.old-data-drill/v1',
  generatedAt: new Date().toISOString(),
  commit,
  sourceRoot: taskRoot,
  readOnly,
  sourceMutated: !readOnly,
  tasks: tasks.map((task) => ({ id: task.id, state: task.state, schemaVersion: task.schemaVersion, taskSha256: task.taskSha256, reportSha256: task.reportSha256, evidenceLines: task.evidenceLines, snapshotFiles: Object.keys(snapshotTask(task.dir).files).length })),
  migration: migration ?? null,
  faultInjection: fault ?? null,
  pass: readOnly && migration?.sourceUnchanged === true && migration?.rollback?.removed === true && fault?.injected === true && fault?.targetExists === false,
}
writeFileSync(join(root, 'docs/v2/acceptance/old-data-readonly-drill.json'), `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify(report, null, 2))
if (!report.pass) process.exitCode = 1
