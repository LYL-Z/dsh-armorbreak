import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { planMigration, recoverInterruptedMigrations, rollbackMigration } from '../lib/migrations/v1-to-v2.js'

async function maliciousManifest({ root, mode, file, backup, backupRoot }) {
  const workspaceRoot = join(root, 'workspace')
  const migrationRoot = join(workspaceRoot, '.armorbreak', 'migrations', `synthetic-${mode}`)
  const resolvedBackupRoot = backupRoot ?? join(migrationRoot, 'tasks')
  const manifestPath = join(migrationRoot, 'manifest.json')
  await mkdir(resolvedBackupRoot, { recursive: true })
  await mkdir(join(workspaceRoot, '.armorbreak', 'tasks', 'task_synthetic'), { recursive: true })
  const backupPath = backup ?? join(resolvedBackupRoot, 'task.json.backup')
  await writeFile(backupPath, 'SYNTHETIC-BACKUP-BYTES')
  const { createHash } = await import('node:crypto')
  const beforeSha256 = createHash('sha256').update('SYNTHETIC-BACKUP-BYTES').digest('hex')
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 'armorbreak.migration/v1',
    status: mode === 'recovery' ? 'prepared' : 'completed',
    workspaceRoot,
    items: [{ file, backup: backupPath, beforeSha256, taskId: 'task_synthetic' }],
  }))
  return { workspaceRoot, migrationRoot, manifestPath }
}

test('direct rollback rejects a workspace-external task target', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-migration-direct-boundary-'))
  const workspaceRoot = join(root, 'workspace')
  const externalTarget = join(root, 'synthetic-victim.txt')
  await mkdir(workspaceRoot, { recursive: true })
  await writeFile(externalTarget, 'SYNTHETIC-EXTERNAL-ORIGINAL')
  const fixture = await maliciousManifest({ root, mode: 'direct', file: externalTarget })

  await assert.rejects(() => rollbackMigration({ manifestPath: fixture.manifestPath }), /migration target/)
  assert.equal(await readFile(externalTarget, 'utf8'), 'SYNTHETIC-EXTERNAL-ORIGINAL')
})

test('interrupted-migration recovery rejects a workspace-external task target', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-migration-recovery-boundary-'))
  const workspaceRoot = join(root, 'workspace')
  const externalTarget = join(root, 'synthetic-victim.txt')
  await mkdir(workspaceRoot, { recursive: true })
  await writeFile(externalTarget, 'SYNTHETIC-EXTERNAL-ORIGINAL')
  await maliciousManifest({ root, mode: 'recovery', file: externalTarget })

  await assert.rejects(() => recoverInterruptedMigrations({ workspaceRoot }), /migration target/)
  assert.equal(await readFile(externalTarget, 'utf8'), 'SYNTHETIC-EXTERNAL-ORIGINAL')
})

test('migration rollback rejects a backup outside its migration directory', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-migration-backup-boundary-'))
  const workspaceRoot = join(root, 'workspace')
  const target = join(workspaceRoot, '.armorbreak', 'tasks', 'task_synthetic', 'task.json')
  const externalBackup = join(root, 'external-backup.json')
  await mkdir(join(workspaceRoot, '.armorbreak', 'tasks', 'task_synthetic'), { recursive: true })
  await writeFile(target, 'SYNTHETIC-TASK-ORIGINAL')
  const fixture = await maliciousManifest({ root, mode: 'backup', file: target, backup: externalBackup })

  await assert.rejects(() => rollbackMigration({ manifestPath: fixture.manifestPath }), /backup must be a direct child/)
  assert.equal(await readFile(target, 'utf8'), 'SYNTHETIC-TASK-ORIGINAL')
})

test('migration planning rejects a task directory reached through a junction or symlink', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'abm-migration-task-link-'))
  const workspaceRoot = join(root, 'workspace')
  const tasksRoot = join(workspaceRoot, '.armorbreak', 'tasks')
  const externalTask = join(root, 'external-task')
  await mkdir(tasksRoot, { recursive: true })
  await mkdir(externalTask, { recursive: true })
  await writeFile(join(externalTask, 'task.json'), JSON.stringify({ id: 'task_external', state: 'COMPLETED', steps: [] }))
  try {
    await symlink(externalTask, join(tasksRoot, 'task_link'), process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    t.skip(`could not create isolated directory link: ${String(error?.code ?? error)}`)
    return
  }

  await assert.rejects(() => planMigration({ workspaceRoot }), /task directory is a symlink or junction/)
  assert.equal(JSON.parse(await readFile(join(externalTask, 'task.json'), 'utf8')).id, 'task_external')
})

test('migration rollback rejects a backup-root junction or symlink', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'abm-migration-backup-link-'))
  const workspaceRoot = join(root, 'workspace')
  const externalBackupRoot = join(root, 'external-backups')
  const target = join(workspaceRoot, '.armorbreak', 'tasks', 'task_synthetic', 'task.json')
  await mkdir(externalBackupRoot, { recursive: true })
  await mkdir(join(workspaceRoot, '.armorbreak', 'tasks', 'task_synthetic'), { recursive: true })
  await writeFile(target, 'SYNTHETIC-TASK-ORIGINAL')
  const migrationRoot = join(workspaceRoot, '.armorbreak', 'migrations', 'synthetic-backup-link')
  const backupRoot = join(migrationRoot, 'tasks')
  await mkdir(migrationRoot, { recursive: true })
  try {
    await symlink(externalBackupRoot, backupRoot, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    t.skip(`could not create isolated directory link: ${String(error?.code ?? error)}`)
    return
  }
  const backup = join(backupRoot, 'task.json.backup')
  await writeFile(join(externalBackupRoot, 'task.json.backup'), 'SYNTHETIC-BACKUP-BYTES')
  const { createHash } = await import('node:crypto')
  const beforeSha256 = createHash('sha256').update('SYNTHETIC-BACKUP-BYTES').digest('hex')
  const manifestPath = join(migrationRoot, 'manifest.json')
  await writeFile(manifestPath, JSON.stringify({
    schemaVersion: 'armorbreak.migration/v1', status: 'completed', workspaceRoot,
    items: [{ file: target, backup, beforeSha256, taskId: 'task_synthetic' }],
  }))

  await assert.rejects(() => rollbackMigration({ manifestPath }), /symlink or junction/)
  assert.equal(await readFile(target, 'utf8'), 'SYNTHETIC-TASK-ORIGINAL')
})
