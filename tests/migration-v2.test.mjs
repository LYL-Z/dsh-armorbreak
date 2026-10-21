import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { applyMigration, planMigration, rollbackMigration } from '../lib/migrations/v1-to-v2.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

async function workspaceWithTask() {
  const root = await mkdtemp(join(tmpdir(), 'abm-migrate-'))
  const dir = join(root, '.armorbreak', 'tasks', 'task_1')
  await mkdir(dir, { recursive: true })
  const file = join(dir, 'task.json')
  const original = JSON.stringify({ id: 'task_1', title: 'legacy task', state: 'COMPLETED', steps: [{ id: 's1', capabilityId: 'binary.identify', status: 'DONE' }], stats: { evidence: 1, findings: 0 } }, null, 2) + '\n'
  await writeFile(file, original)
  return { root, file, original }
}

test('migration plan is read-only and detects v1 task', async () => {
  const { root, file, original } = await workspaceWithTask()
  const plan = await planMigration({ workspaceRoot: root })
  assert.equal(plan.taskCount, 1)
  assert.equal(plan.needsMigration, 1)
  assert.equal(await readFile(file, 'utf8'), original)
  assert.equal(plan.items[0].beforeSha256, sha256(original))
})

test('apply writes v2 schema, backups original and rollback restores exact bytes', async () => {
  const { root, file, original } = await workspaceWithTask()
  const applied = await applyMigration({ workspaceRoot: root })
  assert.equal(applied.migrated, 1)
  const migrated = JSON.parse(await readFile(file, 'utf8'))
  assert.equal(migrated.schemaVersion, 'armorbreak/v2')
  assert.equal(migrated.id, 'task_1')
  const restored = await rollbackMigration({ manifestPath: applied.manifestPath })
  assert.equal(restored.restored, 1)
  assert.equal(await readFile(file, 'utf8'), original)
})

test('invalid task data refuses migration', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-migrate-bad-'))
  const dir = join(root, '.armorbreak', 'tasks', 'task_bad')
  await mkdir(dir, { recursive: true })
  await writeFile(join(dir, 'task.json'), JSON.stringify({ id: '', state: 'NOPE', steps: [] }))
  const plan = await planMigration({ workspaceRoot: root })
  assert.equal(plan.invalid, 1)
  await assert.rejects(() => applyMigration({ workspaceRoot: root }), /refused/)
})
