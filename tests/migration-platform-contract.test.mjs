import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, mkdir, readFile, writeFile, realpath, rm, readdir } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

// Native Darwin executes the real contract. Linux and Windows use an isolated
// child that changes only the platform discriminator to cover the refusal path;
// this does not establish Darwin filesystem semantics or writable support.
function runUnsupportedPlatform(script, root) {
  const moduleUrl = new URL('../lib/migrations/v1-to-v2.js', import.meta.url).href
  return spawnSync(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict'
    if (process.platform !== 'darwin') Object.defineProperty(process, 'platform', { value: 'darwin' })
    const { planMigration, applyMigration, rollbackMigration, recoverInterruptedMigrations } = await import(${JSON.stringify(moduleUrl)})
    const root = process.argv[1]
    ${script}
  `, root], { encoding: 'utf8', timeout: 20_000 })
}

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'abm-platform-contract-')))
  t.after(() => rm(root, { recursive: true, force: true }))
  const tasks = join(root, '.armorbreak', 'tasks', 'task_a')
  await mkdir(tasks, { recursive: true })
  const task = join(tasks, 'task.json')
  const original = Buffer.from(JSON.stringify({ id: 'task_a', title: 'legacy task', state: 'COMPLETED', steps: [{ id: 's1', capabilityId: 'binary.identify', status: 'DONE' }] }) + '\r\n')
  await writeFile(task, original)
  return { root, task, original }
}

test('unsupported legacy migration is advertised as read-only and apply changes no bytes or backup directory', async t => {
  const { root, task, original } = await fixture(t)
  const result = runUnsupportedPlatform(`
    const plan = await planMigration({ workspaceRoot: root })
    assert.equal(plan.needsMigration, 1)
    assert.equal(plan.mutationSupported, false)
    assert.equal(plan.mutationBlocker, 'MIGRATION_PLATFORM_UNSUPPORTED')
    let invoked = false
    await assert.rejects(() => applyMigration({ workspaceRoot: root, onBeforeReplace() { invoked = true } }), { code: 'MIGRATION_PLATFORM_UNSUPPORTED' })
    assert.equal(invoked, false)
  `, root)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(await readFile(task), original)
  assert.deepEqual(await readdir(join(root, '.armorbreak')), ['tasks'])
})

test('unsupported rollback and recovery leave task, backup and prepared manifest unchanged', async t => {
  const { root, task, original } = await fixture(t)
  const migration = join(root, '.armorbreak', 'migrations', 'fixture')
  const backups = join(migration, 'tasks')
  await mkdir(backups, { recursive: true })
  const backup = join(backups, 'task_a.json')
  const backupBytes = Buffer.from('original backup bytes\r\n')
  await writeFile(backup, backupBytes)
  const manifest = join(migration, 'manifest.json')
  const manifestBytes = Buffer.from(JSON.stringify({ schemaVersion: 'armorbreak.migration/v1', status: 'prepared', workspaceRoot: root, items: [{ file: task, backup, beforeSha256: createHash('sha256').update(backupBytes).digest('hex'), taskId: 'task_a' }] }) + '\n')
  await writeFile(manifest, manifestBytes)
  const result = runUnsupportedPlatform(`
    import { join } from 'node:path'
    const manifestPath = join(root, '.armorbreak', 'migrations', 'fixture', 'manifest.json')
    let invoked = false
    await assert.rejects(() => rollbackMigration({ manifestPath, onBeforeTargetWrite() { invoked = true } }), { code: 'MIGRATION_PLATFORM_UNSUPPORTED' })
    await assert.rejects(() => recoverInterruptedMigrations({ workspaceRoot: root }), { code: 'MIGRATION_PLATFORM_UNSUPPORTED' })
    assert.equal(invoked, false)
  `, root)
  assert.equal(result.status, 0, result.stderr)
  assert.deepEqual(await readFile(task), original)
  assert.deepEqual(await readFile(backup), backupBytes)
  assert.deepEqual(await readFile(manifest), manifestBytes)
})
