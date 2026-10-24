import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { applyMigration, recoverInterruptedMigrations, rollbackMigration } from '../lib/migrations/v1-to-v2.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')
const childScript = fileURLToPath(new URL('../scripts/v2/migrate-fault-child.mjs', import.meta.url))

async function workspaceWithTwoTasks() {
  const root = await mkdtemp(join(tmpdir(), 'abm-migrate-fault-'))
  const originals = new Map()
  for (const id of ['task_a', 'task_b']) {
    const dir = join(root, '.armorbreak', 'tasks', id)
    await mkdir(dir, { recursive: true })
    const text = `${JSON.stringify({ id, title: id, state: 'COMPLETED', steps: [{ id: 's1', capabilityId: 'binary.identify', status: 'DONE' }] }, null, 2)}\n`
    await writeFile(join(dir, 'task.json'), text)
    originals.set(join(dir, 'task.json'), text)
  }
  return { root, originals }
}

async function assertOriginals(root, originals) {
  for (const [file, original] of originals) assert.equal(await readFile(file, 'utf8'), original, `${file} changed`)
}

test('ENOSPC/EACCES during replacement leaves backups and recovery restores every original byte', async () => {
  for (const code of ['ENOSPC', 'EACCES']) {
    const { root, originals } = await workspaceWithTwoTasks()
    await assert.rejects(
      () => applyMigration({
        workspaceRoot: root,
        onBeforeReplace(index) {
          if (index === 1) throw Object.assign(new Error(`${code} injected`), { code })
        },
      }),
      new RegExp(code),
    )
    const recovered = await recoverInterruptedMigrations({ workspaceRoot: root })
    assert.equal(recovered.recovered, 2)
    await assertOriginals(root, originals)
  }
})

test('a real SIGKILL child during migration is recovered from the prepared manifest', async () => {
  const { root, originals } = await workspaceWithTwoTasks()
  const child = spawnSync(process.execPath, [childScript, root], { encoding: 'utf8', timeout: 30_000 })
  assert.ok(child.status !== 0 || child.signal, `child unexpectedly completed: ${JSON.stringify(child)}`)
  const recovered = await recoverInterruptedMigrations({ workspaceRoot: root })
  assert.equal(recovered.recovered, 2)
  await assertOriginals(root, originals)
})

test('a truncated rollback target is restored from its durable backup during recovery', async () => {
  const { root, originals } = await workspaceWithTwoTasks()
  const applied = await applyMigration({ workspaceRoot: root })
  await assert.rejects(() => rollbackMigration({
    manifestPath: applied.manifestPath,
    onAfterTargetTruncate(index) {
      if (index === 0) throw new Error('INJECTED_ROLLBACK_INTERRUPTION')
    },
  }), /INJECTED_ROLLBACK_INTERRUPTION/)

  const recovered = await recoverInterruptedMigrations({ workspaceRoot: root })
  assert.equal(recovered.recovered, 2)
  await assertOriginals(root, originals)
})
