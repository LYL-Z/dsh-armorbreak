import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { inspectTask, migrateTask, rollbackMigration, snapshotTask } from '../packages/migration/oldData.js'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'abm-old-data-'))
  const source = join(root, 'source')
  const target = join(root, 'target')
  mkdirSync(source, { recursive: true })
  writeFileSync(join(source, 'report.md'), '# old v2 report\n')
  writeFileSync(join(source, 'task.json'), `${JSON.stringify({ schemaVersion: 'armorbreak/v2', id: 'task_old_1', state: 'COMPLETED', workspace: source, targetPath: source, report: { sha256: createHash('sha256').update('# old v2 report\n').digest('hex'), path: join(source, 'report.md') } }, null, 2)}\n`)
  writeFileSync(join(source, 'evidence.jsonl'), `${JSON.stringify({ id: 'ev_old_1', hash: 'a'.repeat(64) })}\n`)
  return { root, source, target }
}

test('old V2 task inspection, copy migration, fault rollback and source immutability', () => {
  const f = fixture()
  try {
    const inspected = inspectTask(f.source)
    assert.equal(inspected.id, 'task_old_1')
    assert.equal(inspected.state, 'COMPLETED')
    assert.equal(inspected.evidenceLines, 1)
    const before = snapshotTask(f.source)
    assert.throws(() => migrateTask(f.source, f.target, { fault: 'after-copy' }), /injected/)
    assert.equal(snapshotTask(f.source).files['task.json'].sha256, before.files['task.json'].sha256)
    const migrated = migrateTask(f.source, f.target)
    assert.equal(migrated.sourceUnchanged, true)
    assert.ok(snapshotTask(f.target).files['migration.json'])
    const rolled = rollbackMigration(f.target)
    assert.equal(rolled.removed, true)
  } finally {
    rmSync(f.root, { recursive: true, force: true })
  }
})
