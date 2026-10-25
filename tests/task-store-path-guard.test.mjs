import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { TaskStore } from '../packages/core/src/tasks.js'

test('TaskStore rejects traversal task ids before reading or writing outside tasks root', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-task-store-path-'))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside.json')
  await writeFile(outside, JSON.stringify({ id: 'outside', marker: 'UNCHANGED' }))
  const store = new TaskStore({ workspaceRoot: workspace })

  for (const id of ['..', '../outside', '..\\outside', 'C:\\outside', '/outside', 'task/../../outside']) {
    assert.throws(() => store.taskDir(id), /invalid task id/)
    await assert.rejects(() => store.get(id), /invalid task id/)
  }
  await assert.rejects(() => store.save({ id: '..\\outside', title: 'overwrite' }), /invalid task id/)
  assert.equal(JSON.parse(await readFile(outside, 'utf8')).marker, 'UNCHANGED')
})
