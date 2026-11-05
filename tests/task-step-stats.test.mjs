import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { TaskStore } from '../packages/core/src/tasks.js'

test('task step counters are derived from persisted statuses and do not double-count retries', async () => {
  const workspaceRoot = await mkdtemp(join(tmpdir(), 'abm-task-stats-'))
  try {
    const store = new TaskStore({ workspaceRoot })
    const task = await store.create({ title: 'step counter check', steps: [
      { id: 'done-1', capabilityId: 'test.one' },
      { id: 'failed-1', capabilityId: 'test.two' },
      { id: 'pending-1', capabilityId: 'test.three' },
    ] })
    task.steps[0].status = 'DONE'
    task.steps[1].status = 'FAILED'
    await store.save(task)
    assert.equal(task.stats.stepsDone, 1)
    assert.equal(task.stats.stepsFailed, 1)

    await store.updateStep(task, 'done-1', { status: 'DONE' })
    assert.equal(task.stats.stepsDone, 1)
    task.steps[1].status = 'PENDING'
    await store.save(task)
    assert.equal(task.stats.stepsFailed, 0)
    assert.equal((await store.get(task.id)).stats.stepsDone, 1)
  } finally {
    await rm(workspaceRoot, { recursive: true, force: true })
  }
})
