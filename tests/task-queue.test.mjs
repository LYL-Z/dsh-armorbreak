/**
 * Stage C tests: background queue semantics (concurrency, cancellation) and
 * restart recovery/resume through the real runner.
 */
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { TaskQueue } from '../lib/core/taskQueue.js'

function delay(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms))
}

async function execTask(runtime, workspace, title = 'queue task') {
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({ title, targetPath: null, targetKind: 'none', steps: [] })
  await runtime.runner.prepareTask(task)
  return { task, store }
}

test('queue bounds concurrency and reports WAITING then RUNNING', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-queue-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-queue-ws-'))
  runtime.runner.runWorkflow = async (task, opts) => {
    await delay(60)
    task.state = 'COMPLETED'
    return task
  }
  const queue = new TaskQueue({ runtime, concurrency: 1 })
  const { task: first } = await execTask(runtime, workspace, 'first')
  const { task: second } = await execTask(runtime, workspace, 'second')
  const firstStart = await queue.start(first)
  await delay(5)
  const secondStart = await queue.start(second)
  assert.ok(['WAITING', 'RUNNING'].includes(firstStart.state))
  assert.equal(secondStart.state, 'WAITING')
  assert.equal(queue.status(second.id).queued, true)
  await queue.wait(first.id)
  const secondEnd = await queue.wait(second.id)
  assert.equal(secondEnd.state, 'COMPLETED')
})

test('queue cancellation aborts the runner and settles the task as CANCELLED', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-queue-cancel-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-queue-cancel-ws-'))
  runtime.runner.runWorkflow = async (task, opts) => {
    await new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(resolvePromise, 5000)
      opts.signal?.addEventListener('abort', () => {
        clearTimeout(timer)
        rejectPromise(Object.assign(new Error('cancelled'), { code: 'CANCELLED' }))
      }, { once: true })
    })
    return task
  }
  const queue = new TaskQueue({ runtime, concurrency: 1 })
  const { task, store } = await execTask(runtime, workspace, 'cancel me')
  await queue.start(task, {})
  await delay(20)
  const result = await queue.cancel(task.id, { reason: 'test cancellation' })
  assert.equal(result.cancelled, true)
  const latest = await store.get(task.id)
  assert.equal(latest.state, 'CANCELLED')
  assert.equal(queue.status(task.id).state, 'CANCELLED')
})

test('restart recovery marks stale running tasks INTERRUPTED/RECOVERABLE and resume completes them', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-recovery-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-recovery-ws-'))
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'MZ recovery sample')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'interrupted analysis',
    targetPath: sample,
    targetKind: 'file',
    steps: [{ id: 'hash', capabilityId: 'forensics.hash', dependsOn: [] }],
  })
  await runtime.runner.prepareTask(task)
  task.steps[0].status = 'RUNNING'
  task.steps[0].startedAt = new Date().toISOString()
  await store.save(task)

  // Simulate a new process: the queue is empty, so the RUNNING step is stale.
  const recovered = await runtime.queue.recover(workspace)
  assert.ok(recovered.interrupted.length >= 1)
  const recoverable = recovered.recoverable.find((item) => item.id === task.id)
  assert.ok(recoverable, 'task should be recoverable')
  const reloaded = await store.get(task.id)
  assert.equal(reloaded.state, 'RECOVERABLE')
  assert.equal(reloaded.steps[0].status, 'PENDING', 'stale RUNNING step must return to PENDING')

  await runtime.queue.resume(reloaded, {})
  const settled = await runtime.queue.wait(task.id, 60_000)
  assert.equal(settled.state, 'COMPLETED')
  const finalTask = await store.get(task.id)
  assert.equal(finalTask.state, 'COMPLETED')
  assert.equal(finalTask.steps[0].status, 'DONE')
  assert.ok(finalTask.report, 'resumed task must finalize with a report')
})
