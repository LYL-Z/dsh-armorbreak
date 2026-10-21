import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-engine-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-engine-ws-'))
  const other = await mkdtemp(join(tmpdir(), 'abm-engine-other-'))
  const engine = await createEngine({
    stateRoot,
    principals: [
      { id: 'alice', kind: 'local-user', workspaces: [workspace] },
      { id: 'bob', kind: 'service', workspaces: [other] },
    ],
  })
  return { engine, workspace, other }
}

const ctx = (principal, workspaceId, requestId = 'req-1') => ({ principal, workspaceId, requestId, traceId: 'trace-1' })

test('trusted principal creates tasks and idempotent replay returns the same task', async () => {
  const { engine, workspace } = await fixture()
  const alice = ctx({ id: 'alice', kind: 'local-user' }, workspace, 'create-1')
  const first = await engine.createTask(alice, { title: 'L0 task', objective: 'hash a file', targetKind: 'file', targetPath: join(workspace, 'sample.txt') })
  assert.equal(first.operator, 'alice')
  assert.equal(first.workspace, workspace)
  const replay = await engine.createTask(alice, { title: 'L0 task', objective: 'hash a file', targetKind: 'file', targetPath: join(workspace, 'sample.txt') })
  assert.equal(replay.id, first.id)
  const caps = await engine.capabilities(ctx({ id: 'alice', kind: 'local-user' }, workspace, 'caps-1'))
  assert.equal(caps.length, 46)
  await engine.close()
})

test('forged operators, unknown principals and cross-workspace reads are rejected', async () => {
  const { engine, workspace, other } = await fixture()
  const alice = ctx({ id: 'alice', kind: 'local-user' }, workspace, 'create-2')
  const task = await engine.createTask(alice, { title: 'L0 task', targetKind: 'none', steps: [] })

  await assert.rejects(() => engine.createTask(alice, { title: 'bad', operator: 'bob' }), (error) => error.code === 'POLICY_DENIED')
  await assert.rejects(() => engine.capabilities(ctx({ id: 'mallory', kind: 'local-user' }, workspace)), (error) => error.code === 'POLICY_DENIED')
  await assert.rejects(() => engine.getTask(ctx({ id: 'bob', kind: 'service' }, other, 'bob-read'), task.id), (error) => error.code === 'POLICY_DENIED')
  await assert.rejects(() => engine.listTasks(ctx({ id: 'bob', kind: 'service' }, workspace, 'bob-list')), (error) => error.code === 'POLICY_DENIED')
  await engine.close()
})

test('requestId reuse with a different payload is rejected', async () => {
  const { engine, workspace } = await fixture()
  const alice = ctx({ id: 'alice', kind: 'local-user' }, workspace, 'same-request')
  await engine.createTask(alice, { title: 'first', targetKind: 'none' })
  await assert.rejects(() => engine.createTask(alice, { title: 'second', targetKind: 'none' }), (error) => /different payload/.test(error.message))
  await engine.close()
})

test('task cancellation requires the workspace-authorized principal', async () => {
  const { engine, workspace, other } = await fixture()
  const alice = ctx({ id: 'alice', kind: 'local-user' }, workspace, 'cancel-1')
  const task = await engine.createTask(alice, { title: 'to cancel', targetKind: 'none' })
  await assert.rejects(() => engine.cancelTask(ctx({ id: 'bob', kind: 'service' }, other, 'cancel-bob'), task.id), (error) => error.code === 'POLICY_DENIED')
  const cancelled = await engine.cancelTask(alice, task.id, 'operator requested')
  assert.equal(cancelled.state, 'CANCELLED')
  assert.equal(cancelled.principalId, 'alice')
  await engine.close()
})
