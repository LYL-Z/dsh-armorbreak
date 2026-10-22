import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { ApprovalAuthority } from '../lib/control/approvalAuthority.js'
import { getRuntime } from '../lib/core/runtime.js'
import { createCore } from '../packages/core/index.js'

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


test('approval tokens are bound, expire and cannot be replayed', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-engine-approval-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-engine-approval-ws-'))
  let now = 1_800_000_000_000
  const authority = new ApprovalAuthority({ stateRoot, clock: () => now })
  const engine = await createEngine({ stateRoot, approvalAuthority: authority, principals: [{ id: 'alice', kind: 'local-user', workspaces: [workspace] }, { id: 'bob', kind: 'local-user', workspaces: [workspace] }] })
  const alice = ctx({ id: 'alice', kind: 'local-user' }, workspace, 'approve-1')
  const token = authority.issue({ id: 'appr-1', riskLevel: 'L1', taskId: 'task-approval', target: workspace, operator: 'alice', ttlMs: 60_000 })
  const approved = await engine.verifyApproval(alice, { riskLevel: 'L1', taskId: 'task-approval', target: workspace, approvalToken: token.token })
  assert.equal(approved.operator, 'alice')
  assert.equal(approved.approvalId, 'appr-1')
  await assert.rejects(() => engine.verifyApproval(alice, { riskLevel: 'L1', taskId: 'task-approval', target: workspace, approvalToken: token.token }), (error) => error.code === 'TOKEN_REPLAYED')

  const forged = authority.issue({ id: 'appr-2', riskLevel: 'L1', taskId: 'task-approval', target: workspace, operator: 'bob', ttlMs: 60_000 })
  await assert.rejects(() => engine.verifyApproval(alice, { riskLevel: 'L1', taskId: 'task-approval', target: workspace, approvalToken: forged.token }), (error) => error.code === 'TOKEN_BINDING_MISMATCH')

  const expiring = authority.issue({ id: 'appr-3', riskLevel: 'L2', taskId: 'task-approval', target: workspace, operator: 'alice', ttlMs: 1000 })
  now += 2000
  await assert.rejects(() => engine.verifyApproval(alice, { riskLevel: 'L2', taskId: 'task-approval', target: workspace, approvalToken: expiring.token }), (error) => error.code === 'TOKEN_EXPIRED')
  await engine.close()
})


test('sanitized evidence envelopes are persisted and abort is fail-closed', async () => {
  const { engine, workspace } = await fixture()
  const alice = ctx({ id: 'alice', kind: 'local-user' }, workspace, 'envelope-1')
  const task = await engine.createTask(alice, { title: 'envelope task', targetKind: 'none' })
  const targetHash = 'a'.repeat(64)
  const recorded = await engine.recordEnvelope(alice, task.id, { origin: 'cli', targetHash, event: 'task.started', payload: { token: 'never-store-me', safe: 'ok' } })
  assert.equal(recorded.envelope.type, 'event')
  assert.equal(recorded.envelope.payload.token, '[REDACTED]')
  assert.equal(JSON.stringify(recorded.envelope).includes('never-store-me'), false)
  const evidence = await engine.runtime.workspace(workspace).taskStore.evidenceStore(task.id).readEvidence()
  assert.ok(evidence.some((record) => record.id === recorded.evidenceId))
  const chain = await engine.runtime.workspace(workspace).taskStore.evidenceStore(task.id).verifyChain()
  assert.equal(chain.valid, true)
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(() => engine.recordEnvelope({ ...alice, cancellation: controller.signal }, task.id, { origin: 'cli', targetHash, payload: {} }), (error) => error.code === 'CANCELLED')
  await engine.close()
})



test('forward-slash workspace paths are equivalent to backslash paths', async () => {
  const { engine, workspace } = await fixture()
  const forward = workspace.replaceAll('\\', '/')
  const alice = ctx({ id: 'alice', kind: 'local-user' }, forward, 'slash-1')
  const task = await engine.createTask(alice, { title: 'slash task', targetKind: 'none' })
  const loaded = await engine.getTask(alice, task.id)
  assert.equal(loaded.id, task.id)
  await engine.close()
})


test('deadline bounds are enforced on public Engine methods', async () => {
  const { engine, workspace } = await fixture()
  const alice = { ...ctx({ id: 'alice', kind: 'local-user' }, workspace, 'deadline-1'), deadline: new Date(Date.now() - 1000).toISOString() }
  await assert.rejects(() => engine.capabilities(alice), (error) => error.code === 'TIMEOUT')
  const invalid = { ...alice, deadline: 'not-a-date' }
  await assert.rejects(() => engine.capabilities(invalid), (error) => error.code === 'INVALID_REQUEST')
  await engine.close()
})


test('DSH/Core/Engine share one runtime per stateRoot', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-shared-runtime-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-shared-ws-'))
  const core = await createCore({ stateRoot })
  assert.equal(core.runtime, getRuntime({ stateRoot }))
  const engine = await createEngine({ stateRoot, principals: [{ id: 'alice', kind: 'local-user', workspaces: [workspace] }] })
  assert.equal(engine.runtime, core.runtime)
  const otherRoot = await mkdtemp(join(tmpdir(), 'abm-shared-other-'))
  assert.notEqual(getRuntime({ stateRoot: otherRoot }), core.runtime)
  await engine.close()
  await core.close()
})
