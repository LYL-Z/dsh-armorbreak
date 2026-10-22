import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-approval-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-approval-ws-'))
  const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'alice' }
  const run = (...args) => spawnSync(process.execPath, ['packages/cli/index.js', ...args], { cwd: process.cwd(), env, encoding: 'utf8' })
  return { stateRoot, workspace, env, run }
}

test('approval CLI requires an explicit human challenge and Engine consumes the token', async () => {
  const f = await fixture()
  const target = join(f.workspace, 'sample.bin')
  const base = ['approval', 'issue', '--risk', 'L1', '--task-id', 'task-approval', '--target', target, '--operator', 'alice', '--json']
  const challenge = f.run(...base)
  assert.equal(challenge.status, 2)
  const pending = JSON.parse(challenge.stdout)
  assert.equal(pending.status, 'CONFIRMATION_REQUIRED')
  assert.match(pending.challenge, /^confirm-[a-f0-9]{16}$/)
  const wrong = f.run(...base, '--confirm', 'confirm-deadbeef')
  assert.equal(wrong.status, 1)
  const issued = f.run(...base, '--confirm', pending.challenge)
  assert.equal(issued.status, 0)
  const result = JSON.parse(issued.stdout)
  assert.equal(result.status, 'ISSUED')
  assert.match(result.token, /^abappr1\./)

  const engine = await createEngine({ stateRoot: f.stateRoot, principals: [{ id: 'alice', kind: 'local-user', workspaces: [f.workspace] }] })
  const ctx = { principal: { id: 'alice', kind: 'local-user' }, workspaceId: f.workspace, requestId: 'approval-consume', traceId: 'approval-consume' }
  const approved = await engine.verifyApproval(ctx, { riskLevel: 'L1', taskId: 'task-approval', target, approvalToken: result.token })
  assert.equal(approved.operator, 'alice')
  await assert.rejects(() => engine.verifyApproval(ctx, { riskLevel: 'L1', taskId: 'task-approval', target, approvalToken: result.token }), (error) => error.code === 'TOKEN_REPLAYED')
  await engine.close()
})

test('approval CLI refuses L3 and missing confirmation material', async () => {
  const f = await fixture()
  const l3 = f.run('approval', 'issue', '--risk', 'L3', '--task-id', 't', '--target', 'x', '--operator', 'alice', '--json')
  assert.equal(l3.status, 1)
  assert.match(l3.stderr, /L1 or L2/)
  const missing = f.run('approval', 'issue', '--risk', 'L2', '--task-id', 't', '--operator', 'alice', '--json')
  assert.equal(missing.status, 1)
  assert.match(missing.stderr, /task-id|target/)
})
