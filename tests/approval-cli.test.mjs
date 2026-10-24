import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { runCli } from '../packages/cli/index.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-approval-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-approval-ws-'))
  const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'alice' }
  const run = (...args) => spawnSync(process.execPath, ['packages/cli/index.js', ...args], { cwd: process.cwd(), env, encoding: 'utf8' })
  const openEngine = () => createEngine({
    stateRoot,
    workspaceId: workspace,
    principal: { id: 'alice', kind: 'local-user', workspaces: [workspace] },
    principals: [{ id: 'alice', kind: 'local-user', workspaces: [workspace] }],
  })
  return { stateRoot, workspace, env, run, openEngine }
}

async function captureStdout(operation) {
  const originalWrite = process.stdout.write
  let captured = ''
  process.stdout.write = function (chunk, encoding, callback) {
    captured += Buffer.isBuffer(chunk) ? chunk.toString(typeof encoding === 'string' ? encoding : 'utf8') : String(chunk)
    if (typeof encoding === 'function') encoding()
    else if (typeof callback === 'function') callback()
    return true
  }
  try {
    await operation()
  } finally {
    process.stdout.write = originalWrite
  }
  return captured
}

test('standalone approval CLI cannot mint a token from caller-controlled terminal input or flags', async () => {
  const f = await fixture()
  const target = join(f.workspace, 'sample.bin')
  const base = ['approval', 'issue', '--risk', 'L1', '--task-id', 'task-approval', '--target', target, '--json']

  const direct = f.run(...base)
  assert.equal(direct.status, 1)
  assert.match(direct.stderr, /trusted host approval provider/i)
  const guessed = f.run(...base, '--confirm', 'allowed-once')
  assert.equal(guessed.status, 1)
  assert.match(guessed.stderr, /predictable command-line flag/i)
  const spoofedOperator = f.run(...base, '--operator', 'platform-approval')
  assert.equal(spoofedOperator.status, 1)
  assert.match(spoofedOperator.stderr, /caller-controlled label/i)
  assert.doesNotMatch(direct.stdout + direct.stderr + guessed.stdout + guessed.stderr + spoofedOperator.stdout + spoofedOperator.stderr, /abappr1\./)
})

test('approval CLI still rejects invalid risk and incomplete scope before requesting host approval', async () => {
  const f = await fixture()
  const l3 = f.run('approval', 'issue', '--risk', 'L3', '--task-id', 't', '--target', 'x', '--json')
  assert.equal(l3.status, 1)
  assert.match(l3.stderr, /L1 or L2/)
  const missingTarget = f.run('approval', 'issue', '--risk', 'L2', '--task-id', 't', '--json')
  assert.equal(missingTarget.status, 1)
  assert.match(missingTarget.stderr, /task-id|target/)
})

test('trusted host approval issues a scoped, session-bound token', async () => {
  const f = await fixture()
  const target = join(f.workspace, 'synthetic-target.bin')
  const requests = []
  const output = await captureStdout(() => runCli(
    ['approval', 'issue', '--risk', 'L2', '--task-id', 'task-host-approved', '--target', target, '--json'],
    {
      env: f.env,
      agent: 'trusted-host-agent',
      callId: 'host-call-approval-1',
      sessionId: 'host-session-approval-1',
      approvalProvider: {
        async request(request) {
          requests.push(request)
          return 'allowed-once'
        },
      },
    },
  ))
  const issued = JSON.parse(output)
  assert.equal(issued.status, 'ISSUED')
  assert.equal(requests.length, 1)
  assert.equal(requests[0].agent, 'trusted-host-agent')
  assert.equal(requests[0].toolName, 'armorbreak')
  assert.equal(requests[0].callId, 'host-call-approval-1')
  assert.equal(requests[0].sessionId, 'host-session-approval-1')
  assert.match(requests[0].reason, /task-host-approved/)

  const engine = await f.openEngine()
  try {
    const verified = engine.approvalAuthority.verify(issued.token, {
      riskLevel: 'L2',
      taskId: 'task-host-approved',
      target,
      operator: 'platform-approval',
      sessionId: 'host-session-approval-1',
    })
    assert.equal(verified.valid, true)
  } finally {
    await engine.close()
  }
})

test('trusted approval cannot issue a token without a host session identity', async () => {
  const f = await fixture()
  let providerCalled = false
  await assert.rejects(
    () => runCli(
      ['approval', 'issue', '--risk', 'L1', '--task-id', 'task-no-session', '--target', 'synthetic-target', '--json'],
      {
        env: f.env,
        agent: 'trusted-host-agent',
        callId: 'host-call-no-session',
        approvalProvider: {
          async request() {
            providerCalled = true
            return 'allowed-once'
          },
        },
      },
    ),
    (error) => error.code === 'TRUSTED_APPROVAL_CONTEXT_REQUIRED',
  )
  assert.equal(providerCalled, false)
})

test('installer approval fails closed without a host and succeeds after host approval', async () => {
  const f = await fixture()
  const artifactPath = join(f.workspace, 'bundle.tgz')
  await writeFile(artifactPath, 'synthetic bundle')
  const engine = await f.openEngine()
  let plan
  try {
    plan = await engine.runtime.installer.plan({
      artifactPath,
      components: [{ name: 'bundle', version: '1', license: 'MIT', commit: 'abc', digest: 'sha256:test', scripts: {} }],
    })
    await engine.runtime.installer.persist(plan)
    plan = await engine.runtime.installer.stage(plan)
    plan = await engine.runtime.installer.verify(plan)
  } finally {
    await engine.close()
  }

  const attempt = f.run('install', 'approve', '--plan-id', plan.planId, '--json')
  assert.equal(attempt.status, 1)
  assert.match(attempt.stderr, /trusted host approval provider/i)
  const stillVerified = await f.openEngine()
  try {
    assert.equal((await stillVerified.runtime.installer.get(plan.planId)).status, 'VERIFIED')
  } finally {
    await stillVerified.close()
  }

  const requests = []
  const output = await captureStdout(() => runCli(
    ['install', 'approve', '--plan-id', plan.planId, '--json'],
    {
      env: f.env,
      agent: 'trusted-host-agent',
      callId: 'host-call-install-1',
      sessionId: 'host-session-install-1',
      approvalProvider: {
        async request(request) {
          requests.push(request)
          return 'allowed-once'
        },
      },
    },
  ))
  const approved = JSON.parse(output)
  assert.equal(approved.status, 'APPROVED')
  assert.equal(requests.length, 1)
  assert.match(requests[0].reason, new RegExp(plan.planHash))
  const finalEngine = await f.openEngine()
  try {
    assert.equal((await finalEngine.runtime.installer.get(plan.planId)).status, 'APPROVED')
  } finally {
    await finalEngine.close()
  }
})
