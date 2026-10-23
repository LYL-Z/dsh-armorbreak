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

test('approval CLI refuses a predictable non-interactive confirmation flag', async () => {
  const f = await fixture()
  const target = join(f.workspace, 'sample.bin')
  const base = ['approval', 'issue', '--risk', 'L1', '--task-id', 'task-approval', '--target', target, '--operator', 'alice', '--json']
  const direct = f.run(...base)
  assert.equal(direct.status, 1)
  assert.match(direct.stderr, /interactive terminal/i)
  const guessed = f.run(...base, '--confirm', 'confirm-0000000000000000')
  assert.equal(guessed.status, 1)
  assert.match(guessed.stderr, /predictable command-line flag/i)
  assert.doesNotMatch(direct.stdout + direct.stderr + guessed.stdout + guessed.stderr, /abappr1\./)
})

test('approval CLI refuses L3 and installation approval without an interactive terminal', async () => {
  const f = await fixture()
  const l3 = f.run('approval', 'issue', '--risk', 'L3', '--task-id', 't', '--target', 'x', '--operator', 'alice', '--json')
  assert.equal(l3.status, 1)
  assert.match(l3.stderr, /L1 or L2/)
  const missing = f.run('approval', 'issue', '--risk', 'L2', '--task-id', 't', '--operator', 'alice', '--json')
  assert.equal(missing.status, 1)
  assert.match(missing.stderr, /task-id|target/)

  const artifactPath = join(f.workspace, 'bundle.tgz')
  const { writeFile } = await import('node:fs/promises')
  await writeFile(artifactPath, 'synthetic bundle')
  const engine = await createEngine({ stateRoot: f.stateRoot, principals: [{ id: 'alice', kind: 'local-user', workspaces: [f.workspace] }] })
  try {
    let plan = await engine.runtime.installer.plan({ artifactPath, components: [{ name: 'bundle', version: '1', license: 'MIT', commit: 'abc', digest: 'sha256:test', scripts: {} }] })
    await engine.runtime.installer.persist(plan)
    plan = await engine.runtime.installer.stage(plan)
    plan = await engine.runtime.installer.verify(plan)
    const attempt = f.run('install', 'approve', '--plan-id', plan.planId, '--json')
    assert.equal(attempt.status, 1)
    assert.match(attempt.stderr, /interactive terminal/i)
    assert.equal((await engine.runtime.installer.get(plan.planId)).status, 'VERIFIED')
  } finally {
    await engine.close()
  }
})
