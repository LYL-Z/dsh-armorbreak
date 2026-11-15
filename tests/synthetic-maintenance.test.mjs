import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile, rm, rename, link, symlink, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fork } from 'node:child_process'
import { once } from 'node:events'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
import { createSyntheticMaintenance, reopenSyntheticMaintenance } from '../packages/core/src/syntheticMaintenance.js'
const approved = { request: async () => 'allowed-once' }
const context = { operator: 'fixture-owner', sessionId: 'fixture-session' }
async function setup(t) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'ab-lab-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot }); await runtime.init()
  const lab = await createSyntheticMaintenance(runtime, { ...context, seeds: { 'one.txt': 'first\r\noriginal\0', 'two.txt': 'other' } })
  t.after(() => rm(lab.root, { recursive: true, force: true })); t.after(() => rm(stateRoot, { recursive: true, force: true }))
  const plan = await lab.plan([{ name: 'one.txt', content: 'updated' }, { name: 'two.txt', content: '' }])
  return { runtime, lab, plan, stateRoot }
}
test('synthetic transaction uses Core single-use approvals, commits, audits and byte-exact restores', async t => {
  const { runtime, lab, plan } = await setup(t)
  assert.equal((await lab.apply(plan.planId, approved)).state, 'COMMITTED')
  assert.equal(await readFile(join(lab.data, 'one.txt'), 'utf8'), 'updated')
  assert.equal((await readFile(join(lab.data, 'two.txt'))).length, 0)
  assert.equal((await lab.rollback(plan.planId, approved)).state, 'ROLLED_BACK')
  assert.deepEqual(await readFile(join(lab.data, 'one.txt')), Buffer.from('first\r\noriginal\0'))
  assert.equal(await readFile(join(lab.data, 'two.txt'), 'utf8'), 'other')
  const grants = runtime.scope.state.approvals.filter(row => row.taskId === plan.planId)
  assert.equal(grants.length, 2)
  for (const row of grants) assert.equal(runtime.approvalAuthority.verify(row.approvalToken).code, 'TOKEN_REPLAYED')
  const audit = await readFile(join(lab.control, 'audit.jsonl'), 'utf8')
  assert.match(audit, /COMMITTED/); assert.match(audit, /ROLLED_BACK/); assert.doesNotMatch(audit, /updated|first|original/)
  await assert.rejects(() => lab.apply(plan.planId, approved), /STATE_DENIED/)
})
test('missing/denied/cancelled approval and wrong plan cannot mutate synthetic targets', async t => {
  const { lab, plan } = await setup(t)
  await assert.rejects(() => lab.apply(plan.planId), /PROVIDER_REQUIRED/)
  for (const outcome of ['denied', 'cancelled', 'allowed', 'unavailable']) await assert.rejects(() => lab.apply(plan.planId, { request: async () => outcome }), /APPROVAL_DENIED/)
  await assert.rejects(() => lab.apply('other-task', approved), /PLAN_BINDING/)
  assert.equal(await readFile(join(lab.data, 'one.txt'), 'utf8'), 'first\r\noriginal\0')
})
test('existing host roots, directory traversal, paths, unknown targets and excessive bytes are rejected', async t => {
  const { runtime, lab } = await setup(t)
  for (const name of ['../outside.txt', 'C:\\host.txt', 'nested/a.txt', 'CON.txt', 'unseeded.txt']) {
    await assert.rejects(() => lab.file(name, () => assert.fail('must not reach operation')), /TARGET_DENIED/)
  }
  await assert.rejects(() => createSyntheticMaintenance(runtime, { ...context, seeds: { '../host.txt': 'x' } }), /SEED_INVALID/)
  await assert.rejects(() => reopenSyntheticMaintenance(runtime, tmpdir(), context))
})
test('corrupt backup/manifest and changed operator/session fail closed', async t => {
  const { runtime, lab, plan } = await setup(t)
  await assert.rejects(() => reopenSyntheticMaintenance(runtime, lab.root, { ...context, sessionId: 'other' }), /CONTEXT_BINDING/)
  await assert.rejects(() => reopenSyntheticMaintenance(runtime, lab.root, { ...context, operator: 'other' }), /CONTEXT_BINDING/)
  const path = join(lab.control, 'plan.json'), original = await readFile(path)
  const record = JSON.parse(original); record.value.rows[0].before = Buffer.from('forged').toString('base64')
  await writeFile(path, JSON.stringify(record))
  await assert.rejects(() => lab.apply(plan.planId, approved), /RECORD_INTEGRITY/)
  await writeFile(path, original)
  assert.equal((await lab.apply(plan.planId, approved)).state, 'COMMITTED')
})
test('drift in content, members or opened object identity blocks activation', async t => {
  const { lab, plan } = await setup(t)
  await writeFile(join(lab.data, 'one.txt'), 'concurrent-edit')
  await assert.rejects(() => lab.apply(plan.planId, approved), /CONTENT_DRIFT/)
  await writeFile(join(lab.data, 'one.txt'), 'first\r\noriginal\0')
  await rename(join(lab.data, 'one.txt'), join(lab.control, 'old.txt'))
  await writeFile(join(lab.data, 'one.txt'), 'first\r\noriginal\0')
  await assert.rejects(() => lab.apply(plan.planId, approved), /FILE_CHANGED/)
})
test('hard links and ancestor junction/symlink replacement cannot redirect a write', async t => {
  const { lab, plan } = await setup(t)
  const extra = join(lab.control, 'extra.txt')
  await link(join(lab.data, 'one.txt'), extra)
  await assert.rejects(() => lab.apply(plan.planId, approved), /FILE_CHANGED/)
  await rm(extra)
  const moved = join(lab.root, 'original-data'), outside = join(lab.root, 'unrelated')
  await mkdir(outside); await writeFile(join(outside, 'one.txt'), 'outside')
  await rename(lab.data, moved)
  await symlink(outside, lab.data, process.platform === 'win32' ? 'junction' : 'dir')
  await assert.rejects(() => lab.apply(plan.planId, approved), /DIRECTORY_CHANGED|PATH_UNSAFE/)
  assert.equal(await readFile(join(outside, 'one.txt'), 'utf8'), 'outside')
  await rm(lab.data); await rename(moved, lab.data)
})
test('injected failure after first committed write is durable and explicitly recoverable after reopen', async t => {
  const { lab, runtime, plan } = await setup(t)
  await assert.rejects(() => lab.apply(plan.planId, approved, async index => { if (index === 0) throw new Error('synthetic failure checkpoint') }), /failure checkpoint/)
  assert.equal((await lab.events()).at(-1).state, 'WROTE')
  assert.equal(await readFile(join(lab.data, 'one.txt'), 'utf8'), 'updated')
  const reopened = await reopenSyntheticMaintenance(runtime, lab.root, context)
  await assert.rejects(() => reopened.apply(plan.planId, approved), /STATE_DENIED/)
  assert.equal((await reopened.rollback(plan.planId, approved)).state, 'ROLLED_BACK')
  assert.equal(await readFile(join(lab.data, 'one.txt'), 'utf8'), 'first\r\noriginal\0')
})
test('concurrent executor is rejected while original lock holder waits for trusted approval', async t => {
  const { lab, runtime, plan } = await setup(t)
  let unlock, entered
  const arrived = new Promise(resolve => { entered = resolve })
  const pending = lab.apply(plan.planId, { request: async () => { entered(); return new Promise(resolve => { unlock = resolve }) } })
  await arrived
  const other = await reopenSyntheticMaintenance(runtime, lab.root, context)
  await assert.rejects(() => other.apply(plan.planId, approved), /LOCKED_RECOVERY_REQUIRED/)
  await assert.rejects(() => other.releaseExitedProcessLock(process.pid), /PROCESS_STILL_ALIVE/)
  unlock('allowed-once'); assert.equal((await pending).state, 'COMMITTED')
})
test('unknown partial bytes never trigger optimistic automatic recovery', async t => {
  const { lab, plan } = await setup(t)
  await lab.apply(plan.planId, approved)
  await writeFile(join(lab.data, 'one.txt'), 'partial-corrupt')
  await assert.rejects(() => lab.rollback(plan.planId, approved), /CONTENT_DRIFT/)
  assert.equal(await readFile(join(lab.data, 'one.txt'), 'utf8'), 'partial-corrupt')
})
test('a same-object edit during approval is rejected before truncate', async t => {
  const { lab, plan } = await setup(t)
  await assert.rejects(() => lab.apply(plan.planId, { request: async () => {
    await writeFile(join(lab.data, 'one.txt'), 'concurrent-owner-edit')
    return 'allowed-once'
  } }), /CONTENT_DRIFT/)
  assert.equal(await readFile(join(lab.data, 'one.txt'), 'utf8'), 'concurrent-owner-edit')
})
test('corrupted journal, extra file and live-lock recovery attempts are refused', async t => {
  const { lab, plan } = await setup(t)
  const journal = join(lab.control, 'journal.jsonl'), original = await readFile(journal)
  await writeFile(journal, '{"value":{"state":"COMMITTED"},"signature":"forged"}\n')
  await assert.rejects(() => lab.apply(plan.planId, approved), /JOURNAL_INTEGRITY/)
  await writeFile(journal, original)
  await writeFile(join(lab.data, 'unexpected.txt'), 'unrelated')
  await assert.rejects(() => lab.apply(plan.planId, approved), /MEMBERS_CHANGED/)
  await rm(join(lab.data, 'unexpected.txt'))
  assert.equal((await lab.apply(plan.planId, approved)).state, 'COMMITTED')
})
test('real child process termination retains its lock and explicit recovery verifies prior bytes', async t => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'ab-lab-crash-')); t.after(() => rm(stateRoot, { recursive: true, force: true }))
  const child = fork(new URL('./fixtures/maintenance-lab-worker.mjs', import.meta.url), [stateRoot], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
  let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk })
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL') })
  const message = await Promise.race([once(child, 'message').then(([value]) => value), once(child, 'exit').then(() => { throw new Error(`child exited before checkpoint: ${stderr}`) })])
  t.after(() => rm(message.root, { recursive: true, force: true }))
  const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited
  const runtime = new ArmorBreakRuntime({ stateRoot }); await runtime.init()
  const lab = await reopenSyntheticMaintenance(runtime, message.root, context)
  await assert.rejects(() => lab.rollback(message.planId, approved), /LOCKED_RECOVERY_REQUIRED/)
  await lab.releaseExitedProcessLock(child.pid)
  assert.equal((await lab.rollback(message.planId, approved)).state, 'ROLLED_BACK')
  assert.equal(await readFile(join(lab.data, 'first.txt'), 'utf8'), 'before-first')
  assert.equal(await readFile(join(lab.data, 'second.txt'), 'utf8'), 'before-second')
})
