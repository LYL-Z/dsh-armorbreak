import assert from 'node:assert/strict'
import { mkdtemp, realpath, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { runCli } from '../packages/cli/index.js'
import { createEngine } from '../packages/engine-node/index.js'
import { createProductApi } from '../workbench/product.mjs'
import { createWorkbenchServer } from '../workbench/server.mjs'

async function capture(fn) {
  const chunks = []
  const write = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true }
  try { await fn() } finally { process.stdout.write = write }
  return chunks.join('')
}

test('failed L0 task retry preserves the original record and completes after the file returns', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-retry-state-'))
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'abm-retry-ws-')))
  const principal = { id: 'alice', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  const sample = join(workspace, 'sample.txt')
  const ctx = { principal, workspaceId: workspace, requestId: 'fail-1', traceId: 'trace-fail' }
  await assert.rejects(() => engine.analyze(ctx, { capability: 'forensics.hash', target: sample }), /target file not found|TARGET_NOT_FOUND/)
  const failed = (await engine.listTasks(ctx))[0]
  assert.equal(failed.state, 'FAILED')
  const intruder = { principal: { id: 'mallory', kind: 'local-user' }, workspaceId: workspace, requestId: 'deny-1', traceId: 'trace-deny' }
  await assert.rejects(() => engine.retryTask(intruder, failed.id), (error) => error.code === 'POLICY_DENIED')
  await assert.rejects(() => engine.retryTask({ ...ctx, requestId: 'still-missing' }, failed.id), /target file not found|TARGET_NOT_FOUND/)
  const stillFailed = await engine.getTask(ctx, failed.id)
  assert.equal(stillFailed.state, 'FAILED')
  assert.equal(stillFailed.steps[0].status, 'FAILED')
  const parked = (await engine.listTasks({ ...ctx, requestId: 'list-parked' })).find((task) => task.retryOf === failed.id)
  assert.equal(parked.state, 'FAILED')
  assert.notEqual(parked.id, failed.id)

  await writeFile(sample, 'restored synthetic input\n')
  const retried = await engine.retryTask({ ...ctx, requestId: 'retry-ok' }, failed.id)
  assert.equal(retried.state, 'COMPLETED')
  assert.equal(retried.retryOf, failed.id)
  assert.notEqual(retried.taskId, failed.id)
  assert.ok(retried.evidenceIds.length >= 1)
  assert.match(retried.reportPath, /\.md$/)
  assert.equal((await engine.getTask(ctx, failed.id)).state, 'FAILED')
  const replay = await engine.retryTask({ ...ctx, requestId: 'retry-ok' }, failed.id)
  assert.equal(replay.taskId, retried.taskId)
  await assert.rejects(() => engine.retryTask({ ...ctx, requestId: 'retry-complete' }, retried.taskId), (error) => error.code === 'INVALID_REQUEST')
  await engine.close()
})

test('L1 retry is refused before a successor task exists', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-retry-l1-state-'))
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'abm-retry-l1-ws-')))
  const principal = { id: 'alice', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  const ctx = { principal, workspaceId: workspace, requestId: 'l1-create', traceId: 'trace-l1' }
  const elevated = (await engine.capabilities({ ...ctx, requestId: 'caps' })).find((item) => item.riskLevel !== 'L0')
  assert.ok(elevated, 'expected at least one capability above L0')
  const task = await engine.createTask(ctx, {
    title: 'elevated',
    objective: 'must not self-approve',
    targetKind: 'none',
    steps: [{ id: 'step', title: elevated.title, capabilityId: elevated.id }],
  })
  await engine.runtime.workspace(workspace).taskStore.transition(task, 'FAILED', 'synthetic terminal failure')
  await assert.rejects(() => engine.retryTask({ ...ctx, requestId: 'l1-retry' }, task.id), (error) => error.code === 'APPROVAL_REQUIRED')
  assert.equal((await engine.listTasks(ctx)).length, 1)
  await engine.close()
})

test('CLI and Workbench retry the same failed Core task without rewriting it', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-retry-cli-state-'))
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'abm-retry-cli-ws-')))
  const sample = join(workspace, 'sample.txt')
  const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'cli-local-user' }
  await assert.rejects(() => runCli(['analyze', '--capability', 'forensics.hash', '--target', sample, '--json'], { env }), /target file not found|TARGET_NOT_FOUND/)
  const listed = JSON.parse(await capture(() => runCli(['task', 'list', '--json'], { env })))
  const failed = listed.find((task) => task.state === 'FAILED')
  await writeFile(sample, 'cli restored input\n')
  const retried = JSON.parse(await capture(() => runCli(['task', 'retry', failed.id, '--json'], { env })))
  assert.equal(retried.state, 'COMPLETED')
  assert.equal(retried.retryOf, failed.id)
  const after = JSON.parse(await capture(() => runCli(['task', 'status', failed.id, '--json'], { env })))
  assert.equal(after.state, 'FAILED')

  const server = await createWorkbenchServer({ native: { workspaceId: workspace, stateRoot: join(stateRoot, 'workbench') } })
  try {
    const session = await (await fetch(`${server.url}/api/native/session`)).json()
    const headers = { 'content-type': 'application/json', 'x-armorbreak-session': session.csrf }
    const missing = join(workspace, 'panel.txt')
    const first = await fetch(`${server.url}/api/product/run`, { method: 'POST', headers, body: JSON.stringify({ action: 'file-integrity', target: 'panel.txt' }) })
    assert.equal(first.status, 400)
    await writeFile(missing, 'panel restored input\n')
    const rows = await (await fetch(`${server.url}/api/product/tasks`, { headers })).json()
    const panelFailed = rows.find((row) => row.retryable && row.capability === 'forensics.hash')
    assert.equal(panelFailed.state, 'FAILED')
    const retry = await fetch(`${server.url}/api/product/retry`, { method: 'POST', headers, body: JSON.stringify({ taskId: panelFailed.taskId }) })
    assert.equal(retry.status, 200)
    const body = await retry.json()
    assert.equal(body.state, 'COMPLETED')
    assert.equal(body.hostModified, false)
    const refreshed = await (await fetch(`${server.url}/api/product/tasks`, { headers })).json()
    assert.equal(refreshed.find((row) => row.taskId === panelFailed.taskId).state, 'FAILED')
    assert.equal(refreshed.find((row) => row.taskId === body.taskId).retryOf, panelFailed.taskId)
  } finally {
    await server.close()
  }
})

test('product retry rejects a completed task and an unrelated principal payload', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-retry-product-state-'))
  const workspace = await realpath(await mkdtemp(join(tmpdir(), 'abm-retry-product-ws-')))
  const sample = join(workspace, 'sample.txt')
  await writeFile(sample, 'already present\n')
  const principal = { id: 'alice', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  const ctx = { principal, workspaceId: workspace, requestId: 'product-run', traceId: 'trace-product' }
  const product = createProductApi({ engine, ctx })
  const done = await product.run({ action: 'file-integrity', target: 'sample.txt' })
  assert.equal(done.state, 'COMPLETED')
  await assert.rejects(() => product.retry({ taskId: done.taskId, extra: true }), /PRODUCT_INVALID_REQUEST/)
  await assert.rejects(() => product.retry({ taskId: done.taskId }), (error) => error.code === 'INVALID_REQUEST')
  await engine.close()
})
