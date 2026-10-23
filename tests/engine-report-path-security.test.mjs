import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { link, mkdir, mkdtemp, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'

async function withReportFixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'abm-engine-report-security-'))
  const workspace = join(root, 'workspace')
  const engine = await createEngine({
    stateRoot: join(root, 'state'),
    principals: [{ id: 'alice', kind: 'local-user', workspaces: [workspace] }],
  })
  const ctx = {
    principal: { id: 'alice', kind: 'local-user', sessionId: 'report-security-session' },
    workspaceId: workspace,
    requestId: 'report-security-create',
    traceId: 'report-security',
  }
  try {
    const task = await engine.createTask(ctx, { title: 'report path security', targetKind: 'none' })
    const store = engine.runtime.workspace(workspace).taskStore
    await run({ root, workspace, engine, store, task, ctx, reportsRoot: join(store.taskDir(task.id), 'reports') })
  } finally {
    await engine.close()
    await rm(root, { recursive: true, force: true })
  }
}

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

test('getReport rejects a task.report.path outside its task report directory', async () => {
  await withReportFixture(async ({ root, engine, store, task, ctx }) => {
    const content = 'SYNTHETIC_OUTSIDE_TASK_REPORT'
    const outsidePath = join(root, 'outside-report.md')
    await writeFile(outsidePath, content)
    task.report = { format: 'markdown', path: outsidePath, sha256: sha256(content) }
    await store.save(task)

    await assert.rejects(() => engine.getReport(ctx, task.id), (error) => error.code === 'POLICY_DENIED')
  })
})

test('getReport rejects a traversal task id before loading another task directory', async () => {
  await withReportFixture(async ({ engine, ctx }) => {
    await assert.rejects(() => engine.getReport(ctx, '../../loot'), (error) => error.code === 'POLICY_DENIED')
  })
})

test('getReport rejects a task reports root redirected to an outside junction', async () => {
  await withReportFixture(async ({ root, engine, store, task, ctx, reportsRoot }) => {
    const outsideReports = join(root, 'outside-reports')
    const retainedReports = join(store.taskDir(task.id), 'reports-retained')
    const content = 'SYNTHETIC_OUTSIDE_JUNCTION_REPORT'
    await mkdir(reportsRoot, { recursive: true })
    await mkdir(outsideReports, { recursive: true })
    await writeFile(join(outsideReports, 'report.md'), content)
    await rename(reportsRoot, retainedReports)
    await symlink(outsideReports, reportsRoot, process.platform === 'win32' ? 'junction' : 'dir')
    task.report = { format: 'markdown', path: join(reportsRoot, 'report.md'), sha256: sha256(content) }
    await store.save(task)

    await assert.rejects(() => engine.getReport(ctx, task.id), (error) => error.code === 'POLICY_DENIED')
  })
})

test('getReport rejects a reports-root junction swap in the open window', async () => {
  await withReportFixture(async ({ root, engine, store, task, ctx, reportsRoot }) => {
    const outsideReports = join(root, 'outside-race-reports')
    const retainedReports = join(store.taskDir(task.id), 'reports-race-retained')
    await mkdir(reportsRoot, { recursive: true })
    await mkdir(outsideReports, { recursive: true })
    const content = 'SYNTHETIC_OPEN_WINDOW_REPORT'
    const reportPath = join(reportsRoot, 'report.md')
    await writeFile(reportPath, content)
    await writeFile(join(outsideReports, 'report.md'), content)
    task.report = { format: 'markdown', path: reportPath, sha256: sha256(content) }
    await store.save(task)

    const originalOpen = fs.promises.open
    let swapped = false
    fs.promises.open = async function (...args) {
      if (!swapped && String(args[0]) === reportPath) {
        await rename(reportsRoot, retainedReports)
        await symlink(outsideReports, reportsRoot, process.platform === 'win32' ? 'junction' : 'dir')
        swapped = true
      }
      return originalOpen.apply(this, args)
    }
    syncBuiltinESMExports()
    try {
      await assert.rejects(() => engine.getReport(ctx, task.id), (error) => error.code === 'POLICY_DENIED')
    } finally {
      fs.promises.open = originalOpen
      syncBuiltinESMExports()
    }
    assert.equal(swapped, true, 'the test must swap the report root immediately before open')
  })
})

test('getReport fails closed when report metadata has no SHA-256 digest', async () => {
  await withReportFixture(async ({ engine, store, task, ctx, reportsRoot }) => {
    await mkdir(reportsRoot, { recursive: true })
    const reportPath = join(reportsRoot, 'report.md')
    await writeFile(reportPath, 'SYNTHETIC_REPORT_WITHOUT_DIGEST')
    task.report = { format: 'markdown', path: reportPath }
    await store.save(task)

    await assert.rejects(() => engine.getReport(ctx, task.id), (error) => error.code === 'EVIDENCE_MISMATCH')
  })
})

test('getReport rejects a report file with an outside hard-link alias', async (t) => {
  await withReportFixture(async ({ root, engine, store, task, ctx, reportsRoot }) => {
    await mkdir(reportsRoot, { recursive: true })
    const outsidePath = join(root, 'outside-hardlink-source.md')
    const reportPath = join(reportsRoot, 'report.md')
    const content = 'SYNTHETIC_HARDLINK_REPORT'
    await writeFile(outsidePath, content)
    try {
      await link(outsidePath, reportPath)
    } catch (error) {
      if (['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'EXDEV'].includes(error.code)) {
        t.skip(`hard links unavailable on this filesystem: ${error.code}`)
        return
      }
      throw error
    }
    task.report = { format: 'markdown', path: reportPath, sha256: sha256(content) }
    await store.save(task)

    await assert.rejects(() => engine.getReport(ctx, task.id), (error) => error.code === 'POLICY_DENIED')
  })
})

