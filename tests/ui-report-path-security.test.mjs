import assert from 'node:assert/strict'
import test from 'node:test'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createReportHandler } from '../index.js'

function response() {
  const captured = { status: null, body: '', json: null }
  return {
    captured,
    writeHead(status) { captured.status = status },
    end(body = '') {
      captured.body = String(body)
      try { captured.json = JSON.parse(captured.body) } catch { captured.json = null }
    },
  }
}

function req(url) {
  return { method: 'GET', url, headers: {}, socket: { remoteAddress: '127.0.0.1' } }
}

test('workbench report preview refuses a report path outside its task reports root', async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), 'armorbreak-ui-report-'))
  t.after(() => rm(workspace, { recursive: true, force: true }))

  const taskId = 'task_security_test'
  const taskDirectory = join(workspace, '.armorbreak', 'tasks', taskId)
  const reportsRoot = join(taskDirectory, 'reports')
  await mkdir(reportsRoot, { recursive: true })
  const outsidePath = join(workspace, 'outside-report.md')
  const outsideText = 'SYNTHETIC_OUTSIDE_REPORT_SECRET'
  await writeFile(outsidePath, outsideText, 'utf8')
  const task = {
    id: taskId,
    report: {
      format: 'markdown',
      path: outsidePath,
      sha256: createHash('sha256').update(outsideText).digest('hex'),
    },
  }
  const taskStore = { taskDir: () => taskDirectory, get: async () => task }
  const runtime = {
    lastWorkspace: workspace,
    defaultWorkspace: () => workspace,
    workspace: () => ({ taskStore }),
  }

  const result = response()
  await createReportHandler(runtime)(req(`/armorbreak/report?taskId=${taskId}`), result)
  assert.equal(result.captured.status, 400)
  assert.doesNotMatch(result.captured.body, /SYNTHETIC_OUTSIDE_REPORT_SECRET/)
  assert.match(result.captured.json.error, /outside the task report directory/)
})
