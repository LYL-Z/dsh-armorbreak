/**
 * Stage D tests: presentation model (no misleading UI labels) and the loopback-only
 * read-only task/tool routes used by the browser workbench.
 */
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  findingRows,
  isolationPresentation,
  policyPresentation,
  queueRows,
  taskRows,
  toolsPresentation,
} from '../lib/core/presentation.js'
import { createStateHandler, createTasksHandler, createToolsHandler } from '../index.js'

function fakeResponse() {
  const captured = { status: null, headers: null, body: '', json: null }
  return {
    captured,
    writeHead(status, headers) {
      captured.status = status
      captured.headers = headers
    },
    end(body = '') {
      captured.body = String(body)
      try {
        captured.json = JSON.parse(captured.body)
      } catch {
        captured.json = null
      }
    },
  }
}

function fakeRuntime(overrides = {}) {
  const task = {
    id: 'task_test',
    title: 'sample triage',
    state: 'COMPLETED',
    workflowId: 'BinaryStaticAnalysis',
    targetPath: 'C:/work/sample.exe',
    stats: { evidence: 3, findings: 1 },
    report: { format: 'markdown', path: 'C:/work/.armorbreak/tasks/task_test/reports/r.md', sha256: 'a'.repeat(64) },
  }
  const state = {
    version: 'test',
    workspace: 'C:/work',
    workspaceBinding: 'most-recently-used',
    environment: { platform: 'win32' },
    isolation: { available: true, provider: 'docker' },
    policy: { authorizations: [] },
    registry: { capabilities: 41, domains: ['sast'], diagnostics: [] },
    capabilities: [],
    tasks: [task],
    queue: [],
    ui: {
      isolation: isolationPresentation({ available: true, provider: 'docker' }),
      policy: policyPresentation({ authorizations: [] }),
      tasks: taskRows([task]),
      tools: toolsPresentation([{ domain: 'sast', id: 'sast.scan', title: 'scan', riskLevel: 'L0', targetKind: 'directory', externalTools: [] }], { available: true, provider: 'docker' }),
    },
  }
  const runtime = {
    lastWorkspace: 'C:/work',
    defaultWorkspace: () => 'C:/work',
    stateSummary: async () => state,
    queue: { status: () => null, snapshot: () => [] },
    workspace: () => ({
      taskStore: {
        get: async () => task,
        summary: () => ({ id: task.id, title: task.title, state: task.state, stats: task.stats, report: task.report, steps: [] }),
        evidenceStore: () => ({ readFindings: async () => ({ findings: [{ id: 'f1', title: 'finding', severity: 'high', verification: 'hypothesis', cwe: 'CWE-95', target: 'src/app.js' }] }) }),
      },
    }),
    ...overrides,
  }
  return { runtime, state }
}

function req(url, options = {}) {
  return { method: options.method ?? 'GET', url, socket: { remoteAddress: options.remoteAddress ?? '127.0.0.1' } }
}

test('isolation labels never claim verified isolation without a self-test', () => {
  const available = isolationPresentation({ available: true, provider: 'docker' })
  assert.equal(available.state, 'DaemonReady')
  assert.equal(available.selfTested, false)
  assert.match(available.label, /未执行隔离自检|not self-tested/i)
  assert.equal(isolationPresentation({ available: false, reason: 'no container runtime found (Docker CLI absent)' }).state, 'Unavailable')
  assert.equal(isolationPresentation(null).state, 'Unknown')
})

test('L2 label reports authorization count instead of a misleading zero', () => {
  const none = policyPresentation({ authorizations: [] })
  assert.match(none.l2.label, /无授权目标/)
  assert.equal(none.l2.activeAuthorizations, 0)
  const active = policyPresentation({ authorizations: [{ id: 'a1', active: true }] })
  assert.match(active.l2.label, /1 个授权目标/)
  assert.match(active.l3.label, /始终拒绝/)
})

test('task and tool presentations expose bounded, secret-free metadata', () => {
  const rows = taskRows([{ id: 't1', title: 'x'.repeat(300), state: 'PARTIAL_SUCCESS', workflowId: 'W', targetPath: 'C:/a/b.exe', stats: { evidence: 2, findings: 3 }, report: { format: 'html', path: 'C:/r.html', sha256: 'b'.repeat(64) } }])
  assert.equal(rows[0].title.length, 160)
  assert.equal(rows[0].target, 'b.exe')
  assert.equal(rows[0].report.sha256.length, 64)
  assert.deepEqual(findingRows([{ id: 'f', title: 't'.repeat(300), severity: 'critical', verification: 'corroborated', target: 'x'.repeat(300) }])[0].title.length, 200)
  const tools = toolsPresentation([{ domain: 'sast', id: 'sast.semgrep', title: 'semgrep', riskLevel: 'L0', targetKind: 'directory', externalTools: ['semgrep'] }], { available: false, reason: 'absent' })
  assert.equal(tools.domains[0].capabilityCount, 1)
  assert.deepEqual(tools.domains[0].externalTools, [{ name: 'semgrep', availability: 'not-probed' }])
  assert.equal(queueRows([{ taskId: 't', state: 'RUNNING', queued: false }])[0].state, 'RUNNING')
})

test('task and tool routes return read-only JSON for loopback callers', async () => {
  const { runtime } = fakeRuntime()
  const listRes = fakeResponse()
  await createTasksHandler(runtime)(req('/armorbreak/tasks'), listRes)
  assert.equal(listRes.captured.status, 200)
  assert.equal(listRes.captured.json.tasks[0].id, 'task_test')
  assert.equal(listRes.captured.json.workspaceBinding, 'most-recently-used')

  const detailRes = fakeResponse()
  await createTasksHandler(runtime)(req('/armorbreak/tasks?id=task_test'), detailRes)
  assert.equal(detailRes.captured.status, 200)
  assert.equal(detailRes.captured.json.task.id, 'task_test')
  assert.equal(detailRes.captured.json.findings[0].verification, 'hypothesis')
  assert.equal(detailRes.captured.json.findings[0].description, undefined, 'findings must not leak descriptions/excerpts')

  const toolsRes = fakeResponse()
  await createToolsHandler(runtime)(req('/armorbreak/tools'), toolsRes)
  assert.equal(toolsRes.captured.status, 200)
  assert.equal(toolsRes.captured.json.domains[0].domain, 'sast')
  assert.equal(toolsRes.captured.json.isolation.selfTested, false)
})

test('all workbench routes enforce loopback, GET/HEAD and reject workspace enumeration', async () => {
  const { runtime } = fakeRuntime()
  for (const handler of [createStateHandler(runtime), createTasksHandler(runtime), createToolsHandler(runtime)]) {
    const remote = fakeResponse()
    await handler(req('/armorbreak/tasks', { remoteAddress: '10.0.0.9' }), remote)
    assert.equal(remote.captured.status, 403)
    const post = fakeResponse()
    await handler(req('/armorbreak/tasks', { method: 'POST' }), post)
    assert.equal(post.captured.status, 405)
    const enumAttempt = fakeResponse()
    await handler(req('/armorbreak/tasks?workspace=C%3A%5CWindows'), enumAttempt)
    assert.equal(enumAttempt.captured.status, 403)
  }
})
