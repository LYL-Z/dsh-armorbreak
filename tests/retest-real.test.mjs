import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { auditHandshake, hostArgs, hostVerdict, newRunId, redact, runProvider, sanitize, validateTask } from '../scripts/v2/retest-real.mjs'

test('retest redacts known token shapes and explicit secrets', () => {
  const secret = 'sk-live-abcdefghijklmnop'
  const text = redact(`key ${secret} Bearer abcdefghijk AIza123456789012345678901234 token=plain-secret`, [secret])
  for (const value of [secret, 'abcdefghijk', 'AIza123456789012345678901234', 'plain-secret']) assert.ok(!text.includes(value), value)
  assert.ok(text.includes('[REDACTED]'))
})

test('retest host args are plan/read-only and never yolo or skip-trust', () => {
  for (const key of ['claude', 'antigravity', 'zcode']) {
    const args = hostArgs(key, 'read only prompt', 'D:/dsh-ABM/armorbreak').join(' ')
    assert.match(args, /plan/)
    assert.ok(!/yolo|skip-trust|bypassPermissions|dangerously/i.test(args), args)
  }
})

test('retest rejects historical, concurrent, foreign and non-exact-README tasks', () => {
  const root = mkdtempSync(join(tmpdir(), 'abm-retest-'))
  const taskId = 'task_test_retest'
  const otherId = 'task_test_concurrent'
  const dir = join(root, '.armorbreak/tasks', taskId)
  const otherDir = join(root, '.armorbreak/tasks', otherId)
  const reportPath = join(dir, 'report.md')
  const body = '# test report\n'
  mkdirSync(dir, { recursive: true })
  mkdirSync(otherDir, { recursive: true })
  writeFileSync(join(root, 'README.md'), '# workspace readme\n')
  writeFileSync(reportPath, body)
  writeFileSync(join(dir, 'evidence.jsonl'), `${JSON.stringify({ id: 'ev_1' })}\n`)
  const task = {
    id: taskId, state: 'COMPLETED', operator: 'test-host', workspace: root,
    targetPath: join(root, 'README.md'), createdAt: new Date().toISOString(),
    report: { path: reportPath, sha256: createHash('sha256').update(body).digest('hex') },
  }
  writeFileSync(join(dir, 'task.json'), JSON.stringify(task))
  writeFileSync(join(otherDir, 'task.json'), JSON.stringify({ ...task, id: otherId }))
  try {
    const started = new Date(Date.now() - 5000).toISOString()
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'test-host', root, workspace: root }).pass, true)
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'test-host', root, workspace: root, beforeIds: new Set([taskId]) }).pass, false)
    assert.equal(validateTask({ taskId: otherId, startedAt: started, operator: 'test-host', root, workspace: root, beforeIds: new Set([taskId]) }).pass, false)
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'other', root, workspace: root }).pass, false)
    writeFileSync(join(dir, 'task.json'), JSON.stringify({ ...task, targetPath: join(root, '..', 'README.md') }))
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'test-host', root, workspace: root }).pass, false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('retest rejects a task whose README target is reached through a symlink', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'abm-retest-linked-readme-'))
  const workspace = join(root, 'workspace')
  const outside = join(root, 'outside')
  const taskId = 'task_test_linked_readme'
  const readmePath = join(workspace, 'README.md')
  const taskDir = join(workspace, '.armorbreak/tasks', taskId)
  try {
    mkdirSync(taskDir, { recursive: true })
    mkdirSync(outside, { recursive: true })
    writeFileSync(join(outside, 'README.md'), '# outside synthetic README\n')
    try {
      symlinkSync(outside, readmePath, process.platform === 'win32' ? 'junction' : 'dir')
    } catch (error) {
      if (['EPERM', 'EACCES', 'ENOTSUP', 'UNKNOWN'].includes(error?.code)) {
        t.skip(`directory link creation is unavailable: ${String(error.code)}`)
        return
      }
      throw error
    }
    const task = {
      id: taskId,
      state: 'COMPLETED',
      operator: 'test-host',
      workspace,
      targetPath: readmePath,
      createdAt: new Date().toISOString(),
      report: { path: join(taskDir, 'report.md'), sha256: createHash('sha256').update('# test report\n').digest('hex') },
    }
    writeFileSync(task.report.path, '# test report\n')
    writeFileSync(join(taskDir, 'evidence.jsonl'), `${JSON.stringify({ id: 'ev_linked' })}\n`)
    writeFileSync(join(taskDir, 'task.json'), JSON.stringify(task))
    const started = new Date(Date.now() - 5000).toISOString()
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'test-host', root: workspace, workspace }).pass, false)
  } finally {
    try {
      if (process.platform === 'win32') rmdirSync(readmePath)
      else unlinkSync(readmePath)
    } catch { /* absent when the OS refused link creation */ }
    rmSync(root, { recursive: true, force: true })
  }
})

test('retest host verdict only passes a fully verified authenticated run', () => {
  const states = {
    cliPresent: 'PASS', userConfirmed: 'CONFIRMED', credentialPresent: 'PASS',
    mcpHandshake: 'PASS', accountAuth: 'PASS', modelExecution: 'PASS', taskCompleted: 'PASS',
  }
  assert.equal(hostVerdict(states, true), 'PASS')
  assert.equal(hostVerdict({ ...states, accountAuth: 'NOT_RUN' }, true), 'FAIL')
  assert.equal(hostVerdict({ ...states, userConfirmed: 'NOT_CONFIRMED' }, true), 'FAIL')
  assert.equal(hostVerdict(states, false), 'FAIL')
})

test('retest audit must bind runId, pid, principal, workspace and all L0 tool calls', () => {
  const root = mkdtempSync(join(tmpdir(), 'abm-retest-audit-'))
  const path = join(root, 'audit.jsonl')
  const runId = 'run-test'
  const at = new Date().toISOString()
  const base = { schemaVersion: 'armorbreak.mcp-audit/v1', at, pid: 4242, principal: 'test-host', workspace: root, runId }
  const entries = [
    { ...base, event: 'initialize', clientInfo: { name: 'test-client', version: '1' } },
    { ...base, event: 'tools/list', tools: 3 },
    { ...base, event: 'tools/call', tool: 'armorbreak_health', ok: true },
    { ...base, event: 'tools/call', tool: 'armorbreak_analyze', ok: true },
    { ...base, event: 'tools/call', tool: 'armorbreak_report', ok: true },
  ]
  writeFileSync(path, entries.map((entry) => JSON.stringify(entry)).join('\n') + '\n')
  try {
    const started = new Date(Date.now() - 2000).toISOString()
    assert.equal(auditHandshake('claude', started, { runId, operator: 'test-host', workspace: root, path }).pass, true)
    assert.equal(auditHandshake('claude', started, { runId: 'other-run', operator: 'test-host', workspace: root, path }).pass, false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('retest sanitize keeps JSON valid and truncates fields, not the document', () => {
  const safe = sanitize({ long: 'x'.repeat(5000), nested: { token: 'sk-live-abcdefghijklmnop' } }, [], 128)
  const parsed = JSON.parse(JSON.stringify(safe))
  assert.ok(parsed.long.length <= 128)
  assert.equal(parsed.nested.token, '[REDACTED]')
})

test('retest provider preparation is network-free and run ids are unique', async () => {
  const spec = { id: 'test', label: 'Test', kind: 'openai-compatible', baseUrl: 'https://invalid.test', baseUrlEnv: 'TEST_BASE_URL', model: 'test-model', keyEnv: 'ARMORBREAK_TEST_ABSENT' }
  const prepared = await runProvider(spec, { run: false })
  assert.equal(prepared.status, 'PREPARED')
  assert.equal(prepared.details.credentialPresent, false)
  assert.notEqual(newRunId('x'), newRunId('x'))
})
