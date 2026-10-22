import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { hostArgs, newRunId, redact, runProvider, validateTask } from '../scripts/v2/retest-real.mjs'

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

test('retest rejects historical, foreign and non-README tasks', () => {
  const root = mkdtempSync(join(tmpdir(), 'abm-retest-'))
  const taskId = 'task_test_retest'
  const dir = join(root, '.armorbreak/tasks', taskId)
  const reportPath = join(dir, 'report.md')
  const body = '# test report\n'
  mkdirSync(dir, { recursive: true })
  writeFileSync(reportPath, body)
  writeFileSync(join(dir, 'evidence.jsonl'), `${JSON.stringify({ id: 'ev_1' })}\n`)
  writeFileSync(join(dir, 'task.json'), JSON.stringify({
    id: taskId, state: 'COMPLETED', operator: 'test-host', workspace: root,
    targetPath: join(root, 'README.md'), createdAt: new Date().toISOString(),
    report: { path: reportPath, sha256: createHash('sha256').update(body).digest('hex') },
  }))
  try {
    const started = new Date(Date.now() - 5000).toISOString()
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'test-host', root, workspace: root }).pass, true)
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'test-host', root, workspace: root, beforeIds: new Set([taskId]) }).pass, false)
    assert.equal(validateTask({ taskId, startedAt: started, operator: 'other', root, workspace: root }).pass, false)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('retest provider preparation is network-free and run ids are unique', async () => {
  const spec = { id: 'test', label: 'Test', kind: 'openai-compatible', baseUrl: 'https://invalid.test', baseUrlEnv: 'TEST_BASE_URL', model: 'test-model', keyEnv: 'ARMORBREAK_TEST_ABSENT' }
  const prepared = await runProvider(spec, { run: false })
  assert.equal(prepared.status, 'PREPARED')
  assert.equal(prepared.details.credentialPresent, false)
  assert.notEqual(newRunId('x'), newRunId('x'))
})
