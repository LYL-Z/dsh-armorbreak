import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { EvidenceStore } from '../packages/core/src/evidence.js'

test('evidence metadata recursively redacts secret fields and credential-shaped log text', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'abm-evidence-redaction-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const taskDir = join(root, 'task')
  mkdirSync(taskDir)
  const store = new EvidenceStore({ taskDir, taskId: 'synthetic-task' })
  const sentinels = ['FAKE-META-SECRET-DO-NOT-PERSIST', 'sk-FAKEEVIDENCECREDENTIAL123456789']
  const record = await store.addEvidence({
    title: 'synthetic redaction test',
    meta: {
      log: { api_key: sentinels[0], nested: { authorization: `Bearer ${sentinels[0]}` } },
      rawLog: `provider response included ${sentinels[1]}`,
    },
  })
  const stored = readFileSync(join(taskDir, 'evidence.jsonl'), 'utf8')
  for (const secret of sentinels) {
    assert.equal(JSON.stringify(record).includes(secret), false)
    assert.equal(stored.includes(secret), false)
  }
  assert.equal(record.meta.log.api_key, '[REDACTED]')
  assert.equal(record.meta.log.nested.authorization, '[REDACTED]')
})
