import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import test from 'node:test'

import { AuditLog } from '../packages/core/src/audit.js'
import { EvidenceStore } from '../packages/core/src/evidence.js'
import { withAppendFileLock } from '../packages/core/src/append-lock.js'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const EVIDENCE_MODULE = pathToFileURL(join(ROOT, 'packages/core/src/evidence.js')).href
const AUDIT_MODULE = pathToFileURL(join(ROOT, 'packages/core/src/audit.js')).href

async function temporaryRoot(prefix) {
  return mkdtemp(join(tmpdir(), prefix))
}

function runChildren(source, args, count) {
  return Promise.all(Array.from({ length: count }, (_, index) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', source, ...args(index)], {
      cwd: ROOT,
      env: { ...process.env, TEMP: process.env.TEMP, TMP: process.env.TMP },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    let stderr = ''
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk.toString()).slice(-4000) })
    child.once('error', reject)
    child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`append child ${index} exited ${code}: ${stderr}`)))
  })))
}

test('24 processes append evidence records without forking the per-task hash chain', async () => {
  const base = await temporaryRoot('abm-evidence-append-lock-')
  try {
    const taskDir = join(base, 'task')
    const source = `import { EvidenceStore } from ${JSON.stringify(EVIDENCE_MODULE)}; const store = new EvidenceStore({ taskDir: process.argv[1], taskId: 'parallel-task' }); await store.addEvidence({ title: process.argv[2], excerpt: 'parallel append' });`
    await runChildren(source, (index) => [taskDir, `item-${index}`], 24)

    const store = new EvidenceStore({ taskDir, taskId: 'parallel-task' })
    const records = await store.readEvidence(100)
    const verification = await store.verifyChain()
    assert.equal(records.length, 24)
    assert.equal(verification.valid, true, verification.reason ?? 'evidence chain must remain valid')
    assert.deepEqual(records.map((record) => record.index), Array.from({ length: 24 }, (_, index) => index + 1))
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('24 processes append audit records with a continuous sequence and hash chain', async () => {
  const base = await temporaryRoot('abm-audit-append-lock-')
  try {
    const auditFile = join(base, 'audit.jsonl')
    const source = `import { AuditLog } from ${JSON.stringify(AUDIT_MODULE)}; const log = new AuditLog({ file: process.argv[1] }); await log.append({ action: 'parallel', item: process.argv[2] });`
    await runChildren(source, (index) => [auditFile, `item-${index}`], 24)

    const log = new AuditLog({ file: auditFile })
    const records = await log.read({ limit: 100 })
    const verification = await log.verify()
    assert.equal(records.length, 24)
    assert.equal(verification.valid, true, verification.reason ?? 'audit chain must remain valid')
    assert.deepEqual(records.map((record) => record.seq), Array.from({ length: 24 }, (_, index) => index + 1))
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('lock contention times out without running the append callback', async () => {
  const base = await temporaryRoot('abm-append-lock-timeout-')
  const file = join(base, 'audit.jsonl')
  const lockPath = `${file}.append.lock`
  await writeFile(lockPath, JSON.stringify({ pid: -1, host: 'test', token: 'held' }))
  let callbackRan = false
  try {
    await assert.rejects(
      () => withAppendFileLock(file, async () => { callbackRan = true }, { timeoutMs: 100 }),
      (error) => error.code === 'APPEND_LOCK_TIMEOUT',
    )
    assert.equal(callbackRan, false)
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})
