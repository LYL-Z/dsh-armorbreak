import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { EvidenceStore } from '../packages/core/src/evidence.js'

async function tempDir() {
  return mkdtemp(join(tmpdir(), 'abm-evidence-tail-anchor-'))
}

test('evidence chain detects tail truncation against its persisted head anchor', async () => {
  const root = await tempDir()
  try {
    const taskDir = join(root, 'task')
    await mkdir(taskDir, { recursive: true })
    const store = new EvidenceStore({ taskId: 'task-tail', taskDir })
    for (let index = 0; index < 5; index += 1) {
      await store.addEvidence({ title: `e${index}`, excerpt: `record ${index}` })
    }

    const evidenceFile = join(taskDir, 'evidence.jsonl')
    const lines = (await readFile(evidenceFile, 'utf8')).trim().split('\n')
    await writeFile(evidenceFile, `${lines.slice(0, 3).join('\n')}\n`)

    const chain = await store.verifyChain()
    assert.equal(chain.valid, false)
    assert.equal(chain.records, 3)
    assert.equal(chain.reason, 'evidence head anchor mismatch')
    await assert.rejects(
      () => store.addEvidence({ title: 'must not extend truncated history', excerpt: 'new record' }),
      (error) => error.code === 'EVIDENCE_CHAIN_INVALID',
    )
    assert.equal((await readFile(evidenceFile, 'utf8')).trim().split('\n').length, 3)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('legacy non-empty evidence without a head anchor fails closed', async () => {
  const root = await tempDir()
  try {
    const taskDir = join(root, 'task')
    await mkdir(taskDir, { recursive: true })
    await writeFile(join(taskDir, 'evidence.jsonl'), `${JSON.stringify({ index: 1, prevHash: 'genesis', hash: 'a'.repeat(64) })}\n`)
    const store = new EvidenceStore({ taskId: 'legacy-task', taskDir })

    const chain = await store.verifyChain()
    assert.equal(chain.valid, false)
    assert.equal(chain.reason, 'evidence head anchor missing')
    await assert.rejects(
      () => store.addEvidence({ title: 'must not bless legacy history', excerpt: 'new record' }),
      (error) => error.code === 'EVIDENCE_CHAIN_INVALID',
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
