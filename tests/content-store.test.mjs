import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { hashFileStream, importContent } from '../lib/workers/contentStore.js'

test('streaming hash matches a one-shot hash and returns byte count', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-cas-'))
  const payload = Buffer.alloc(4 * 1024 * 1024 + 17)
  for (let i = 0; i < payload.length; i += 1) payload[i] = (i * 31 + 7) & 0xff
  const file = join(dir, 'sample.bin')
  await writeFile(file, payload)
  const result = await hashFileStream(file)
  assert.equal(result.bytes, payload.length)
  assert.equal(result.sha256, createHash('sha256').update(payload).digest('hex'))
})

test('CAS import deduplicates by hash and rejects a mismatched expected hash', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-cas-'))
  const source = join(dir, 'source.bin')
  const payload = Buffer.from('ArmorBreak CAS fixture')
  await writeFile(source, payload)
  const first = await importContent({ sourcePath: source, storeRoot: join(dir, 'store') })
  const second = await importContent({ sourcePath: source, storeRoot: join(dir, 'store') })
  assert.equal(first.sha256, second.sha256)
  assert.equal(second.deduplicated, true)
  assert.deepEqual(await readFile(first.path), payload)
  await assert.rejects(() => importContent({ sourcePath: source, storeRoot: join(dir, 'store'), expectedSha256: '0'.repeat(64) }), /hash mismatch/)
})
