import assert from 'node:assert/strict'
import { link, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createSparseStreamingFixture } from '../scripts/v2/verify-streaming-10gb.mjs'

test('streaming fixture creation leaves the old predictable hard-link target untouched', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'abm-stream-hardlink-test-'))
  const protectedPath = join(parent, 'protected.bin')
  const oldPredictablePath = join(parent, `abm-stream-10g-${process.pid}.bin`)
  const original = Buffer.from('protected user data')
  await writeFile(protectedPath, original)
  await link(protectedPath, oldPredictablePath)

  const fixture = await createSparseStreamingFixture(1024, parent)
  try {
    assert.notEqual(fixture.file, oldPredictablePath)
    assert.equal((await stat(fixture.file)).size, 1024)
    assert.deepEqual(await readFile(protectedPath), original)
  } finally {
    await rm(fixture.directory, { recursive: true, force: true })
    await rm(parent, { recursive: true, force: true })
  }
})
