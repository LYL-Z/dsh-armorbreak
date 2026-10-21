import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { LayeredCache } from '../lib/connectivity/layeredCache.js'
import { VersionedIndex } from '../lib/connectivity/versionedIndex.js'

test('layered cache stages/activates core and falls back safely on failed activation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-cache-'))
  const cache = new LayeredCache({ root })
  const staged = await cache.stage({ layer: 'core', version: '1.0.0', files: { 'rules.json': '{"v":1}', 'readme.txt': 'core' } })
  const activated = await cache.activate({ layer: 'core', stagingId: staged.stagingId })
  assert.equal(activated.version, '1.0.0')
  assert.equal((await cache.active('core')).version, '1.0.0')

  const bad = await cache.stage({ layer: 'core', version: '2.0.0', files: { 'rules.json': '{"v":2}' } })
  await writeFile(join(bad.dir, 'rules.json'), '{"v":"tampered"}')
  await assert.rejects(() => cache.activate({ layer: 'core', stagingId: bad.stagingId }), /hash mismatch/)
  assert.equal((await cache.active('core')).version, '1.0.0', 'active pointer must stay on the healthy version')
})

test('layered cache rollback restores the previous active descriptor', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-cache-'))
  const cache = new LayeredCache({ root })
  const v1 = await cache.stage({ layer: 'extension', version: '1', files: { a: '1' } })
  await cache.activate({ layer: 'extension', stagingId: v1.stagingId })
  const v2 = await cache.stage({ layer: 'extension', version: '2', files: { a: '2' } })
  await cache.activate({ layer: 'extension', stagingId: v2.stagingId })
  assert.equal((await cache.active('extension')).version, '2')
  const restored = await cache.rollback('extension')
  assert.equal(restored.version, '1')
  assert.equal((await cache.active('extension')).version, '1')
})

test('versioned CAS index detects tampering and rolls back to previous hash', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-index-'))
  const index = new VersionedIndex({ root })
  const first = await index.publish([{ id: 'a', version: '1' }])
  const second = await index.publish([{ id: 'b', version: '2' }])
  assert.notEqual(first.hash, second.hash)
  assert.deepEqual((await index.read()).index.entries, [{ id: 'b', version: '2' }])
  await writeFile(second.path, '{"tampered":true}')
  await assert.rejects(() => index.read(), /hash mismatch/)
  await index.rollback()
  assert.deepEqual((await index.read()).index.entries, [{ id: 'a', version: '1' }])
})
