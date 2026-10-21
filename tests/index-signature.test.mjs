import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { VersionedIndex } from '../lib/connectivity/versionedIndex.js'

test('index publishes signed descriptors, rejects tamper and verifies with public key', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-index-sig-'))
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const index = new VersionedIndex({ root })
  const descriptor = await index.publish([{ id: 'a', version: '1' }], { signingKey: privateKey, keyId: 'test-key' })
  assert.equal(descriptor.signature.alg, 'ed25519')
  assert.equal(descriptor.signature.keyId, 'test-key')
  const loaded = await index.read({ publicKey, requireSignature: true })
  assert.deepEqual(loaded.index.entries, [{ id: 'a', version: '1' }])

  const fs = await import('node:fs/promises')
  const pointer = JSON.parse(await fs.readFile(index.pointer, 'utf8'))
  pointer.signature.signature = 'AAAA'
  await fs.writeFile(index.pointer, JSON.stringify(pointer))
  await assert.rejects(() => index.read({ publicKey, requireSignature: true }), /signature/i)
})

test('unsigned index is rejected when signature is required', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-index-sig2-'))
  const index = new VersionedIndex({ root })
  await index.publish([{ id: 'b' }])
  await assert.rejects(() => index.read({ requireSignature: true }), /signature/i)
})
