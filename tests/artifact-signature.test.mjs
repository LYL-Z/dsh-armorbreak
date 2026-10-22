import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { signArtifact, verifyArtifactSignature } from '../scripts/v2/artifact-signature.mjs'

test('Ed25519 artifact signatures detect tampering and wrong keys', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-sign-'))
  const artifact = join(dir, 'artifact.bin')
  await writeFile(artifact, 'armorbreak portable artifact')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const signature = await signArtifact(artifact, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  assert.equal(signature.algorithm, 'ed25519')
  assert.equal(await verifyArtifactSignature(artifact, signature.signature, publicKey.export({ type: 'spki', format: 'pem' })), true)
  await writeFile(artifact, 'tampered')
  assert.equal(await verifyArtifactSignature(artifact, signature.signature, publicKey.export({ type: 'spki', format: 'pem' })), false)
  const other = generateKeyPairSync('ed25519')
  assert.equal(await verifyArtifactSignature(artifact, signature.signature, other.publicKey.export({ type: 'spki', format: 'pem' })), false)
})
