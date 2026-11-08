import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { verifyV23PortableManifest } from '../scripts/v2/verify-v23-portable-manifest.mjs'

const hash = (value) => createHash('sha256').update(value).digest('hex')

function fixture(mutator = (manifest) => manifest) {
  const root = mkdtempSync(join(tmpdir(), 'v23-portable-manifest-'))
  const artifactPath = join(root, 'armorbreak-portable-2.3.1.tar.gz')
  const artifactBytes = Buffer.from('harmless portable archive fixture')
  const manifest = {
    schemaVersion: 'armorbreak.release-build/v1',
    commit: 'a'.repeat(40),
    version: '2.3.1',
    reproducible: true,
    artifact: 'armorbreak-portable-2.3.1.tar.gz',
    bytes: artifactBytes.length,
    sha256: hash(artifactBytes),
  }
  writeFileSync(artifactPath, artifactBytes)
  writeFileSync(`${artifactPath}.manifest.json`, JSON.stringify(mutator(manifest)))
  return { root, artifactPath, artifactBytes, manifest }
}

test('accepts an archive only when its bytes and build manifest bind to the expected source commit', (t) => {
  const item = fixture()
  t.after(() => rmSync(item.root, { recursive: true, force: true }))
  const verified = verifyV23PortableManifest(item.artifactPath, item.manifest.commit)
  assert.equal(verified.artifactSha256, hash(item.artifactBytes))
  assert.equal(verified.manifest.commit, item.manifest.commit)
})

test('rejects a previous source commit even when its archive manifest is internally consistent', (t) => {
  const item = fixture()
  t.after(() => rmSync(item.root, { recursive: true, force: true }))
  assert.throws(() => verifyV23PortableManifest(item.artifactPath, 'b'.repeat(40)), /exact source commit/)
})

test('rejects a modified archive whose SHA no longer matches the manifest', (t) => {
  const item = fixture()
  t.after(() => rmSync(item.root, { recursive: true, force: true }))
  writeFileSync(item.artifactPath, Buffer.from('tampered archive'))
  assert.throws(() => verifyV23PortableManifest(item.artifactPath, item.manifest.commit), /exact source commit/)
})

test('rejects an unapproved build manifest schema', (t) => {
  const item = fixture((manifest) => ({ ...manifest, schemaVersion: 'unknown/v9' }))
  t.after(() => rmSync(item.root, { recursive: true, force: true }))
  assert.throws(() => verifyV23PortableManifest(item.artifactPath, item.manifest.commit), /exact source commit/)
})
