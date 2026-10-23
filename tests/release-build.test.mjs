import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

import { verifyArtifactSignature } from '../scripts/v2/artifact-signature.mjs'

test('release build is reproducible, hashed, SBOM-backed and test-signature verifiable', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-release-'))
  const out = join(root, 'dist')
  const evidence = join(root, 'release-build.json')
  try {
    const build = spawnSync(process.execPath, ['scripts/v2/build-release.mjs', '--out', out, '--evidence', evidence, '--no-portable-evidence'], { cwd: process.cwd(), encoding: 'utf8', timeout: 300_000 })
    assert.equal(build.status, 0, build.stderr)
    const manifest = JSON.parse(await readFile(evidence, 'utf8'))
    assert.equal(manifest.reproducible, true)
    assert.equal(manifest.signature.valid, true)
    assert.equal(manifest.signature.testKey, true)
    assert.equal(manifest.productionSigned, false)
    assert.match(manifest.sha256, /^[a-f0-9]{64}$/)
    assert.ok(manifest.files > 100)
    assert.equal(manifest.contentManifest.length, manifest.files)
    assert.match(manifest.contentManifestSha256, /^[a-f0-9]{64}$/)
    assert.ok(manifest.contentManifest.every((file) => /^[a-f0-9]{64}$/.test(file.sha256) && Number.isSafeInteger(file.size)))
    assert.ok(!manifest.contentManifest.some((file) => file.path === 'FOUR_REVIEW_UNIFIED_FINDINGS.json' || file.path.endsWith('.pyc') || file.path.startsWith('.runtime/')))
    assert.equal(typeof manifest.toolchain.zlib, 'string')
    const artifact = await readFile(join(out, manifest.artifact))
    assert.equal((await import('node:crypto')).createHash('sha256').update(artifact).digest('hex'), manifest.sha256)
    const valid = await verifyArtifactSignature(join(out, manifest.artifact), manifest.signature.signature, manifest.signature.publicKey)
    assert.equal(valid, true)
    const sbom = JSON.parse(await readFile(join(out, manifest.sbom), 'utf8'))
    assert.equal(sbom.bomFormat, 'CycloneDX')
    const expectedPackages = (await readdir(join(process.cwd(), 'packages'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => `@armorbreak/${entry.name}`).sort()
    assert.deepEqual(sbom.components.map((component) => component.name).sort(), expectedPackages)
    assert.ok(sbom.components.every((component) => component.hashes?.some((hash) => hash.alg === 'SHA-256' && /^[a-f0-9]{64}$/.test(hash.content))))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
