import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
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
    assert.ok(!manifest.contentManifest.some((file) => file.path.startsWith('fixtures/') || file.path.startsWith('tests/')))
    assert.ok(manifest.contentManifest.some((file) => file.path === 'docs/v2.3/m1-artifact-intake.md'))
    assert.ok(!manifest.contentManifest.some((file) => file.path.startsWith('docs/v2.3/evidence/')))
    assert.ok(!manifest.contentManifest.some((file) => file.path === 'FOUR_REVIEW_UNIFIED_FINDINGS.json' || file.path.endsWith('.pyc') || file.path.startsWith('.runtime/')))
    for (const path of ['lib/release/githubRulesets.js', 'scripts/v2/stable-gate.mjs', 'scripts/v2/build-release.mjs']) {
      const committed = spawnSync('git', ['show', `${manifest.commit}:${path}`], { cwd: process.cwd(), maxBuffer: 16 * 1024 * 1024 })
      assert.equal(committed.status, 0, `read committed Git blob for ${path}: ${committed.stderr}`)
      const file = manifest.contentManifest.find((entry) => entry.path === path)
      assert.ok(file, `release inventory includes ${path}`)
      assert.equal(file.size, committed.stdout.length, `${path} size must match the Git blob, independent of checkout line endings`)
      assert.equal(file.sha256, createHash('sha256').update(committed.stdout).digest('hex'), `${path} digest must match the Git blob`)
    }
    assert.equal(typeof manifest.toolchain.zlib, 'string')
    const artifactPath = join(out, manifest.artifact)
    const artifact = await readFile(artifactPath)
    assert.equal(createHash('sha256').update(artifact).digest('hex'), manifest.sha256)
    const valid = await verifyArtifactSignature(artifactPath, manifest.signature.signature, manifest.signature.publicKey)
    assert.equal(valid, true)
    const sbom = JSON.parse(await readFile(join(out, manifest.sbom), 'utf8'))
    assert.equal(sbom.bomFormat, 'CycloneDX')
    assert.ok(sbom.components.every((component) => {
      const inventoryHash = component.properties?.find((property) => property.name === 'armorbreak:included-file-inventory-sha256')?.value
      return /^[a-f0-9]{64}$/.test(inventoryHash ?? '')
    }))

    const extracted = join(root, 'extracted')
    await mkdir(extracted, { recursive: true })
    const unpack = spawnSync('tar', ['-xzf', artifactPath, '-C', extracted], { encoding: 'utf8', timeout: 120_000 })
    assert.equal(unpack.status, 0, unpack.stderr)
    async function walk(directory, prefix = '') {
      const files = []
      for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
        const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name
        if (entry.isDirectory()) files.push(...await walk(directory, relativePath))
        else if (entry.isFile()) {
          const bytes = await readFile(join(directory, ...relativePath.split('/')))
          files.push({ path: relativePath, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') })
        } else assert.fail(`unexpected non-regular artifact entry: ${relativePath}`)
      }
      return files
    }
    const extractedInventory = (await walk(extracted)).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
    assert.deepEqual(extractedInventory, manifest.contentManifest)
    assert.ok(!extractedInventory.some((file) => file.path.startsWith('fixtures/') || file.path.startsWith('tests/')))
    const rootInventoryProperty = sbom.metadata.component.properties?.find((property) => property.name === 'armorbreak:included-file-inventory')
    assert.ok(rootInventoryProperty, 'root SBOM component must enumerate every file extracted from the artifact')
    assert.deepEqual(JSON.parse(rootInventoryProperty.value), extractedInventory)

    const packageManifestPaths = extractedInventory
      .filter((file) => file.path === 'package.json' || file.path.endsWith('/package.json'))
      .map((file) => file.path).sort()
    assert.ok(packageManifestPaths.includes('plugins/pi/package.json'))
    assert.ok(!packageManifestPaths.includes('fixtures/gate-b-sample/package.json'))
    const componentManifestPaths = sbom.components.map((component) =>
      component.properties?.find((property) => property.name === 'armorbreak:package-manifest-path')?.value).sort()
    assert.deepEqual(componentManifestPaths, packageManifestPaths.filter((file) => file !== 'package.json'))
    for (const component of sbom.components) {
      const manifestPath = component.properties.find((property) => property.name === 'armorbreak:package-manifest-path').value
      const packageJson = JSON.parse(await readFile(join(extracted, ...manifestPath.split('/')), 'utf8'))
      assert.equal(component.name, packageJson.name)
      assert.equal(component.version, packageJson.version)
      const componentRoot = manifestPath.slice(0, -'/package.json'.length)
      const expectedInventory = extractedInventory.filter((file) => file.path.startsWith(`${componentRoot}/`))
      const inventoryProperty = component.properties.find((property) => property.name === 'armorbreak:included-file-inventory')
      assert.deepEqual(JSON.parse(inventoryProperty.value), expectedInventory)
      assert.equal(component.properties.find((property) => property.name === 'armorbreak:included-file-inventory-sha256').value,
        createHash('sha256').update(JSON.stringify(expectedInventory)).digest('hex'))
    }
    assert.ok(!sbom.components.some((component) => component.name === '@armorbreak/migration'))

    const spdx = JSON.parse(await readFile(join(process.cwd(), 'docs/v2/release/sbom.spdx.json'), 'utf8'))
    const expectedSpdxPackages = (await readdir(join(process.cwd(), 'packages'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => `@armorbreak/${entry.name}`).sort()
    assert.deepEqual(spdx.packages.filter((component) => component.primaryPackagePurpose === 'LIBRARY').map((component) => component.name).sort(), expectedSpdxPackages)
    assert.ok(spdx.files.length > 0)
    assert.ok(spdx.files.every((file) => file.checksums?.some((checksum) => checksum.algorithm === 'SHA256' && /^[a-f0-9]{64}$/.test(checksum.checksumValue))))
    const relationships = new Set(spdx.relationships.map((relationship) => `${relationship.spdxElementId}:${relationship.relationshipType}:${relationship.relatedSpdxElement}`))
    assert.ok(spdx.packages.filter((component) => component.primaryPackagePurpose === 'LIBRARY').every((component) => relationships.has(`SPDXRef-DOCUMENT:DESCRIBES:${component.SPDXID}`)))
    assert.ok(spdx.files.every((file) => spdx.packages.some((component) => component.primaryPackagePurpose === 'LIBRARY' && relationships.has(`${component.SPDXID}:CONTAINS:${file.SPDXID}`))))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
