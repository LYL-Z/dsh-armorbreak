import assert from 'node:assert/strict'
import { link, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createSpdx } from '../scripts/v2/build-sbom.mjs'

test('SBOM source collection rejects a hard link without changing its external name', async () => {
  const repoRoot = await mkdtemp(join(tmpdir(), 'abm-sbom-hardlink-'))
  const packageRoot = join(repoRoot, 'packages', 'fixture')
  await mkdir(packageRoot, { recursive: true })
  await writeFile(join(repoRoot, 'package.json'), JSON.stringify({ name: 'fixture-root', version: '1.0.0', dependencies: {} }))
  await writeFile(join(packageRoot, 'package.json'), JSON.stringify({ name: '@fixture/sample', version: '1.0.0' }))
  const protectedPath = join(repoRoot, 'protected.data')
  const linkedPath = join(packageRoot, 'source.js')
  const original = Buffer.from('outside the package source tree')
  await writeFile(protectedPath, original)
  await link(protectedPath, linkedPath)

  await assert.rejects(() => createSpdx({ repoRoot, created: '2026-10-23T00:00:00.000Z' }), /multiple hard links/i)
  assert.deepEqual(await readFile(protectedPath), original)
})
