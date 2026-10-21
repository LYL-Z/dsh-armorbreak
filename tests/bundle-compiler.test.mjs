import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { applyProfileUpgrade, compileBundle, planProfileUpgrade, rollbackProfileUpgrade } from '../lib/pack/bundleCompiler.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

async function bundleRoot() {
  const root = await mkdtemp(join(tmpdir(), 'abm-bundle-'))
  await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'dsh-armorbreak', version: '2.0.0-test' }))
  await writeFile(join(root, 'cordis.patch.yml'), '- insert:\n  - id: preset-armorbreak\n    config:\n      id: armorbreak\n')
  await writeFile(join(root, 'index.js'), 'export default {}\n')
  await mkdir(join(root, 'lib'), { recursive: true })
  await writeFile(join(root, 'lib', 'x.js'), 'export const x = 1\n')
  return root
}

test('bundle compiler hashes real files and preserves preset armorbreak', async () => {
  const root = await bundleRoot()
  const bundle = await compileBundle({ root })
  assert.equal(bundle.preset.id, 'armorbreak')
  assert.equal(bundle.preset.preserved, true)
  assert.equal(bundle.executable, false)
  assert.ok(bundle.fileCount >= 4)
  const again = await compileBundle({ root })
  assert.equal(bundle.aggregateSha256, again.aggregateSha256)
})

test('isolated profile upgrade preserves other bundles/preset and rolls back exact bytes', async () => {
  const root = await bundleRoot()
  const bundle = await compileBundle({ root })
  const profileDir = await mkdtemp(join(tmpdir(), 'abm-profile-'))
  const original = { schemaVersion: 'profile/v1', bundles: [{ name: 'other-bundle', version: '1.0.0' }], presets: [{ id: 'armorbreak', name: 'ArmorBreak' }, { id: 'standard', name: 'Standard' }] }
  const text = `${JSON.stringify(original, null, 2)}\n`
  await writeFile(join(profileDir, 'profile.json'), text)
  const plan = await planProfileUpgrade({ profileDir, bundle })
  const applied = await applyProfileUpgrade(plan)
  const after = JSON.parse(await readFile(join(profileDir, 'profile.json'), 'utf8'))
  assert.equal(after.bundles.some((item) => item.name === 'other-bundle'), true)
  assert.equal(after.presets.find((preset) => preset.id === 'armorbreak').id, 'armorbreak')
  assert.equal(after.presets.some((preset) => preset.id === 'standard'), true)
  const rolled = await rollbackProfileUpgrade({ backup: applied.backup, profileDir })
  assert.equal(rolled.sha256, sha256(text))
  assert.equal(await readFile(join(profileDir, 'profile.json'), 'utf8'), text)
})
