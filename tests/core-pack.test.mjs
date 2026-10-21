import assert from 'node:assert/strict'
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { buildCorePack } from '../lib/pack/corePack.js'

test('core pack is deterministic, hashes files and excludes workspace state/tests', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-pack-'))
  await mkdir(join(root, 'lib'), { recursive: true })
  await mkdir(join(root, '.armorbreak'), { recursive: true })
  await writeFile(join(root, 'package.json'), '{"name":"x"}')
  await writeFile(join(root, 'lib', 'a.js'), 'export const a = 1\n')
  await writeFile(join(root, '.armorbreak', 'secret.json'), '{"no":true}')
  await writeFile(join(root, 'tests-evil.js'), 'should not be included')
  const pack = await buildCorePack({ root, include: ['package.json', 'lib'] })
  assert.equal(pack.fileCount, 2)
  assert.deepEqual(pack.entries.map((entry) => entry.path), ['lib/a.js', 'package.json'])
  assert.ok(pack.entries.every((entry) => entry.sha256.length === 64))
  const again = await buildCorePack({ root, include: ['package.json', 'lib'] })
  assert.equal(pack.aggregateSha256, again.aggregateSha256)
})
