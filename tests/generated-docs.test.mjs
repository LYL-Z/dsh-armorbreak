import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

test('pre-publication generated docs are reproducible and include host/API/Skill/release status', async (t) => {
  // These checked-in documents are the pre-publication snapshot. Exercise that
  // fixture without inheriting tags later published in the surrounding repo.
  const fixture = await mkdtemp(join(tmpdir(), 'abm-docs-prepublication-'))
  t.after(() => rm(fixture, { recursive: true, force: true }))
  const source = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' })
  assert.equal(source.status, 0, source.stderr)
  const clone = spawnSync('git', ['clone', '--no-checkout', '--no-tags', '--no-hardlinks', '--quiet', process.cwd(), fixture], { encoding: 'utf8' })
  assert.equal(clone.status, 0, clone.stderr)
  const checkout = spawnSync('git', ['checkout', '--detach', '--quiet', source.stdout.trim()], { cwd: fixture, encoding: 'utf8' })
  assert.equal(checkout.status, 0, checkout.stderr)
  const tags = spawnSync('git', ['tag', '--list', 'v2.2.0'], { cwd: fixture, encoding: 'utf8' })
  assert.equal(tags.status, 0, tags.stderr)
  assert.equal(tags.stdout.trim(), '', 'pre-publication fixture must not contain the published tag')
  const result = spawnSync(process.execPath, ['scripts/v2/generate-docs.mjs', '--check'], { cwd: fixture, encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const host = await readFile('docs/v2/generated/host-matrix.md', 'utf8')
  assert.match(host, /DSH/)
  assert.match(host, /Codex/)
  const api = await readFile('docs/v2/generated/api-matrix.md', 'utf8')
  assert.match(api, /createCore/)
  const skills = await readFile('docs/v2/generated/skill-list.md', 'utf8')
  assert.match(skills, /armorbreak-triage/)
  const release = await readFile('docs/v2/generated/release-status.md', 'utf8')
  assert.match(release, /Pre-release ready: \*\*true\*\*/)
  assert.match(release, /GA ready: \*\*false\*\*/)
  assert.match(release, /Owner waivers \(pre-release only\)/)
  assert.match(release, /0 items/)
  assert.match(release, /None\./) 
})
