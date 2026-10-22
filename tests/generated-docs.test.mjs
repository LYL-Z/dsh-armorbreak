import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('generated docs are reproducible and include host/API/Skill/release status', async () => {
  const result = spawnSync(process.execPath, ['scripts/v2/generate-docs.mjs', '--check'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const host = await readFile('docs/v2/generated/host-matrix.md', 'utf8')
  assert.match(host, /DSH/)
  assert.match(host, /Codex/)
  const api = await readFile('docs/v2/generated/api-matrix.md', 'utf8')
  assert.match(api, /createCore/)
  const skills = await readFile('docs/v2/generated/skill-list.md', 'utf8')
  assert.match(skills, /armorbreak-triage/)
  const release = await readFile('docs/v2/generated/release-status.md', 'utf8')
  assert.match(release, /Ready: \*\*true\*\*/)
  assert.match(release, /Owner waivers/)
  assert.match(release, /WAIVED_BY_OWNER/)
})
