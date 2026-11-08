import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { inspectDshHostProfile } from '../lib/integrations/dshHostInspector.js'

async function fixture(t) {
  const home = await mkdtemp(join(tmpdir(), 'armorbreak-dsh-host-'))
  t.after(() => rm(home, { recursive: true, force: true }))
  const profilePath = join(home, 'profiles', 'web')
  await mkdir(profilePath, { recursive: true })
  return { home, profilePath }
}

test('profile inventory reports only package names and ranges, never secret configuration values', async (t) => {
  const { home, profilePath } = await fixture(t)
  await writeFile(join(profilePath, 'package.json'), JSON.stringify({ dependencies: { 'dsh-armorbreak': '2.3.1', 'dsh-purge-community': 'https://registry.example/SECRET_NOT_TO_LEAK' }, token: 'SECRET_NOT_TO_LEAK' }))
  await writeFile(join(profilePath, 'cordis.patch.yml'), "- name: dsh-armorbreak\n  token: SECRET_NOT_TO_LEAK\n- name: dsh-purge-community\n")
  const report = await inspectDshHostProfile({ home, profile: 'web' })
  assert.equal(report.mode, 'READ_ONLY')
  assert.equal(report.status, 'INSPECTED')
  assert.deepEqual(report.manifest.declaredPackages.map((x) => x.name), ['dsh-armorbreak', 'dsh-purge-community'])
  assert.equal(report.observations.length, 2)
  assert.doesNotMatch(JSON.stringify(report), /SECRET_NOT_TO_LEAK/)
})

test('host inspection fails closed on invalid profile paths and symlinked input', async (t) => {
  const { home, profilePath } = await fixture(t)
  await assert.rejects(() => inspectDshHostProfile({ home, profile: '../outside' }), /invalid --profile/)
  await assert.rejects(() => inspectDshHostProfile({ home: 'relative', profile: 'web' }), /absolute --home/)
  await symlink(join(home, 'missing-outside'), join(profilePath, 'package.json'))
  await writeFile(join(profilePath, 'cordis.patch.yml'), 'name: harmless\n')
  const report = await inspectDshHostProfile({ home, profile: 'web' })
  assert.equal(report.manifest.status, 'SYMLINK_NOT_FOLLOWED')
  assert.equal(report.status, 'INCOMPLETE')
})

test('missing profile or malformed metadata reports incomplete evidence, not installed status', async (t) => {
  const { home, profilePath } = await fixture(t)
  const absent = await inspectDshHostProfile({ home, profile: 'desktop' })
  assert.equal(absent.status, 'INCOMPLETE')
  assert.equal(absent.manifest.status, 'NOT_INSPECTED')
  await writeFile(join(profilePath, 'package.json'), 'not json')
  await writeFile(join(profilePath, 'cordis.patch.yml'), '# no bundle\n')
  const invalid = await inspectDshHostProfile({ home, profile: 'web' })
  assert.equal(invalid.status, 'INCOMPLETE')
  assert.equal(invalid.manifest.status, 'INVALID_JSON')
  assert.deepEqual(invalid.manifest.declaredPackages, [])
})

test('host inspect CLI runs without configuring ArmorBreak state or modifying the profile', async (t) => {
  const { home, profilePath } = await fixture(t)
  const content = '{"dependencies":{"dsh-purge":"1.1.71"}}'
  await writeFile(join(profilePath, 'package.json'), content)
  await writeFile(join(profilePath, 'cordis.patch.yml'), 'name: dsh-purge\n')
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'host', 'inspect', '--home', home, '--profile', 'web', '--json'], {
    cwd: new URL('..', import.meta.url), env: {}, encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(cli.status, 0, cli.stderr)
  assert.equal(JSON.parse(cli.stdout).manifest.declaredPackages[0].name, 'dsh-purge')
  assert.equal(await readFile(join(profilePath, 'package.json'), 'utf8'), content)
})
