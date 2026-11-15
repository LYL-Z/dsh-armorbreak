import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { diagnoseDshAnchors } from '../lib/integrations/dshAnchorDiagnostic.js'

async function fixture(t, anchors) {
  const root = await mkdtemp(join(tmpdir(), 'armorbreak-anchor-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const targetFile = join(root, 'host.js')
  const specFile = join(root, 'anchors.json')
  await writeFile(specFile, JSON.stringify({ schemaVersion: 'armorbreak.anchor-spec/v1', anchors }))
  return { root, targetFile, specFile }
}

test('exact, missing and ambiguous anchors are reported without copying host source', async (t) => {
  const f = await fixture(t, [
    { id: 'unique', literal: 'stable-anchor' },
    { id: 'duplicate', literal: 'repeated-anchor' },
    { id: 'absent', literal: 'missing-anchor' },
  ])
  await writeFile(f.targetFile, 'secret=TOKEN_NEVER_REPORT\nstable-anchor\nrepeated-anchor repeated-anchor\n')
  const report = await diagnoseDshAnchors(f)
  assert.equal(report.status, 'REVIEW_REQUIRED')
  assert.deepEqual(report.anchors.map((anchor) => anchor.status), ['MATCH', 'AMBIGUOUS', 'MISSING'])
  assert.doesNotMatch(JSON.stringify(report), /TOKEN_NEVER_REPORT|stable-anchor|repeated-anchor/)
})

test('malformed spec, duplicate IDs and invalid paths fail closed', async (t) => {
  const f = await fixture(t, [{ id: 'a', literal: 'abc' }, { id: 'a', literal: 'def' }])
  await writeFile(f.targetFile, 'abc\n')
  await assert.rejects(() => diagnoseDshAnchors(f), /duplicate anchor/)
  await writeFile(f.specFile, JSON.stringify({ schemaVersion: 'armorbreak.anchor-spec/v1', anchors: [{ id: 'valid', literal: 'abc' }] }))
  await assert.rejects(() => diagnoseDshAnchors({ ...f, targetFile: '../host.js' }), /expected absolute file path/)
  await writeFile(f.specFile, '{"anchors":[]}')
  await assert.rejects(() => diagnoseDshAnchors(f), /invalid anchor specification schema/)
  await writeFile(f.specFile, '{ bad secret here }')
  await assert.rejects(() => diagnoseDshAnchors(f), /^Error: invalid anchor specification JSON$/)
})

test('diagnostic does not follow symlinked host files', async (t) => {
  const f = await fixture(t, [{ id: 'a', literal: 'abc' }])
  if (process.platform === 'win32') {
    const outside = f.specFile + '.external'
    await mkdir(outside)
    await symlink(outside, f.targetFile, 'junction')
  } else await symlink(f.specFile, f.targetFile)
  await assert.rejects(() => diagnoseDshAnchors(f), /symlinked file/)
})

test('CLI is read-only and does not need an initialized ArmorBreak engine', async (t) => {
  const f = await fixture(t, [{ id: 'a', literal: 'abc' }])
  await writeFile(f.targetFile, 'abc')
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'host', 'diagnose', '--target', f.targetFile, '--spec', f.specFile, '--json'], {
    cwd: new URL('..', import.meta.url), env: {}, encoding: 'utf8', timeout: 10_000,
  })
  assert.equal(cli.status, 0, cli.stderr)
  assert.equal(JSON.parse(cli.stdout).status, 'MATCHES_EXPECTATIONS')
  assert.equal(await readFile(f.targetFile, 'utf8'), 'abc')
})
