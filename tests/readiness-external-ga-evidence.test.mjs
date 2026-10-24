import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { REQUIRED_EXTERNAL_GA_CLAIMS } from '../lib/release/externalGaEvidence.js'

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, encoding: 'utf8' })
  assert.equal(result.error, undefined, result.error?.message)
  assert.equal(result.status, 0, `${command} ${args.join(' ')}\n${result.stderr}`)
  return result.stdout
}

test('Markdown-only external status flips cannot clear Full GA blockers', (t) => {
  const sourceRoot = process.cwd()
  const runtime = path.join(sourceRoot, '.runtime', 'tests')
  mkdirSync(runtime, { recursive: true })
  const fixtureRoot = mkdtempSync(path.join(runtime, 'readiness-external-ga-'))
  t.after(() => rmSync(fixtureRoot, { recursive: true, force: true }))

  for (const relative of [
    'scripts/v2/v2-readiness.mjs',
    'lib/release/safeEvidenceFile.js',
    'lib/release/artifactAttestation.js',
    'lib/release/externalGaEvidence.js',
    'docs/v2/acceptance/compatibility-matrix.json',
    'docs/v2/acceptance/portable-artifact.json',
    'docs/v2/acceptance/signoff.json',
    'docs/v2/release/waivers.json',
  ]) {
    const destination = path.join(fixtureRoot, relative)
    mkdirSync(path.dirname(destination), { recursive: true })
    cpSync(path.join(sourceRoot, relative), destination)
  }
  cpSync(path.join(sourceRoot, 'docs/v2/tasks'), path.join(fixtureRoot, 'docs/v2/tasks'), { recursive: true })

  run('git', ['init', '--quiet'], fixtureRoot)
  run('git', ['-c', 'user.name=Security Regression', '-c', 'user.email=security-regression@example.invalid', 'add', '.'], fixtureRoot)
  run('git', ['-c', 'user.name=Security Regression', '-c', 'user.email=security-regression@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'isolated readiness regression fixture'], fixtureRoot)

  const isolatedEnv = {
    ...process.env,
    ARMORBREAK_EXTERNAL_GA_TRUSTED_SIGNERS: '[]',
    ARMORBREAK_EXTERNAL_GA_EVIDENCE_BUNDLE: '',
    ARMORBREAK_PORTABLE_ARTIFACT: '',
  }
  const readReadiness = () => JSON.parse(run(process.execPath, ['scripts/v2/v2-readiness.mjs'], fixtureRoot, isolatedEnv))
  const baseline = readReadiness()
  const expectedCodes = REQUIRED_EXTERNAL_GA_CLAIMS.map((claim) => claim.blockerCode).sort()
  const baselineExternal = baseline.gaBlockers.filter((blocker) => expectedCodes.includes(blocker.code)).map((blocker) => blocker.code).sort()
  assert.deepEqual(baselineExternal, expectedCodes)

  const taskIds = ['ABU-311', 'ABU-312', 'ABU-313', 'ABU-314', 'ABU-318', 'ABU-409']
  const originals = new Map()
  try {
    for (const taskId of taskIds) {
      const file = path.join(fixtureRoot, 'docs', 'v2', 'tasks', `${taskId}.md`)
      const original = readFileSync(file)
      originals.set(file, original)
      const field = taskId === 'ABU-409' ? 'independentReview' : 'realEndpoint'
      const updated = original.toString('utf8').replace(new RegExp(`^${field}:\\s*BLOCKED_EXTERNAL\\s*$`, 'm'), `${field}: DONE`)
      assert.notEqual(updated, original.toString('utf8'), `${taskId} must contain the expected blocked field`)
      writeFileSync(file, updated)
    }
    const afterFlip = readReadiness()
    const afterExternal = afterFlip.gaBlockers.filter((blocker) => expectedCodes.includes(blocker.code)).map((blocker) => blocker.code).sort()
    assert.deepEqual(afterExternal, expectedCodes)
    assert.equal(afterFlip.externalAcceptanceEvidence.ok, false)
    assert.equal(afterFlip.gaReady, false)
    assert.ok(afterFlip.gaBlockers.some((blocker) => blocker.code === 'ARTIFACT_ATTESTATION_NOT_VERIFIED'))
  } finally {
    for (const [file, original] of originals) writeFileSync(file, original)
  }
})
