import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { evaluateMainContract, evaluatePrContract, evaluateReleaseContract, missingRequiredReleaseClaims } from '../scripts/v2/v23-release-gate.mjs'

const node = process.execPath
const gateScript = 'scripts/v2/v23-release-gate.mjs'
const SHA = 'a'.repeat(40)

test('PR contract accepts an in-progress candidate only while structured readiness remains NOT_READY', () => {
  assert.deepEqual(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'IN_PROGRESS', releaseState: 'NOT_READY' }), {
    valid: true, releaseReadiness: 'NOT_READY', blockers: [],
  })
})

test('PR contract ignores historical Markdown wording and rejects contradictory structured state', () => {
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'COMPLETE', releaseState: 'NOT_READY' }).valid, true)
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'IN_PROGRESS', releaseState: 'READY' }).valid, false)
  assert.equal(evaluatePrContract({ packageName: 'other', status: 'IN_PROGRESS', releaseState: 'NOT_READY' }).valid, false)
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'BLOCKED', releaseState: 'NOT_READY' }).valid, false)
})

test('main candidate contract accepts NOT_READY without future release evidence and binds exact SHA', () => {
  assert.deepEqual(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'IN_PROGRESS', releaseState: 'NOT_READY', expectedSha: SHA, head: SHA }), {
    valid: true, releaseReadiness: 'NOT_READY', blockers: [],
  })
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'IN_PROGRESS', releaseState: 'NOT_READY', expectedSha: SHA, head: 'b'.repeat(40) }).valid, false)
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'IN_PROGRESS', releaseState: 'READY', expectedSha: SHA, head: SHA }).valid, false)
})

test('Release contract transitions to READY only for complete P0-H, structured READY, exact tag and SHA', () => {
  assert.deepEqual(evaluateReleaseContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'COMPLETE', releaseState: 'READY', tag: 'refs/tags/v2.3.0', expectedSha: SHA }), {
    valid: true, blockers: [],
  })
})

test('Release contract rejects reverse and partial transitions', () => {
  const base = { packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'COMPLETE', releaseState: 'READY', tag: 'refs/tags/v2.3.0', expectedSha: SHA }
  for (const invalid of [
    { ...base, status: 'IN_PROGRESS' },
    { ...base, releaseState: 'NOT_READY' },
    { ...base, packageVersion: '2.2.0' },
    { ...base, tag: 'refs/tags/v2.3.1' },
    { ...base, expectedSha: 'HEAD' },
  ]) assert.equal(evaluateReleaseContract(invalid).valid, false)
})

test('PR readiness keeps remaining installer and second-principal validation distinct from the completed package drill', () => {
  const result = spawnSync(node, [gateScript, '--check-pr'], { encoding: 'utf8' })
  assert.equal(result.status, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.releaseReadiness, 'NOT_READY')
  assert.ok(report.blockers.includes('OS-integrated updater and second-principal permission validation'))
  assert.ok(!report.blockers.includes('real candidate package upgrade/rollback and OS permission drill'))
})

test('PR, main-candidate and release modes follow a monotonic simulated transition', () => {
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'IN_PROGRESS', releaseState: 'NOT_READY' }).valid, true)
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'IN_PROGRESS', releaseState: 'NOT_READY', expectedSha: SHA, head: SHA }).valid, true)
  assert.equal(evaluateReleaseContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'COMPLETE', releaseState: 'READY', tag: 'refs/tags/v2.3.0', expectedSha: SHA }).valid, true)
})

test('every absent mandatory release claim is rejected before release authorization can proceed', () => {
  const required = ['securityReview', 'licenseReview', 'upgradeRollback', 'artifact', 'sbom', 'mainCi', 'attestation', 'maintainerAuthorization']
  const claims = Object.fromEntries(required.map((key) => [key, { status: 'PASS', evidencePath: `evidence/${key}.json`, evidenceSha256: '0'.repeat(64) }]))
  assert.deepEqual(missingRequiredReleaseClaims(claims), [])
  for (const key of required) {
    const { [key]: ignored, ...incomplete } = claims
    assert.deepEqual(missingRequiredReleaseClaims(incomplete), [key])
  }
  assert.deepEqual(missingRequiredReleaseClaims({ ...claims, artifact: 'PASS' }), ['artifact'])
})

test('Release CLI fails closed while P0-H is open and no signed evidence package exists', () => {
  const result = spawnSync(node, [gateScript, '--release'], { encoding: 'utf8', env: { ...process.env, GITHUB_REF: 'refs/tags/v2.3.0', GITHUB_SHA: SHA } })
  assert.notEqual(result.status, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.decision, 'NOT_READY')
  assert.ok(report.blockers.length > 0, 'release mode must report a concrete fail-closed blocker even from a shallow checkout')
})

test('V2.3 workflow separates PR, main and exact-tag checks and preserves the V2.2.0 guard', () => {
  const workflow = readFileSync('.github/workflows/v2.3-main-gate.yml', 'utf8')
  const legacy = readFileSync('.github/workflows/ci.yml', 'utf8')
  assert.match(workflow, /pull_request:[\s\S]*branches:\s*\[main\]/)
  assert.match(workflow, /push:[\s\S]*branches:\s*\[main\]/)
  assert.match(workflow, /tags:\s*\['v2\.3\.0'\]/)
  assert.match(workflow, /pr-candidate-validation:[\s\S]*if: \$\{\{ github\.event_name == 'pull_request' \}\}[\s\S]*name: Node \$\{\{ matrix\.node \}\} \/ \$\{\{ matrix\.os \}\}/)
  assert.match(workflow, /main-candidate-validation:[\s\S]*if: \$\{\{ github\.event_name == 'push' && github\.ref == 'refs\/heads\/main' \}\}[\s\S]*name: Node \$\{\{ matrix\.node \}\} \/ \$\{\{ matrix\.os \}\}/)
  assert.match(workflow, /main-candidate-validation:[\s\S]*v23-release-gate\.mjs --check-main/)
  assert.match(workflow, /pr-candidate-validation:[\s\S]*v23-release-gate\.mjs --check-pr/)
  assert.match(workflow, /name: V2\.3\.0 release verification/)
  assert.equal((workflow.match(/Prepare runner-local temporary directory \(Windows\)/g) ?? []).length, 2)
  assert.equal((workflow.match(/Prepare runner-local temporary directory \(Unix\)/g) ?? []).length, 2)
  assert.match(workflow, /TEMP=\$runtimeTemp`nTMP=\$runtimeTemp`n/)
  assert.match(workflow, /Prepare repository-local test scratch root[\s\S]*\.runtime\/tmp/)
  assert.match(workflow, /rhysd\/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667/)
  assert.match(workflow, /v23-release-gate\.mjs --release/)
  assert.match(legacy, /if: github\.ref != 'refs\/tags\/v2\.2\.0'/)
  assert.match(legacy, /if: github\.ref == 'refs\/tags\/v2\.2\.0'/)
  assert.match(legacy, /actions\/checkout@[\s\S]{0,180}fetch-depth:\s*0/)
})
