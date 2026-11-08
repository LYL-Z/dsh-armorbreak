import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { evaluateMainContract, evaluatePrContract, evaluateReleaseContract, missingRequiredReleaseClaims, validateOwnerSelfReviewClaims } from '../scripts/v2/v23-release-gate.mjs'

const node = process.execPath
const gateScript = 'scripts/v2/v23-release-gate.mjs'
const SHA = 'a'.repeat(40)
const gateSource = readFileSync(gateScript, 'utf8')
const legacyAttestWorkflow = readFileSync('.github/workflows/attest.yml', 'utf8')
const v23Workflow = readFileSync('.github/workflows/v2.3-main-gate.yml', 'utf8')
const ciWorkflow = readFileSync('.github/workflows/ci.yml', 'utf8')
const exactHeadWorkflow = readFileSync('.github/workflows/v2.3-validation.yml', 'utf8')

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

test('main candidate contract requires completed engineering while retaining NOT_READY until tag evidence exists', () => {
  assert.deepEqual(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'COMPLETE', releaseState: 'NOT_READY', expectedSha: SHA, head: SHA }), {
    valid: true, releaseReadiness: 'NOT_READY', blockers: [],
  })
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'COMPLETE', releaseState: 'NOT_READY', expectedSha: SHA, head: 'b'.repeat(40) }).valid, false)
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'IN_PROGRESS', releaseState: 'NOT_READY', expectedSha: SHA, head: SHA }).valid, false)
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'IN_PROGRESS', releaseState: 'READY', expectedSha: SHA, head: SHA }).valid, false)
})

test('Release contract transitions to READY only from COMPLETE frozen tree plus exact external tag authorization input', () => {
  assert.deepEqual(evaluateReleaseContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'COMPLETE', releaseState: 'NOT_READY', tag: 'refs/tags/v2.3.1', expectedSha: SHA }), {
    valid: true, blockers: [],
  })
})

test('Release contract rejects reverse and partial transitions', () => {
  const base = { packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'COMPLETE', releaseState: 'NOT_READY', tag: 'refs/tags/v2.3.1', expectedSha: SHA }
  for (const invalid of [
    { ...base, status: 'IN_PROGRESS' },
    { ...base, releaseState: 'READY' },
    { ...base, packageVersion: '2.2.0' },
    { ...base, tag: 'refs/tags/v2.3.0' },
    { ...base, expectedSha: 'HEAD' },
  ]) assert.equal(evaluateReleaseContract(invalid).valid, false)
})

test('release verification requires exact-main build provenance and the pre-Tag Windows deployment job', () => {
  assert.match(gateSource, /'V2\.3 main candidate build and provenance'/)
  assert.match(gateSource, /'Exact main package Windows deployment and rollback'/)
})

test('legacy V2.2 attestation workflow does not run on V2.3 main while the V2.3 gate owns main provenance', () => {
  assert.match(legacyAttestWorkflow, /branches: \[feat\/attestation\]/)
  assert.doesNotMatch(legacyAttestWorkflow, /branches: \[main,\s*feat\/attestation\]/)
  assert.match(v23Workflow, /push:[\s\S]*branches: \[main\][\s\S]*build-and-attest-main-candidate:/)
  assert.match(v23Workflow, /actions\/attest-build-provenance/)
})

test('fix/v2.3 repair PRs use exact-head and V2.3 evidence contracts instead of legacy V2.2 checks', () => {
  assert.match(ciWorkflow, /github\.head_ref, 'fix\/v2\.3'/)
  assert.match(ciWorkflow, /github\.ref_name, 'fix\/v2\.3'/)
  assert.match(exactHeadWorkflow, /github\.head_ref, 'fix\/v2\.3'/)
})

test('PR readiness identifies self-review and one-principal release requirements separately from the completed package drill', () => {
  const result = spawnSync(node, [gateScript, '--check-pr'], { encoding: 'utf8' })
  assert.equal(result.status, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.releaseReadiness, 'NOT_READY')
  assert.ok(!report.blockers.includes('owner-approved self-review evidence and risk acceptance'))
  assert.ok(!report.blockers.includes('single-principal configuration verification'))
  assert.ok(report.blockers.includes('exact-main CI, immutable package/SBOM hashes and GitHub attestation'))
  assert.ok(report.blockers.includes('owner-authorized exact-tag release event and detached authorization envelope'))
  assert.ok(!report.blockers.includes('real candidate package upgrade/rollback and OS permission drill'))
})

test('PR, main-candidate and release modes follow a monotonic simulated transition', () => {
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'IN_PROGRESS', releaseState: 'NOT_READY' }).valid, true)
  assert.equal(evaluateMainContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'COMPLETE', releaseState: 'NOT_READY', expectedSha: SHA, head: SHA }).valid, true)
  assert.equal(evaluateReleaseContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.1', status: 'COMPLETE', releaseState: 'NOT_READY', tag: 'refs/tags/v2.3.1', expectedSha: SHA }).valid, true)
})

test('every absent mandatory release claim is rejected before release authorization can proceed', () => {
  const required = ['securityReview', 'licenseReview', 'portableCleanroom', 'upgradeRollback', 'artifact', 'sbom', 'mainCi', 'attestation', 'maintainerAuthorization']
  const claims = Object.fromEntries(required.map((key) => [key, { status: 'PASS', evidencePath: `evidence/${key}.json`, evidenceSha256: '0'.repeat(64) }]))
  assert.deepEqual(missingRequiredReleaseClaims(claims), [])
  for (const key of required) {
    const { [key]: ignored, ...incomplete } = claims
    assert.deepEqual(missingRequiredReleaseClaims(incomplete), [key])
  }
  assert.deepEqual(missingRequiredReleaseClaims({ ...claims, artifact: 'PASS' }), ['artifact'])
})

test('owner self-review claims require truthful reviewer type, owner event, exact main and bound rollback', () => {
  const digest = 'a'.repeat(64)
  const review = { reviewerType: 'IMPLEMENTER_AI_SELF_REVIEW', independentHumanReview: 'NOT_PERFORMED', conclusion: 'OWNER_ACCEPTED_RISK', evidencePath: 'review.json', evidenceSha256: digest }
  const base = {
    decision: 'READY', releaseModel: 'OWNER_APPROVED_SELF_REVIEW',
    securityReview: { ...review }, licenseReview: { ...review },
    portableCleanroom: { status: 'PASS_ACTUAL_CLEANROOM_ARCHIVE_EXECUTION', sourceCommit: SHA, artifactSha256: digest, manifestCommit: SHA, manifestSha256: digest, evidencePath: 'portable.json', evidenceSha256: digest },
    upgradeRollback: { kind: 'REAL_CANDIDATE_PACKAGE', rollbackVerified: true, permissionsVerified: true, evidencePath: 'rollback.json', evidenceSha256: digest, artifactSha256: digest },
    artifact: { path: 'artifact.tgz', sha256: digest }, sbom: { path: 'sbom.json', sha256: digest },
    mainCi: { commit: SHA, runId: '12345' }, attestation: { kind: 'GITHUB_OIDC_BUILD_PROVENANCE', evidencePath: 'attestation.json', evidenceSha256: digest },
    maintainerAuthorization: { authorized: true, method: 'OWNER_TAG_EVENT', actorId: '250811935', eventSenderId: '250811935' },
  }
  assert.deepEqual(validateOwnerSelfReviewClaims(base, SHA), { valid: true, blockers: [] })
  assert.ok(validateOwnerSelfReviewClaims({ ...base, portableCleanroom: { ...base.portableCleanroom, manifestCommit: 'b'.repeat(40) } }, SHA).blockers.some((item) => item.includes('portable package manifest')))
  assert.equal(validateOwnerSelfReviewClaims({ ...base, securityReview: { ...review, reviewerType: 'INDEPENDENT_HUMAN' } }, SHA).valid, false)
  assert.equal(validateOwnerSelfReviewClaims({ ...base, licenseReview: { ...review, independentHumanReview: 'PASS' } }, SHA).valid, false)
  assert.equal(validateOwnerSelfReviewClaims({ ...base, maintainerAuthorization: { ...base.maintainerAuthorization, eventSenderId: '1' } }, SHA).valid, false)
  assert.equal(validateOwnerSelfReviewClaims({ ...base, upgradeRollback: { ...base.upgradeRollback, artifactSha256: 'b'.repeat(64) } }, SHA).valid, false)
  assert.equal(validateOwnerSelfReviewClaims({ ...base, mainCi: { ...base.mainCi, commit: 'b'.repeat(40) } }, SHA).valid, false)
})

test('Release CLI fails closed while P0-H is open and no signed evidence package exists', () => {
  const result = spawnSync(node, [gateScript, '--release'], { encoding: 'utf8', env: { ...process.env, GITHUB_REF: 'refs/tags/v2.3.1', GITHUB_SHA: SHA } })
  assert.notEqual(result.status, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.decision, 'NOT_READY')
  assert.ok(report.blockers.length > 0, 'release mode must report a concrete fail-closed blocker even from a shallow checkout')
})

test('V2.3 workflow separates PR, main and exact-tag checks and preserves the V2.2.0 guard', () => {
  const workflow = readFileSync('.github/workflows/v2.3-main-gate.yml', 'utf8')
  const exactHead = readFileSync('.github/workflows/v2.3-validation.yml', 'utf8')
  const legacy = readFileSync('.github/workflows/ci.yml', 'utf8')
  assert.equal((exactHead.match(/startsWith\(github\.head_ref, 'feature\/v2\.3'\)/g) ?? []).length, 3)
  assert.doesNotMatch(exactHead, /startsWith\(github\.head_ref, 'feature\/v2\.3-'\)/)
  assert.match(workflow, /pull_request:[\s\S]*branches:\s*\[main\]/)
  assert.match(workflow, /push:[\s\S]*branches:\s*\[main\]/)
  assert.match(workflow, /tags:\s*\['v2\.3\.1'\]/)
  assert.match(workflow, /pr-candidate-validation:[\s\S]*if: \$\{\{ github\.event_name == 'pull_request' \}\}[\s\S]*name: Node \$\{\{ matrix\.node \}\} \/ \$\{\{ matrix\.os \}\}/)
  assert.match(workflow, /main-candidate-validation:[\s\S]*if: \$\{\{ github\.event_name == 'push' && github\.ref == 'refs\/heads\/main' \}\}[\s\S]*name: Node \$\{\{ matrix\.node \}\} \/ \$\{\{ matrix\.os \}\}/)
  assert.match(workflow, /main-candidate-validation:[\s\S]*v23-release-gate\.mjs --check-main/)
  assert.match(workflow, /pr-candidate-validation:[\s\S]*v23-release-gate\.mjs --check-pr/)
  assert.match(workflow, /name: V2\.3\.1 release verification/)
  assert.match(workflow, /pr-windows-package-drill:[\s\S]*event_name == 'pull_request'[\s\S]*Run real V2\.2 to exact PR package deployment and rollback drill/)
  assert.match(workflow, /main-windows-package-drill:[\s\S]*refs\/heads\/main[\s\S]*needs: \[main-candidate-validation, build-and-attest-main-candidate\][\s\S]*Run real V2\.2 to exact main V2\.3 package deployment and rollback drill/)
  assert.match(workflow, /Upload PR Windows diagnostics \(including failure evidence\)[\s\S]*if: \$\{\{ always\(\) \}\}/)
  assert.match(workflow, /Upload successful PR Windows drill evidence[\s\S]*if: \$\{\{ success\(\) \}\}/)
  assert.match(workflow, /v23-main-rollback-\$\{\{ github\.sha \}\}/)
  assert.equal((workflow.match(/Prepare runner-local temporary directory \(Windows\)/g) ?? []).length, 2)
  assert.equal((workflow.match(/Prepare runner-local temporary directory \(Unix\)/g) ?? []).length, 2)
  assert.match(workflow, /TEMP=\$runtimeTemp`nTMP=\$runtimeTemp`n/)
  assert.match(workflow, /Prepare repository-local test scratch root[\s\S]*\.runtime\/tmp/)
  assert.match(workflow, /rhysd\/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667/)
  assert.match(workflow, /v23-release-gate\.mjs --release/)
  assert.match(legacy, /if: github\.ref != 'refs\/tags\/v2\.2\.0'/)
  assert.match(legacy, /if: github\.ref == 'refs\/tags\/v2\.2\.0'/)
  assert.match(legacy, /startsWith\(github\.head_ref, 'feature\/v2\.3'\)/)
  assert.match(legacy, /startsWith\(github\.ref_name, 'feature\/v2\.3'\)/)
  assert.match(legacy, /Detect release evidence contract[\s\S]*version.*2\.3\.1[\s\S]*refs\/heads\/main[\s\S]*refs\/tags\/v2\.3\.1/)
  assert.match(legacy, /Validate V2\.3 evidence integrity[\s\S]*validate-v23-acceptance\.mjs/)
  assert.match(legacy, /Validate V2\.3 exact-main candidate contract[\s\S]*v23-release-gate\.mjs --check-main/)
  assert.match(legacy, /Evidence hashes and references[\s\S]*steps\.release_contract\.outputs\.v23 != 'true'/)
  assert.match(legacy, /actions\/checkout@[\s\S]{0,180}fetch-depth:\s*0/)
})
