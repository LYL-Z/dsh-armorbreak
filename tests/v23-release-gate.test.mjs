import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { evaluatePrContract, evaluateReleaseContract } from '../scripts/v2/v23-release-gate.mjs'

const node = process.execPath
const gateScript = 'scripts/v2/v23-release-gate.mjs'
const SHA = 'a'.repeat(40)
const READY = '## RELEASE READINESS: READY\n'
const NOT_READY = '## RELEASE READINESS: NOT_READY\n'

test('PR contract accepts an in-progress candidate only while release remains explicitly NOT_READY', () => {
  assert.deepEqual(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'IN_PROGRESS', report: NOT_READY }), {
    valid: true, releaseReadiness: 'NOT_READY', blockers: [],
  })
})

test('PR contract never interprets readiness as release approval and allows a completed milestone pending release authorization', () => {
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'COMPLETE', report: NOT_READY }).valid, true)
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'IN_PROGRESS', report: READY }).valid, false)
  assert.equal(evaluatePrContract({ packageName: 'other', status: 'IN_PROGRESS', report: NOT_READY }).valid, false)
  assert.equal(evaluatePrContract({ packageName: 'dsh-armorbreak', status: 'BLOCKED', report: NOT_READY }).valid, false)
})

test('Release contract transitions to READY only for complete P0-H, version 2.3.0, exact tag, SHA and READY report', () => {
  assert.deepEqual(evaluateReleaseContract({ packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'COMPLETE', report: READY, tag: 'refs/tags/v2.3.0', expectedSha: SHA }), {
    valid: true, blockers: [],
  })
})

test('Release contract rejects reverse and partial transitions', () => {
  const base = { packageName: 'dsh-armorbreak', packageVersion: '2.3.0', status: 'COMPLETE', report: READY, tag: 'refs/tags/v2.3.0', expectedSha: SHA }
  for (const invalid of [
    { ...base, status: 'IN_PROGRESS' },
    { ...base, report: NOT_READY },
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
  assert.match(workflow, /name: V2\.3\.0 release verification/)
  assert.match(workflow, /Prepare repository-local test scratch root[\s\S]*\.runtime\/tmp/)
  assert.match(workflow, /rhysd\/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667/)
  assert.match(workflow, /v23-release-gate\.mjs --release/)
  assert.match(legacy, /if: github\.ref != 'refs\/tags\/v2\.2\.0'/)
  assert.match(legacy, /if: github\.ref == 'refs\/tags\/v2\.2\.0'/)
})
