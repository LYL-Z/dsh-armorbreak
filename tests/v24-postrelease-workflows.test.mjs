import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const mainWorkflow = readFileSync('.github/workflows/v2.3-main-gate.yml', 'utf8')
const genericCi = readFileSync('.github/workflows/ci.yml', 'utf8')
const frozen = 'cfb984b7178bb8b1dca9728325fdbe599b5430a3'

function jobHeader(source, name) {
  const marker = `  ${name}:\n`
  const index = source.indexOf(marker)
  assert.ok(index >= 0, `missing ${name} job`)
  const rest = source.slice(index + marker.length)
  const next = rest.search(/^  [a-z][a-z0-9-]*:/m)
  return next < 0 ? rest : rest.slice(0, next)
}

test('V2.3 PR jobs are limited to actual V2.3 maintenance branches', () => {
  for (const name of ['pr-candidate-validation', 'pr-windows-package-drill']) {
    const job = jobHeader(mainWorkflow, name)
    assert.match(job, /github\.event_name == 'pull_request'/)
    assert.match(job, /startsWith\(github\.head_ref, 'feature\/v2\.3'\)/)
    assert.match(job, /startsWith\(github\.head_ref, 'fix\/v2\.3'\)/)
  }
})

test('post-release main updates cannot impersonate V2.3 exact-main evidence', () => {
  for (const name of ['main-candidate-validation', 'build-and-attest-main-candidate', 'main-windows-package-drill']) {
    const job = jobHeader(mainWorkflow, name)
    assert.match(job, /github\.ref == 'refs\/heads\/main'/)
    assert.ok(job.includes(`github.sha == '${frozen}'`))
  }
})

test('V2.4 development gate runs exact-head cross-platform and explicit L0/L1 jobs', () => {
  const matrix = jobHeader(mainWorkflow, 'v24-development-validation')
  assert.match(matrix, /github\.event_name == 'pull_request'/)
  assert.match(matrix, /github\.event_name == 'push'/)
  assert.match(matrix, /github\.event\.pull_request\.head\.sha \|\| github\.sha/)
  assert.match(matrix, /os: \[ubuntu-latest, windows-latest\]/)
  assert.match(matrix, /node: \['22', '24'\]/)
  assert.match(matrix, /npm ci --no-audit --no-fund/)
  assert.match(matrix, /node --test --test-concurrency=1/)
  assert.match(matrix, /npm run typecheck/)
  for (const [name, assertion] of [
    ['v24-development-l0', /tests\/offline-core\.test\.mjs/],
    ['v24-development-l1', /scripts\/verify-l1\.mjs/],
  ]) {
    const job = jobHeader(mainWorkflow, name)
    assert.match(job, /github\.event\.pull_request\.head\.sha \|\| github\.sha/)
    assert.match(job, assertion)
  }
  const l1 = jobHeader(mainWorkflow, 'v24-development-l1')
  assert.match(l1, /busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662/)
  assert.doesNotMatch(l1, /busybox:1\.36|RepoDigests/)
})

test('V2.4 aggregate gate fails closed when any real validation is skipped or fails', () => {
  const gate = jobHeader(mainWorkflow, 'v24-development-gate')
  assert.match(gate, /always\(\)/)
  assert.match(gate, /needs: \[v24-development-validation, v24-development-l0, v24-development-l1\]/)
  for (const result of ['MATRIX_RESULT', 'L0_RESULT', 'L1_RESULT']) {
    assert.match(gate, new RegExp(`test \\"\\$${result}\\" = success`))
  }
})

test('V2.3.1 protected tag verifier and main artifact authorization remain intact', () => {
  const release = jobHeader(mainWorkflow, 'release-verification')
  assert.match(release, /github\.ref == 'refs\/tags\/v2\.3\.1'/)
  assert.match(release, /v23-release-gate\.mjs --release/)
  assert.match(release, /gh attestation verify/)
  assert.match(release, /sender_id.*250811935/)
})

test('generic CI retains cross-platform tests but reserves release evidence for exact release refs', () => {
  const release = jobHeader(genericCi, 'release-evidence')
  assert.match(release, /github\.event_name == 'push'/)
  assert.match(release, /startsWith\(github\.ref, 'refs\/tags\/v'\)/)
  assert.ok(release.includes(`github.sha == '${frozen}'`))
  assert.doesNotMatch(release.split('runs-on:')[0], /github\.event_name == 'pull_request'/)
  assert.match(genericCi, /os: \[ubuntu-latest, windows-latest\]/)
  assert.match(genericCi, /name: L0 offline boundary \(static gate\)/)
  assert.match(genericCi, /name: L1 Docker integration \(real daemon\)/)
})
