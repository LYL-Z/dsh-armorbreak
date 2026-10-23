import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { computeReleaseGates, docsOnlyGateReport, REQUIRED_M4, sha256File } from '../lib/release/gates.js'

const COMMIT = 'a'.repeat(40)

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`)
}

function makeRepo({ commit = COMMIT, failTests = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'abm-gates-'))
  const evidence = join(root, 'docs/v2/acceptance')
  const tasks = join(root, 'docs/v2/tasks')
  mkdirSync(evidence, { recursive: true })
  mkdirSync(tasks, { recursive: true })
  const tap = `TAP version 13\nok 1 - policy gateway denies unknown actions\nok 2 - approval binding rejects model self-approval\n${failTests ? 'not ok 3 - deliberate failure\n' : 'ok 3 - evidence report metadata validates\n'}# tests 3\n# pass ${failTests ? 2 : 3}\n# fail ${failTests ? 1 : 0}\n# cancelled 0\n# skipped 0\n# todo 0\n`
  writeFileSync(join(evidence, 'test-report.tap'), tap)
  const counts = { tests: 3, pass: failTests ? 2 : 3, fail: failTests ? 1 : 0, skipped: 0, cancelled: 0, todo: 0 }
  writeJson(join(evidence, 'test-report.json'), {
    schemaVersion: 'armorbreak.test-report/v1', commit, node: process.version, generatedAt: new Date().toISOString(),
    counts, exitCode: failTests ? 1 : 0, command: 'node --test --test-reporter=tap --test-concurrency=1', processError: null, signal: null,
    tapPath: 'docs/v2/acceptance/test-report.tap', tapSha256: createHash('sha256').update(tap).digest('hex'),
  })
  writeJson(join(evidence, 'airgap-container.json'), { result: 'PASS' })
  writeJson(join(evidence, 'offline-score.json'), { summary: { targetPass: 62 } })
  writeJson(join(evidence, 'supplychain-e2e.json'), { result: 'PASS' })
  writeJson(join(evidence, 'supplychain-live.json'), { result: 'PASS' })
  writeJson(join(evidence, 'garak-live.json'), { status: 'PASS' })
  writeJson(join(evidence, 'pyrit-live.json'), { result: 'PASS' })
  writeJson(join(evidence, 'jailbreak-live.json'), { result: 'PASS' })
  writeJson(join(evidence, 'desktop-analysis.json'), { result: 'PASS' })
  writeJson(join(evidence, 'desktop-e2e.md'), '# Desktop E2E\n')
  writeJson(join(evidence, 'performance-compare.json'), { regressionsOver10Percent: [] })
  const shots = []
  for (const name of ['shot1.webp', 'shot2.webp', 'shot3.webp']) {
    const rel = `docs/v2/acceptance/${name}`
    writeFileSync(join(root, rel), `image-${name}`)
    shots.push({ path: rel, sha256: sha256File(join(root, rel)) })
  }
  writeJson(join(evidence, 'desktop-e2e.json'), { result: 'PASS', l0Task: { reportSha256: 'b'.repeat(64) }, screenshots: shots })
  for (const file of REQUIRED_M4) writeFileSync(join(tasks, file), '---\nstatus: DONE\n---\n')
  const writeManifest = (manifestCommit = commit) => {
    const files = {}
    for (const name of [
      'test-report.json', 'test-report.tap', 'airgap-container.json', 'offline-score.json', 'supplychain-e2e.json',
      'supplychain-live.json', 'garak-live.json', 'pyrit-live.json', 'jailbreak-live.json', 'desktop-analysis.json',
      'desktop-e2e.md', 'desktop-e2e.json', 'performance-compare.json', 'shot1.webp', 'shot2.webp', 'shot3.webp',
    ]) {
      const rel = `docs/v2/acceptance/${name}`
      files[rel] = { sha256: sha256File(join(root, rel)), size: readFileSync(join(root, rel)).length }
    }
    writeJson(join(evidence, 'evidence-manifest.json'), { schemaVersion: 'armorbreak.evidence-manifest/v1', commit: manifestCommit, generatedAt: new Date().toISOString(), files })
  }
  writeManifest()
  return { root, writeManifest, evidence }
}

test('evidence-driven gates PASS only with current commit, raw TAP and pinned evidence', () => {
  const repo = makeRepo()
  const report = computeReleaseGates({ repoRoot: repo.root, commit: COMMIT })
  assert.equal(report.releasable, true)
  assert.deepEqual(Object.fromEntries(Object.entries(report.gates).map(([name, gate]) => [name, gate.status])), {
    security: 'PASS', offline: 'PASS', supplyChain: 'PASS', aiEvaluation: 'PASS', compatibility: 'PASS', performance: 'PASS',
  })
  rmSync(repo.root, { recursive: true, force: true })
})

test('tampered evidence is FAIL, missing report is REVIEW, stale commit is REVIEW', () => {
  const repo = makeRepo()
  writeFileSync(join(repo.root, 'docs/v2/acceptance/offline-score.json'), '{"summary":{"targetPass":99}}\n')
  const tampered = computeReleaseGates({ repoRoot: repo.root, commit: COMMIT })
  assert.equal(tampered.gates.offline.status, 'FAIL')
  assert.equal(tampered.releasable, false)

  rmSync(join(repo.root, 'docs/v2/acceptance/test-report.json'))
  const missing = computeReleaseGates({ repoRoot: repo.root, commit: COMMIT })
  assert.equal(missing.gates.security.status, 'REVIEW')

  const fresh = makeRepo({ commit: 'b'.repeat(40) })
  const stale = computeReleaseGates({ repoRoot: fresh.root, commit: COMMIT })
  assert.equal(stale.gates.security.status, 'REVIEW')
  assert.equal(stale.releasable, false)
  rmSync(repo.root, { recursive: true, force: true })
  rmSync(fresh.root, { recursive: true, force: true })
})

test('failed test run can never be releasable', () => {
  const repo = makeRepo({ failTests: true })
  const report = computeReleaseGates({ repoRoot: repo.root, commit: COMMIT })
  assert.equal(report.gates.security.status, 'FAIL')
  assert.equal(report.releasable, false)
  rmSync(repo.root, { recursive: true, force: true })
})

test('failed process metadata and skipped tests cannot produce a PASS release gate', () => {
  const failedProcess = makeRepo()
  const failedReportPath = join(failedProcess.evidence, 'test-report.json')
  const failedReport = JSON.parse(readFileSync(failedReportPath, 'utf8'))
  failedReport.exitCode = 1
  writeJson(failedReportPath, failedReport)
  failedProcess.writeManifest()
  const processGate = computeReleaseGates({ repoRoot: failedProcess.root, commit: COMMIT })
  assert.equal(processGate.gates.security.status, 'FAIL')
  assert.equal(processGate.releasable, false)

  const processMetadata = makeRepo()
  const metadataReportPath = join(processMetadata.evidence, 'test-report.json')
  const metadataReport = JSON.parse(readFileSync(metadataReportPath, 'utf8'))
  metadataReport.processError = 'spawn returned an error despite a forged zero exit code'
  writeJson(metadataReportPath, metadataReport)
  processMetadata.writeManifest()
  const metadataGate = computeReleaseGates({ repoRoot: processMetadata.root, commit: COMMIT })
  assert.equal(metadataGate.gates.security.status, 'FAIL')
  assert.equal(metadataGate.releasable, false)

  const skipped = makeRepo()
  const tapPath = join(skipped.evidence, 'test-report.tap')
  const tap = `TAP version 13\nok 1 - policy gateway denies unknown actions\nok 2 - approval binding rejects model self-approval\nok 3 - evidence report metadata validates\nok 4 - platform-specific boundary # SKIP not available\n# tests 4\n# pass 3\n# fail 0\n# cancelled 0\n# skipped 1\n# todo 0\n`
  writeFileSync(tapPath, tap)
  const skippedReportPath = join(skipped.evidence, 'test-report.json')
  const skippedReport = JSON.parse(readFileSync(skippedReportPath, 'utf8'))
  skippedReport.counts = { tests: 4, pass: 3, fail: 0, skipped: 1, cancelled: 0, todo: 0 }
  skippedReport.tapSha256 = createHash('sha256').update(tap).digest('hex')
  writeJson(skippedReportPath, skippedReport)
  skipped.writeManifest()
  const skippedGate = computeReleaseGates({ repoRoot: skipped.root, commit: COMMIT })
  assert.equal(skippedGate.gates.security.status, 'REVIEW')
  assert.equal(skippedGate.releasable, false)
  rmSync(failedProcess.root, { recursive: true, force: true })
  rmSync(processMetadata.root, { recursive: true, force: true })
  rmSync(skipped.root, { recursive: true, force: true })
})

test('docs-only gate inherits the target base gates and never fabricates releasability', () => {
  const validation = { ok: true, mode: 'docs-only', checked: 113, issues: [] }
  const baseReport = { releasable: true, gates: { security: { status: 'PASS' } }, testReport: { tests: 396 } }
  const report = docsOnlyGateReport({ commit: COMMIT, baseCommit: 'b'.repeat(40), baseReport, validation })
  assert.equal(report.mode, 'docs-only')
  assert.equal(report.applicability, 'DOCS_ONLY_BASE_GATES')
  assert.equal(report.releasable, true)
  assert.equal(report.gates.security.status, 'PASS')
  assert.equal(report.evidenceValidation.ok, true)
  assert.equal(report.evidenceValidation.checked, 113)

  const blocked = docsOnlyGateReport({ commit: COMMIT, baseCommit: 'b'.repeat(40), baseReport: { releasable: false }, validation })
  assert.equal(blocked.releasable, false)
  assert.match(blocked.reason, /cannot bypass/)
})

test('docs ancestor gate accepts a base with a prior docs-only merge', () => {
  const repo = makeRepo()
  const git = (...args) => execFileSync('git', ['-C', repo.root, ...args], { encoding: 'utf8' }).trim()
  try {
    git('init')
    git('config', 'user.email', 'qa@example.test')
    git('config', 'user.name', 'QA')
    git('add', '-A')
    git('commit', '-m', 'base evidence')
    const base = git('rev-parse', 'HEAD')
    writeJson(join(repo.root, 'docs/v2/acceptance/test-report.json'), {
      ...JSON.parse(readFileSync(join(repo.root, 'docs/v2/acceptance/test-report.json'), 'utf8')),
      commit: base,
    })
    repo.writeManifest(base)
    writeFileSync(join(repo.root, 'README.md'), '# docs after evidence\n')
    git('add', 'README.md')
    git('commit', '-m', 'docs: prior docs-only merge')
    const head = git('rev-parse', 'HEAD')

    const evidenceOnly = computeReleaseGates({ repoRoot: repo.root, commit: head, allowEvidenceAncestor: true })
    assert.equal(evidenceOnly.evidenceManifest.valid, false)
    const docsAware = computeReleaseGates({ repoRoot: repo.root, commit: head, allowEvidenceAncestor: true, allowDocsAncestor: true })
    assert.equal(docsAware.evidenceManifest.valid, true)
    assert.equal(docsAware.releasable, true)
  } finally {
    rmSync(repo.root, { recursive: true, force: true })
  }
})
