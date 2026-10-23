#!/usr/bin/env node
/** Release readiness check. Never marks the release ready unless every gate passes. */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { classifyEvidenceOnly, validateEvidence } from '../../lib/release/evidenceValidator.js'
import { computeReleaseGates } from '../../lib/release/gates.js'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = process.cwd()
const shaPattern = /^[a-f0-9]{40}$/i
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
function readBytes(path) { return readSafeRepoFile(root, path) }
function readJson(path) {
  try { return JSON.parse(readBytes(path).toString('utf8').replace(/^\uFEFF/, '')) } catch { return null }
}
function parseTap(bytes) {
  const tap = bytes.toString('utf8')
  const count = (name) => Number(new RegExp(`^# ${name} (\\d+)$`, 'm').exec(tap)?.[1] ?? -1)
  return { tests: count('tests'), pass: count('pass'), fail: count('fail'), skipped: count('skipped'), cancelled: count('cancelled'), todo: count('todo') }
}
function recordMatches(manifest, path, bytes) {
  const record = manifest?.files?.[path]
  return Boolean(record && Number.isSafeInteger(record.size) && record.size === bytes.length &&
    typeof record.sha256 === 'string' && /^[a-f0-9]{64}$/i.test(record.sha256) && record.sha256.toLowerCase() === digest(bytes))
}

const pkg = readJson('package.json')
const gates = readJson('docs/v2/acceptance/release-gates.json')
const sbom = readJson('docs/v2/release/sbom.spdx.json')
const manifest = readJson('docs/v2/acceptance/evidence-manifest.json')
const testReport = readJson('docs/v2/acceptance/test-report.json')
const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const sourceCommit = manifest?.commit ?? null
const tapBytes = (() => { try { return readBytes('docs/v2/acceptance/test-report.tap') } catch { return null } })()
const reportBytes = (() => { try { return readBytes('docs/v2/acceptance/test-report.json') } catch { return null } })()
let evidenceLineage = sourceCommit === head
if (!evidenceLineage && sourceCommit && shaPattern.test(sourceCommit) && shaPattern.test(head)) {
  evidenceLineage = classifyEvidenceOnly({ repoRoot: root, base: sourceCommit, head, allowReadiness: true }).ok
}
const evidenceValidation = validateEvidence({ repoRoot: root, commit: head, allowEvidenceAncestor: true, allowReadiness: true })
const recomputedGates = computeReleaseGates({ repoRoot: root, commit: head, allowEvidenceAncestor: true })
const manifestValid = Boolean(manifest?.schemaVersion === 'armorbreak.evidence-manifest/v1' && shaPattern.test(sourceCommit ?? '') &&
  manifest.files && typeof manifest.files === 'object' && !Array.isArray(manifest.files))
const tapCounts = tapBytes ? parseTap(tapBytes) : null
const reportCounts = testReport?.counts
const countKeys = ['tests', 'pass', 'fail', 'skipped', 'cancelled', 'todo']
const countsMatch = Boolean(tapCounts && reportCounts && countKeys.every((key) => Number.isSafeInteger(reportCounts[key]) && reportCounts[key] >= 0 && reportCounts[key] === tapCounts[key]))
const testsPassed = Boolean(testReport?.schemaVersion === 'armorbreak.test-report/v1' && testReport.commit === sourceCommit &&
  testReport.exitCode === 0 && testReport.processError === null && testReport.signal === null &&
  testReport.tapPath === 'docs/v2/acceptance/test-report.tap' && tapBytes && reportBytes &&
  testReport.tapSha256 === digest(tapBytes) && countsMatch && tapCounts.tests > 0 && tapCounts.pass === tapCounts.tests &&
  tapCounts.fail === 0 && tapCounts.skipped === 0 && tapCounts.cancelled === 0 && tapCounts.todo === 0 &&
  recordMatches(manifest, 'docs/v2/acceptance/test-report.json', reportBytes) &&
  recordMatches(manifest, 'docs/v2/acceptance/test-report.tap', tapBytes))

const trackedChanges = execFileSync('git', ['diff', '--name-only', 'HEAD'], { cwd: root, encoding: 'utf8' })
  .split(/\r?\n/).filter(Boolean)
const sourceChanges = trackedChanges.filter((path) =>
  !path.startsWith('docs/v2/acceptance/') && path !== 'docs/v2/release/readiness.json')
const gateResultsMatch = Boolean(gates?.gates && recomputedGates.gates &&
  gates.releasable === recomputedGates.releasable &&
  Object.keys(recomputedGates.gates).every((name) => gates.gates[name]?.status === recomputedGates.gates[name]?.status))
const gatesValid = Boolean(gates?.schemaVersion === 'armorbreak.release-gates/v2' &&
  (gates.commit === head || gates.commit === sourceCommit) && gates.evidenceManifest?.valid === true &&
  gates.evidenceManifest.commit === sourceCommit && gates.evidenceManifest.currentCommit === gates.commit &&
  gates.testReport?.status === 'PASS' && countKeys.every((key) => gates.testReport[key] === tapCounts?.[key]) && gateResultsMatch)
const evidenceOk = Boolean(evidenceValidation.ok && manifestValid && evidenceLineage && testsPassed && gatesValid && sourceChanges.length === 0)

const required = ['AB2-M4-03.md', 'AB2-M4-04.md', 'AB2-M4-06.md', 'AB2-M4-07.md', 'AB2-M4-10.md', 'AB2-M4-11.md', 'AB2-M4-12.md']
const statuses = {}
for (const file of required) {
  try {
    const bytes = readSafeRepoFile(root, `docs/v2/tasks/${file}`, { requiredPrefix: 'docs/v2/tasks/' })
    statuses[file] = /^status:\s*(\S+)/m.exec(bytes.toString('utf8'))?.[1] ?? 'UNKNOWN'
  } catch { statuses[file] = 'MISSING_OR_UNSAFE' }
}
const incomplete = required.filter((file) => statuses[file] !== 'DONE')
const sbomOk = Boolean(sbom && typeof sbom === 'object' && sbom.spdxVersion && pkg?.version && String(sbom.name ?? '').includes(pkg.version))
const ready = Boolean(gates?.releasable === true && incomplete.length === 0 && sbomOk && evidenceOk)
const result = {
  schemaVersion: 'armorbreak.release-readiness/v1',
  generatedAt: new Date().toISOString(),
  package: { name: pkg?.name, version: pkg?.version },
  sbom: sbomOk,
  commit: sourceCommit,
  evaluatedAtCommit: head,
  evidence: {
    manifestCommit: sourceCommit,
    testReportCommit: testReport?.commit ?? null,
    testCounts: reportCounts ?? null,
    current: evidenceOk,
    checks: { manifestValid, evidenceLineage, testsPassed, gatesValid, gateResultsMatch, validatorOk: evidenceValidation.ok, validatorIssues: evidenceValidation.issues, sourceChanges },
  },
  gates: gates?.gates ?? null,
  m4: statuses,
  incomplete,
  ready,
  reason: ready ? 'all required gates/tasks/evidence match the tested source commit' :
    !evidenceOk ? 'release evidence is stale, unsafe, incomplete, or not bound to the tested source commit' :
      'release blocked by incomplete gates/tasks or missing SBOM; this is not a test-pass claim',
}
if (!process.argv.includes('--check-only')) {
  writeSafeRepoFile(root, 'docs/v2/release/readiness.json', `${JSON.stringify(result, null, 2)}\n`, { requiredPrefix: 'docs/v2/release/' })
}
console.log(JSON.stringify({ ready: result.ready, candidateCommit: sourceCommit, evaluatedAtCommit: head, evidence: result.evidence.checks, incomplete, gates: Object.fromEntries(Object.entries(result.gates ?? {}).map(([key, value]) => [key, value.status])) }, null, 2))
if (!evidenceOk || (process.argv.includes('--require-ready') && !ready)) process.exitCode = 1
