import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const drill = readFileSync('scripts/v2/v23-real-package-drill.mjs', 'utf8')
const workflow = readFileSync('.github/workflows/v2.3-main-gate.yml', 'utf8')

test('Windows package drill distinguishes V2.2 task and report failures and records redacted filesystem diagnostics', () => {
  assert.match(drill, /if \(v22Task\.status !== 0\)[\s\S]*FAIL_V22_TASK_READ/)
  assert.match(drill, /if \(v22Report\.status !== 0\)[\s\S]*FAIL_V22_REPORT_READ/)
  assert.match(drill, /v22Task\.status[\s\S]*v22Report\.status/)
  for (const field of ['formatValid', 'workspaceMatches', 'principalMatches', 'sessionIsNull', 'stderr:', 'bytes:', 'sha256:', 'realpathMatchesExpected', 'dev:', 'ino:', 'nlink:', 'windowsRelease:', 'gitVersion:', 'tempEqualsTmp', 'tempPathSha256', 'tmpPathSha256', 'stateRootMatchesConfigured', 'workspaceMatchesConfigured']) {
    assert.ok(drill.includes(field), `missing required Windows failure diagnostic field ${field}`)
  }
  assert.match(drill, /V23_DIAGNOSTICS_PATH/)
  assert.match(drill, /writeDiagnostics\(\)[\s\S]*cleanupScratch\(scratch\)/)
  assert.match(drill, /file:\\\//)
  assert.match(drill, /<redacted-path>/)
  assert.match(drill, /stderrSha256/)
})

test('real package integration exercises fresh CLI reads, candidate refusal, and byte-preserving rollback', () => {
  assert.match(drill, /const v22Task = cli\(v22Install[\s\S]*const v22Report = cli\(v22Install/)
  assert.match(drill, /const candidateTask = cli\(candidateInstall[\s\S]*const candidateReport = cli\(candidateInstall/)
  assert.match(drill, /injectedFailureRejected/)
  assert.match(drill, /assert\.deepEqual\(after, before\)/)
  assert.match(drill, /candidateReadHistoricalTaskAndReport: true/)
})

test('PR and exact-main workflows run real Windows deployment before Tag creation and always upload failure diagnostics', () => {
  assert.match(workflow, /pr-windows-package-drill:[\s\S]*event_name == 'pull_request'[\s\S]*Run real V2\.2 to exact PR package deployment and rollback drill/)
  assert.match(workflow, /main-windows-package-drill:[\s\S]*refs\/heads\/main[\s\S]*Run real V2\.2 to exact main V2\.3 package deployment and rollback drill/)
  assert.match(workflow, /Upload PR Windows drill evidence and diagnostics[\s\S]*if: \$\{\{ always\(\) \}\}/)
  assert.match(workflow, /Upload exact-main Windows drill diagnostics[\s\S]*if: \$\{\{ always\(\) \}\}/)
  assert.match(workflow, /release-verification:[\s\S]*refs\/tags\/v2\.3\.1/)
})
