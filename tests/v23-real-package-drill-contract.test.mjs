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
  assert.equal((workflow.match(/node-version: 22\.23\.4/g) ?? []).length, 2, 'PR and exact-main package drills must reproduce the historical Windows Node runtime')
  assert.match(workflow, /Upload PR Windows diagnostics \(including failure evidence\)[\s\S]*if: \$\{\{ always\(\) \}\}/)
  assert.match(workflow, /Upload successful PR Windows drill evidence[\s\S]*if: \$\{\{ success\(\) \}\}/)
  const failureUploadSection = workflow.split('Upload PR Windows diagnostics (including failure evidence)')[1]?.split('Upload successful PR Windows drill evidence')[0] ?? ''
  assert.doesNotMatch(failureUploadSection, /real-package-upgrade-rollback\.json/)
  assert.match(workflow, /Upload exact-main Windows drill diagnostics[\s\S]*if: \$\{\{ always\(\) \}\}/)
  assert.match(workflow, /release-verification:[\s\S]*refs\/tags\/v2\.3\.1/)
})

test('Windows ACL drill permits only the runner principal and Local System and records safe principal classes', () => {
  assert.match(drill, /allowedAclClasses = new Set\(\['CURRENT_USER', 'LOCAL_SYSTEM'\]\)/)
  assert.match(drill, /principalClass: classifyAclSid\(entry\.sid\)/)
  assert.match(drill, /aclEntries\.some\(\(entry\) => !allowedAclClasses\.has\(classifyAclSid\(entry\.sid\)\)/)
  assert.match(drill, /'\/remove:g', `\*\$\{adminSid\}`/)
  assert.match(drill, /summary\('icacls\.exe', \['isolated temp root', '\/remove:g', 'BUILTIN_ADMINISTRATORS'/)
  assert.match(drill, /aclRestrictedToCurrentUserAndLocalSystem: true/)
})
