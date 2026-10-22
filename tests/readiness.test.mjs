import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

test('pre-release can pass with owner waivers but GA remains blocked', () => {
  const strict = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready', '--no-waivers'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(strict.status, 1)
  const strictReport = JSON.parse(strict.stdout)
  assert.equal(strictReport.preReleaseReady, false)
  assert.equal(strictReport.gaReady, false)
  assert.equal(strictReport.releaseTag, true)
  assert.ok(strictReport.blockers.length > 0)
  assert.ok(strictReport.gaBlockers.some((blocker) => blocker.code === 'ARTIFACT_UNSIGNED'))
  assert.ok(strictReport.gaBlockers.some((blocker) => blocker.code.startsWith('HOST_Claude Code')))
  assert.equal(strictReport.taskStatus['ABU-101'], 'TESTED')
  assert.equal(strictReport.taskStatus['ABU-103'], 'TESTED')

  const waived = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(waived.status, 0, waived.stderr)
  const report = JSON.parse(waived.stdout)
  assert.equal(report.preReleaseReady, true)
  assert.equal(report.ready, true)
  assert.equal(report.gaReady, false)
  assert.equal(report.blockers.length, 0)
  assert.ok(report.waived.some((blocker) => blocker.code === 'ARTIFACT_UNSIGNED'))
  assert.ok(report.gaBlockers.some((blocker) => blocker.code === 'ABU-311_REAL_ENDPOINT_BLOCKED'))
  assert.equal(report.waiver.approvedBy, '刘依林')
  assert.equal(report.waiver.independentReview, 'WAIVED_BY_OWNER')

  const ga = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ga'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(ga.status, 1)
  assert.equal(JSON.parse(ga.stdout).gaReady, false)
})
