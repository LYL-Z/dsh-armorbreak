import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

test('V2.2 readiness refuses without waivers and passes with owner waivers', () => {
  const strict = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready', '--no-waivers'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(strict.status, 1)
  const strictReport = JSON.parse(strict.stdout)
  assert.equal(strictReport.ready, false)
  assert.equal(strictReport.releaseTag, false)
  assert.ok(strictReport.blockers.length > 0)
  assert.ok(strictReport.blockers.some((blocker) => blocker.code === 'ARTIFACT_UNSIGNED'))
  assert.ok(strictReport.blockers.some((blocker) => blocker.code.startsWith('HOST_Claude Code')))
  assert.equal(strictReport.taskStatus['ABU-101'], 'TESTED')
  assert.equal(strictReport.taskStatus['ABU-103'], 'TESTED')

  const waived = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(waived.status, 0, waived.stderr)
  const report = JSON.parse(waived.stdout)
  assert.equal(report.ready, true)
  assert.equal(report.blockers.length, 0)
  assert.ok(report.waived.some((blocker) => blocker.code === 'ARTIFACT_UNSIGNED'))
  assert.equal(report.waiver.approvedBy, '刘依林')
  assert.equal(report.waiver.independentReview, 'WAIVED_BY_OWNER')
})
