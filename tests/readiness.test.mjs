import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

test('pre-release passes with real hosts and zero waivers while GA remains blocked', () => {
  const strict = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready', '--no-waivers'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(strict.status, 0)
  const strictReport = JSON.parse(strict.stdout)
  assert.equal(strictReport.preReleaseReady, true)
  assert.equal(strictReport.gaReady, false)
  const releaseTag = spawnSync('git', ['tag', '--list', 'v2.2.0'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(releaseTag.status, 0, releaseTag.stderr)
  assert.equal(strictReport.releaseTag, releaseTag.stdout.trim() === 'v2.2.0')
  assert.equal(typeof strictReport.preReleaseTag, 'boolean')
  assert.equal(strictReport.blockers.length, 0)
  assert.ok(strictReport.gaBlockers.some((blocker) => blocker.code === 'ARTIFACT_ATTESTATION_NOT_VERIFIED'))
  assert.ok(strictReport.gaBlockers.some((blocker) => blocker.code === 'ABU-311_REAL_ENDPOINT_BLOCKED'))
  assert.ok(strictReport.gaBlockers.some((blocker) => blocker.code === 'ABU-409_INDEPENDENT_REVIEW_BLOCKED'))
  assert.equal(strictReport.taskStatus['ABU-101'], 'TESTED')
  assert.equal(strictReport.taskStatus['ABU-103'], 'TESTED')

  const waived = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(waived.status, 0, waived.stderr)
  const report = JSON.parse(waived.stdout)
  assert.equal(report.preReleaseReady, true)
  assert.equal(report.ready, true)
  assert.equal(report.gaReady, false)
  assert.equal(report.blockers.length, 0)
  assert.equal(report.waived.length, 0)
  assert.ok(report.gaBlockers.some((blocker) => blocker.code === 'ABU-311_REAL_ENDPOINT_BLOCKED'))
  assert.equal(report.waiver.approvedBy, '刘依林')
  assert.equal(report.waiver.independentReview, 'NOT_SIGNED')

  const ga = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ga'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(ga.status, 1)
  assert.equal(JSON.parse(ga.stdout).gaReady, false)
})
