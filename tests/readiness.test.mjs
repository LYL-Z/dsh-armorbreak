import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

test('V2.2 readiness gate refuses GA while blockers remain', () => {
  const result = spawnSync(process.execPath, ['scripts/v2/v2-readiness.mjs', '--require-ready'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(result.status, 1)
  const report = JSON.parse(result.stdout)
  assert.equal(report.ready, false)
  assert.equal(report.releaseTag, false)
  assert.ok(report.blockers.length > 0)
  assert.ok(report.blockers.some((blocker) => blocker.code === 'ARTIFACT_UNSIGNED'))
  assert.ok(report.blockers.some((blocker) => blocker.code.startsWith('HOST_Claude Code')))
  assert.equal(report.taskStatus['ABU-101'], 'TESTED')
  assert.equal(report.taskStatus['ABU-103'], 'TESTED')
})
