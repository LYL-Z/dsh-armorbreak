#!/usr/bin/env node
/**
 * ABU-002/003: produce a commit-bound machine-readable test report and raw TAP.
 * The report is never allowed to claim PASS without the raw TAP hash.
 */
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { readFileSync } from 'node:fs'

const root = process.cwd()
const tapPath = 'docs/v2/acceptance/test-report.tap'
const reportPath = 'docs/v2/acceptance/test-report.json'
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
const tap = String(run.stdout ?? '') + String(run.stderr ?? '')
writeFileSync(tapPath, tap)
const tapSha256 = createHash('sha256').update(readFileSync(tapPath)).digest('hex')
const count = (name) => Number(tap.match(new RegExp(`^# ${name} (\\d+)$`, 'm'))?.[1] ?? -1)
const report = {
  schemaVersion: 'armorbreak.test-report/v1',
  generatedAt: new Date().toISOString(),
  commit,
  node: process.version,
  platform: process.platform,
  command: 'node --test --test-reporter=tap',
  exitCode: run.status,
  counts: { tests: count('tests'), pass: count('pass'), fail: count('fail'), skipped: count('skipped'), cancelled: count('cancelled'), todo: count('todo') },
  tapPath,
  tapSha256,
}
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ commit, exitCode: run.status, counts: report.counts, tapSha256 }, null, 2))
if (run.status !== 0 || report.counts.fail !== 0 || report.counts.tests <= 0) process.exitCode = 1
