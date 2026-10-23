#!/usr/bin/env node
/**
 * ABU-002/003: produce a commit-bound machine-readable test report and raw TAP.
 * The report is never allowed to claim PASS without the raw TAP hash.
 */
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = process.cwd()
const tapPath = 'docs/v2/acceptance/test-report.tap'
const reportPath = 'docs/v2/acceptance/test-report.json'
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const dirtyPaths = execFileSync('git', ['diff', '--name-only', 'HEAD'], { cwd: root, encoding: 'utf8' }).split(/\r?\n/).filter(Boolean)
const dirtySourcePaths = dirtyPaths.filter((path) => !path.startsWith('docs/v2/acceptance/') && path !== 'docs/v2/release/readiness.json')
if (dirtySourcePaths.length) throw new Error(`test evidence must be generated from committed source; dirty paths: ${dirtySourcePaths.join(', ')}`)
const startedAt = new Date().toISOString()
const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', '--test-concurrency=1'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
const finishedAt = new Date().toISOString()
const tap = String(run.stdout ?? '') + String(run.stderr ?? '')
const tapBytes = Buffer.from(tap)
const tapSha256 = createHash('sha256').update(tapBytes).digest('hex')
const count = (name) => Number(tap.match(new RegExp(`^# ${name} (\\d+)$`, 'm'))?.[1] ?? -1)
const counts = { tests: count('tests'), pass: count('pass'), fail: count('fail'), skipped: count('skipped'), cancelled: count('cancelled'), todo: count('todo') }
const exitCode = Number.isInteger(run.status) ? run.status : 1
const report = {
  schemaVersion: 'armorbreak.test-report/v1',
  generatedAt: new Date().toISOString(),
  commit,
  node: process.version,
  platform: process.platform,
  command: 'node --test --test-reporter=tap --test-concurrency=1',
  startedAt,
  finishedAt,
  exitCode,
  processError: run.error ? String(run.error.message ?? run.error) : null,
  signal: run.signal ?? null,
  counts,
  tapPath,
  tapSha256,
}
writeSafeRepoFile(root, tapPath, tapBytes, { requiredPrefix: 'docs/v2/acceptance/' })
writeSafeRepoFile(root, reportPath, `${JSON.stringify(report, null, 2)}\n`, { requiredPrefix: 'docs/v2/acceptance/' })
console.log(JSON.stringify({ commit, exitCode, signal: report.signal, counts: report.counts, tapSha256 }, null, 2))
if (exitCode !== 0 || counts.fail !== 0 || counts.skipped !== 0 || counts.cancelled !== 0 || counts.todo !== 0 || counts.tests <= 0 || counts.pass !== counts.tests) process.exitCode = 1
