import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const node = process.execPath
const gateScript = 'scripts/v2/v23-release-gate.mjs'

test('PR validation mode reports the release blockers without claiming release readiness', () => {
  const result = spawnSync(node, [gateScript, '--check-pr'], { encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  assert.equal(report.gateConfiguration, 'VALIDATED')
  assert.equal(report.releaseReadiness, 'NOT_READY')
  assert.ok(report.blockers.includes('independent human security and license review'))
})

test('release mode fails closed without exact tag SHA and independent authorization evidence', () => {
  const result = spawnSync(node, [gateScript, '--release'], { encoding: 'utf8', env: { ...process.env, GITHUB_REF: 'refs/tags/v2.3.0', GITHUB_SHA: '0'.repeat(40) } })
  assert.notEqual(result.status, 0)
  const report = JSON.parse(result.stdout)
  assert.equal(report.decision, 'NOT_READY')
  assert.ok(report.blockers.includes('independent review, drill, CI, artifact and owner authorization record is missing'))
})

test('V2.3 main gate is separate and the published v2.2.0 tag guard remains present', () => {
  const workflow = readFileSync('.github/workflows/v2.3-main-gate.yml', 'utf8')
  const legacy = readFileSync('.github/workflows/ci.yml', 'utf8')
  assert.match(workflow, /pull_request:[\s\S]*branches:\s*\[main\]/)
  assert.match(workflow, /tags:\s*\['v2\.3\.0'\]/)
  assert.match(workflow, /Prepare repository-local test scratch root[\s\S]*\.runtime\/tmp/)
  assert.match(workflow, /v23-release-gate\.mjs --release/)
  assert.match(legacy, /if: github\.ref != 'refs\/tags\/v2\.2\.0'/)
  assert.match(legacy, /if: github\.ref == 'refs\/tags\/v2\.2\.0'/)
})
