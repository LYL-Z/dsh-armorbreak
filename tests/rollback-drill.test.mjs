import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

test('JSON/TOML/YAML rollback drill restores original bytes', () => {
  const result = spawnSync(process.execPath, ['scripts/v2/rollback-drill.mjs'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  assert.equal(report.passed, true)
  assert.equal(report.json, true)
  assert.equal(report.toml, true)
  assert.equal(report.yaml, true)
  assert.equal(report.byteExact, true)
  assert.equal(report.cleanup, true)
})
