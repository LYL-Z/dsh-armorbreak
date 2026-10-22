import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

test('local overhead benchmark emits p50/p95 for CLI, Core and MCP HTTP', () => {
  const result = spawnSync(process.execPath, ['scripts/v2/benchmark-overhead.mjs', '--iterations', '2'], { cwd: process.cwd(), encoding: 'utf8', timeout: 120_000 })
  assert.equal(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  assert.equal(report.iterations, 2)
  assert.equal(report.realModelCalls, false)
  for (const key of ['cliStartupMs', 'coreCapabilitiesMs', 'httpCapabilitiesMs']) {
    assert.ok(Number.isFinite(report.metrics[key].p50))
    assert.ok(Number.isFinite(report.metrics[key].p95))
  }
  assert.ok(report.metrics.capabilitiesPayloadBytes > 1000)
})
