import assert from 'node:assert/strict'
import test from 'node:test'
import { NetworkStateMachine } from '../lib/connectivity/networkState.js'
import { ConnectorHealth } from '../lib/connectivity/connectorHealth.js'

test('12-class network/connector fault matrix', () => {
  let now = 1000
  const health = new ConnectorHealth({ clock: () => now, failureThreshold: 2, cooldownMs: 1000, baseBackoffMs: 100, maxBackoffMs: 1000 })
  health.register('a'); health.register('b'); health.register('c')
  const fsm = new NetworkStateMachine({ failThreshold: 2, recoverThreshold: 2 })
  const results = {}

  // 1 probe fail from unknown -> degraded
  fsm.probe(false); results['probe-fail-unknown'] = fsm.state === 'DEGRADED'
  // 2 repeated fail -> offline
  fsm.probe(false); results['failure-threshold'] = fsm.state === 'OFFLINE'
  // 3 single transient fail does not oscillate
  fsm.startRecovery(); fsm.probe(false); results['recovery-fail'] = fsm.state === 'OFFLINE'
  // 4 recovery threshold
  fsm.startRecovery(); fsm.probe(true); const afterOne = fsm.state; fsm.probe(true); results['recovery-threshold'] = afterOne === 'RECOVERING' && fsm.state === 'HEALTHY'
  // 5 staging success preserves previous
  fsm.startStaging(); fsm.endStaging(true); results['staging-success'] = fsm.state === 'HEALTHY'
  // 6 staging fail goes offline
  fsm.startStaging(); fsm.endStaging(false); results['staging-fail'] = fsm.state === 'OFFLINE'
  // 7 manual force offline idempotent
  fsm.probe(true); fsm.startRecovery(); fsm.forceOffline('manual'); results['manual-offline'] = fsm.state === 'OFFLINE'
  // 8 invalid transition rejected
  let rejected = false; try { fsm.endStaging(true) } catch { rejected = true } results['invalid-transition'] = rejected
  // 9 history bounded
  for (let i = 0; i < 20; i += 1) { if (fsm.state === 'HEALTHY') fsm.probe(false); else fsm.probe(true) }
  results['history-bounded'] = fsm.history.length <= 20
  // 10 one source 429 isolated
  health.recordFailure('a', { status: 429, retryAfterMs: 200 }); health.recordSuccess('b'); health.recordSuccess('c')
  results['429-isolated'] = health.snapshot('a').breaker === 'OPEN' && health.snapshot('b').breaker === 'CLOSED' && health.snapshot('c').breaker === 'CLOSED'
  // 11 half-open recovery
  now += 1001; const can = health.canAttempt('a'); health.recordSuccess('a')
  results['half-open'] = can === true && health.snapshot('a').breaker === 'CLOSED'
  // 12 exponential backoff bounded
  health.recordFailure('b', { message: 'timeout' }); health.recordFailure('b', { message: 'timeout' }); const backoff = health.backoff('b')
  results['backoff-bounded'] = backoff > 0 && backoff <= 1000 && health.canAttempt('b') === false

  for (const [name, passed] of Object.entries(results)) assert.equal(passed, true, name)
  assert.equal(Object.keys(results).length, 12)
})
