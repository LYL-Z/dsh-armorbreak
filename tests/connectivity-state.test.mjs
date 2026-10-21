import assert from 'node:assert/strict'
import test from 'node:test'
import { NetworkStateMachine } from '../lib/connectivity/networkState.js'
import { ConnectorHealth } from '../lib/connectivity/connectorHealth.js'

test('NetworkState hysteresis: healthy -> degraded -> offline -> recovering -> healthy', () => {
  const fsm = new NetworkStateMachine({ failThreshold: 2, recoverThreshold: 2 })
  assert.equal(fsm.state, 'UNKNOWN')
  fsm.probe(true)
  assert.equal(fsm.state, 'HEALTHY')
  fsm.probe(false)
  assert.equal(fsm.state, 'DEGRADED')
  fsm.probe(false)
  assert.equal(fsm.state, 'OFFLINE')
  fsm.startRecovery()
  fsm.probe(true)
  assert.equal(fsm.state, 'RECOVERING')
  fsm.probe(true)
  assert.equal(fsm.state, 'HEALTHY')
})

test('staging preserves previous state and failed staging goes offline', () => {
  const fsm = new NetworkStateMachine()
  fsm.probe(true)
  fsm.startStaging()
  assert.equal(fsm.state, 'STAGING')
  fsm.endStaging(true)
  assert.equal(fsm.state, 'HEALTHY')
  fsm.startStaging()
  fsm.endStaging(false)
  assert.equal(fsm.state, 'OFFLINE')
})

test('invalid transitions are rejected and history is bounded', () => {
  const fsm = new NetworkStateMachine({ maxHistory: 10 })
  assert.throws(() => fsm.endStaging(true), /staging not active/)
  assert.throws(() => fsm.startRecovery(), /OFFLINE/)
  for (let i = 0; i < 20; i += 1) {
    if (fsm.state === 'HEALTHY') fsm.probe(false)
    else fsm.probe(true)
  }
  assert.ok(fsm.history.length <= 10)
})

test('ConnectorHealth isolates a 429 source and honors Retry-After', () => {
  let now = 1_000_000
  const health = new ConnectorHealth({ clock: () => now, failureThreshold: 3, cooldownMs: 5_000 })
  health.register('kev')
  health.register('osv')
  health.recordSuccess('osv')
  health.recordFailure('kev', { status: 429, retryAfterMs: 5000 })
  assert.equal(health.snapshot('kev').breaker, 'OPEN')
  assert.equal(health.snapshot('osv').breaker, 'CLOSED')
  assert.equal(health.canAttempt('osv'), true)
  assert.equal(health.canAttempt('kev'), false)
  assert.ok(health.backoff('kev') >= 5000)
  now += 5001
  assert.equal(health.canAttempt('kev'), true)
  assert.equal(health.snapshot('kev').breaker, 'HALF_OPEN')
  health.recordSuccess('kev')
  assert.equal(health.snapshot('kev').breaker, 'CLOSED')
})

test('ConnectorHealth exponential backoff is bounded and no busy loop', () => {
  let now = 0
  const health = new ConnectorHealth({ clock: () => now, failureThreshold: 2, baseBackoffMs: 100, maxBackoffMs: 1000, cooldownMs: 1000 })
  health.register('x')
  health.recordFailure('x', { message: 'timeout' })
  const first = health.backoff('x')
  health.recordFailure('x', { message: 'timeout' })
  const second = health.backoff('x')
  assert.ok(first > 0 && second >= first)
  assert.ok(second <= 1000)
  assert.equal(health.canAttempt('x'), false)
  now += 1001
  assert.equal(health.canAttempt('x'), true)
})
