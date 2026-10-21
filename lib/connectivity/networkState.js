/**
 * AB2-M2-01 NetworkState FSM.
 *
 * Event-driven six-state machine with hysteresis (failure/recovery thresholds)
 * so a flapping probe cannot oscillate the UI. It does not perform network I/O;
 * callers feed probe/staging events and can persist the transition log.
 */
export const NETWORK_STATES = Object.freeze(['UNKNOWN', 'HEALTHY', 'DEGRADED', 'OFFLINE', 'RECOVERING', 'STAGING'])

export const NETWORK_TRANSITIONS = Object.freeze({
  UNKNOWN: ['HEALTHY', 'DEGRADED'],
  HEALTHY: ['DEGRADED', 'STAGING'],
  DEGRADED: ['HEALTHY', 'OFFLINE', 'STAGING'],
  OFFLINE: ['RECOVERING', 'STAGING'],
  RECOVERING: ['HEALTHY', 'OFFLINE'],
  STAGING: ['HEALTHY', 'DEGRADED', 'OFFLINE'],
})

export class NetworkStateMachine {
  /**
   * @param {{failThreshold?: number, recoverThreshold?: number, clock?: () => number, maxHistory?: number, onChange?: Function}} [input]
   */
  constructor(input = {}) {
    this.failThreshold = Math.max(1, Math.min(Number(input.failThreshold ?? 2), 10))
    this.recoverThreshold = Math.max(1, Math.min(Number(input.recoverThreshold ?? 2), 10))
    this.clock = input.clock ?? Date.now
    this.maxHistory = Math.max(10, Number(input.maxHistory ?? 200))
    this.onChange = input.onChange ?? null
    this.state = 'UNKNOWN'
    this.failures = 0
    this.successes = 0
    this.previous = null
    this.history = [{ at: new Date(this.clock()).toISOString(), from: null, to: 'UNKNOWN', reason: 'initial' }]
  }

  canTransition(to) {
    return NETWORK_STATES.includes(to) && (NETWORK_TRANSITIONS[this.state] ?? []).includes(to)
  }

  transition(to, reason, meta = {}) {
    if (!this.canTransition(to)) throw new Error(`invalid network transition ${this.state} -> ${to}`)
    const from = this.state
    this.state = to
    if (from !== to) this.history.push({ at: new Date(this.clock()).toISOString(), from, to, reason: String(reason ?? ''), ...meta })
    while (this.history.length > this.maxHistory) this.history.shift()
    try { this.onChange?.({ from, to, reason, state: this.snapshot() }) } catch { /* observer must not break state */ }
    return this.snapshot()
  }

  /** Feed a connectivity probe result. */
  probe(ok, meta = {}) {
    if (ok) {
      this.failures = 0
      if (this.state === 'UNKNOWN') return this.transition('HEALTHY', 'probe-ok', meta)
      if (this.state === 'DEGRADED') return this.transition('HEALTHY', 'probe-ok', meta)
      if (this.state === 'RECOVERING') {
        this.successes += 1
        if (this.successes >= this.recoverThreshold) return this.transition('HEALTHY', 'recovery-threshold-met', meta)
        return this.snapshot()
      }
      return this.snapshot()
    }
    this.successes = 0
    if (this.state === 'HEALTHY' || this.state === 'UNKNOWN') {
      this.failures = 1
      return this.transition('DEGRADED', 'probe-failed', meta)
    }
    if (this.state === 'DEGRADED') {
      this.failures += 1
      if (this.failures >= this.failThreshold) return this.transition('OFFLINE', 'failure-threshold-met', meta)
      return this.snapshot()
    }
    if (this.state === 'RECOVERING') return this.transition('OFFLINE', 'recovery-probe-failed', meta)
    return this.snapshot()
  }

  startRecovery(meta = {}) {
    if (this.state !== 'OFFLINE') throw new Error('recovery can only start from OFFLINE')
    this.successes = 0
    return this.transition('RECOVERING', 'recovery-started', meta)
  }

  startStaging(meta = {}) {
    if (!['HEALTHY', 'DEGRADED', 'OFFLINE'].includes(this.state)) throw new Error(`cannot stage from ${this.state}`)
    this.previous = this.state
    return this.transition('STAGING', 'staging-started', meta)
  }

  endStaging(ok = true, meta = {}) {
    if (this.state !== 'STAGING') throw new Error('staging not active')
    const target = ok ? (this.previous === 'OFFLINE' ? 'OFFLINE' : this.previous ?? 'DEGRADED') : 'OFFLINE'
    return this.transition(target, ok ? 'staging-complete' : 'staging-failed', meta)
  }

  forceOffline(reason = 'manual', meta = {}) {
    if (this.state === 'OFFLINE') return this.snapshot()
    if (!this.canTransition('OFFLINE')) {
      // UNKNOWN/HEALTHY/DEGRADED can be forced via an explicit path without
      // pretending an intermediate probe happened.
      this.state = 'OFFLINE'
      this.history.push({ at: new Date(this.clock()).toISOString(), from: 'UNKNOWN', to: 'OFFLINE', reason })
      return this.snapshot()
    }
    return this.transition('OFFLINE', reason, meta)
  }

  snapshot() {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      previous: this.previous,
      thresholds: { fail: this.failThreshold, recover: this.recoverThreshold },
      history: this.history.slice(-20),
    }
  }
}
