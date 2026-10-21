/**
 * AB2-M2-02 ConnectorHealth: per-source timeout, circuit breaker, Retry-After
 * and bounded exponential backoff. One failing source never blocks another.
 */
export const BREAKER_STATES = Object.freeze(['CLOSED', 'OPEN', 'HALF_OPEN'])

export class ConnectorHealth {
  /**
   * @param {{clock?: () => number, failureThreshold?: number, cooldownMs?: number, baseBackoffMs?: number, maxBackoffMs?: number}} [input]
   */
  constructor(input = {}) {
    this.clock = input.clock ?? Date.now
    this.failureThreshold = Math.max(1, Number(input.failureThreshold ?? 3))
    this.cooldownMs = Math.max(1000, Number(input.cooldownMs ?? 30_000))
    this.baseBackoffMs = Math.max(100, Number(input.baseBackoffMs ?? 500))
    this.maxBackoffMs = Math.max(this.baseBackoffMs, Number(input.maxBackoffMs ?? 60_000))
    this.connectors = new Map()
  }

  register(id) {
    if (!this.connectors.has(id)) {
      this.connectors.set(id, { id, breaker: 'CLOSED', failures: 0, successes: 0, openedAt: null, retryAfter: null, lastError: null })
    }
    return this.snapshot(id)
  }

  get(id) {
    return this.connectors.get(id) ?? null
  }

  canAttempt(id) {
    const state = this.connectors.get(id)
    if (!state) return false
    if (state.breaker === 'CLOSED') return true
    if (state.breaker === 'OPEN' && state.openedAt !== null && this.clock() - state.openedAt >= this.cooldownMs) {
      state.breaker = 'HALF_OPEN'
      return true
    }
    return state.breaker === 'HALF_OPEN'
  }

  backoff(id) {
    const state = this.connectors.get(id)
    if (!state) return this.baseBackoffMs
    const exp = Math.min(this.maxBackoffMs, this.baseBackoffMs * (2 ** Math.max(0, state.failures - 1)))
    return Math.max(exp, state.retryAfter ? Math.max(0, state.retryAfter - this.clock()) : 0)
  }

  recordSuccess(id) {
    const state = this.connectors.get(id)
    if (!state) throw new Error(`unknown connector: ${id}`)
    state.failures = 0
    state.successes += 1
    state.breaker = 'CLOSED'
    state.openedAt = null
    state.retryAfter = null
    state.lastError = null
    return this.snapshot(id)
  }

  recordFailure(id, details = {}) {
    const state = this.connectors.get(id)
    if (!state) throw new Error(`unknown connector: ${id}`)
    state.failures += 1
    state.lastError = String(details.message ?? details.status ?? 'failure').slice(0, 300)
    if (details.retryAfterMs) state.retryAfter = this.clock() + Math.max(0, Number(details.retryAfterMs))
    if (details.status === 429 && details.retryAfterMs) {
      state.breaker = 'OPEN'
      state.openedAt = this.clock()
    } else if (state.failures >= this.failureThreshold) {
      state.breaker = 'OPEN'
      state.openedAt = this.clock()
    }
    return this.snapshot(id)
  }

  snapshot(id) {
    const state = this.connectors.get(id)
    if (!state) return null
    return {
      id: state.id,
      breaker: state.breaker,
      failures: state.failures,
      successes: state.successes,
      retryAfterMs: state.retryAfter ? Math.max(0, state.retryAfter - this.clock()) : 0,
      nextBackoffMs: this.canAttempt(id) ? this.backoff(id) : this.backoff(id),
      lastError: state.lastError,
    }
  }

  all() {
    return [...this.connectors.keys()].map((id) => this.snapshot(id))
  }
}
