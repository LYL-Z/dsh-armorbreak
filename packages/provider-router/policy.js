/** Provider egress, budget and fallback policy. Model text is never authority. */
function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])

export class ProviderPolicy {
  constructor({
    allowedHosts = ['api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com'],
    allowLoopback = true,
    budgetTokens = null,
    budgetUsd = null,
    approvedFallbacks = [],
  } = {}) {
    this.allowedHosts = new Set(allowedHosts.map((host) => String(host).toLowerCase()))
    this.allowLoopback = Boolean(allowLoopback)
    this.budgetTokens = budgetTokens
    this.budgetUsd = budgetUsd
    this.approvedFallbacks = new Set(approvedFallbacks)
    this.usedTokens = 0
    this.usedUsd = 0
    this.authorization = 'host policy; model is never an approver'
  }

  checkEgress(url) {
    let parsed
    try { parsed = new URL(String(url)) } catch { throw fail('EGRESS_INVALID', 'provider URL is invalid') }
    const host = parsed.hostname.toLowerCase()
    if (this.allowLoopback && LOOPBACK.has(host)) return { host, loopback: true }
    if (parsed.protocol !== 'https:') throw fail('EGRESS_HTTPS_REQUIRED', 'non-loopback provider endpoints must use HTTPS')
    if (!this.allowedHosts.has(host)) throw fail('EGRESS_DENIED', `provider host is not allowlisted: ${host}`)
    return { host, loopback: false }
  }

  checkBudget({ tokens = 0, costUsd = 0 } = {}) {
    if (!Number.isFinite(tokens) || tokens < 0 || !Number.isFinite(costUsd) || costUsd < 0) throw fail('BUDGET_INVALID', 'tokens/cost must be non-negative numbers')
    const nextTokens = this.usedTokens + tokens
    const nextUsd = this.usedUsd + costUsd
    if (this.budgetTokens !== null && nextTokens > this.budgetTokens) throw fail('BUDGET_EXCEEDED', `token budget exceeded: ${nextTokens}/${this.budgetTokens}`)
    if (this.budgetUsd !== null && nextUsd > this.budgetUsd) throw fail('BUDGET_EXCEEDED', `USD budget exceeded: ${nextUsd}/${this.budgetUsd}`)
    this.usedTokens = nextTokens
    this.usedUsd = nextUsd
    return { usedTokens: this.usedTokens, usedUsd: this.usedUsd }
  }

  fallback({ from, to }) {
    if (!from || !to || from === to) throw fail('FALLBACK_INVALID', 'fallback needs distinct from/to providers')
    const key = `${from}->${to}`
    if (!this.approvedFallbacks.has(key)) throw fail('FALLBACK_NOT_APPROVED', `fallback is not approved: ${key}`)
    return { from, to, approved: true }
  }
}

export function createProviderPolicy(options) {
  return new ProviderPolicy(options)
}
