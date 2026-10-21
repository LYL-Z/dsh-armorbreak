/**
 * AB2-M3-12 composite evaluation report.
 *
 * Domains are grouped and risk layers retained. Missing/unexecuted domains are
 * explicitly NOT_RUN, never folded into a pass rate.
 */
export function buildCompositeReport(input = {}) {
  const domains = {}
  for (const [domain, value] of Object.entries(input)) {
    if (!value || value.status === 'NOT_RUN' || value.executed === false) {
      domains[domain] = { status: 'NOT_RUN', reason: value?.reason ?? 'not executed' }
      continue
    }
    const results = Array.isArray(value.results) ? value.results : []
    domains[domain] = {
      status: value.status ?? 'RUN',
      riskLevel: value.riskLevel ?? 'L0',
      total: results.length,
      pass: results.filter((item) => item.verdict === 'PASS').length,
      fail: results.filter((item) => item.verdict === 'FAIL').length,
      skipped: results.filter((item) => item.verdict === 'SKIPPED').length,
      executed: true,
    }
  }
  const executed = Object.values(domains).filter((item) => item.status === 'RUN')
  return {
    schemaVersion: 'armorbreak.composite-report/v1',
    generatedAt: new Date().toISOString(),
    domains,
    executedDomains: executed.length,
    notRunDomains: Object.values(domains).filter((item) => item.status === 'NOT_RUN').length,
    total: executed.reduce((sum, item) => sum + item.total, 0),
    pass: executed.reduce((sum, item) => sum + item.pass, 0),
    fail: executed.reduce((sum, item) => sum + item.fail, 0),
    skipped: executed.reduce((sum, item) => sum + item.skipped, 0),
    notRunList: Object.entries(domains).filter(([, item]) => item.status === 'NOT_RUN').map(([domain]) => domain),
  }
}
