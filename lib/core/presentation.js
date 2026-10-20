/**
 * Secret-free presentation model shared by the Host routes and the browser card.
 *
 * Keeping labels here (instead of scattering strings in client.js) makes the UI
 * semantics testable: "L2: 0" was misleading because zero authorizations does not
 * mean zero active-testing capability, and an available Docker CLI is not the same
 * as a verified isolation provider.
 * @module dsh-armorbreak/lib/core/presentation
 */

/** @param {any} isolation */
export function isolationPresentation(isolation) {
  if (!isolation) return { state: 'Unknown', label: '未检测', tone: 'idle' }
  if (isolation.available) {
    return {
      state: 'DaemonReady',
      label: isolation.provider ? `${isolation.provider} 守护进程可用（未执行隔离自检）` : '隔离提供者可用（未自检）',
      tone: 'success',
      selfTested: false,
    }
  }
  const reason = String(isolation.reason ?? '')
  if (/not found|absent|未发现|no container runtime/i.test(reason)) return { state: 'Unavailable', label: '不可用（未检测到容器运行时）', tone: 'idle', reason: reason.slice(0, 200) }
  if (/permission|denied|refused|错误|error/i.test(reason)) return { state: 'Error', label: '检测失败', tone: 'error', reason: reason.slice(0, 200) }
  return { state: 'Unavailable', label: '不可用', tone: 'muted', reason: reason.slice(0, 200) }
}

/**
 * L1/L2/L3 labels. The authority count is not a capability count.
 * @param {any} policy
 */
export function policyPresentation(policy) {
  const authorizations = Array.isArray(policy?.authorizations) ? policy.authorizations : []
  const active = authorizations.filter((item) => item.active)
  return {
    l0: { label: 'L0 离线分析', tone: 'success' },
    l1: { label: 'L1 动态分析', tone: 'muted', requires: ['隔离提供者', '平台审批'] },
    l2: { label: active.length === 0 ? 'L2 主动测试：无授权目标' : `L2 主动测试：${active.length} 个授权目标`, tone: active.length === 0 ? 'muted' : 'success', activeAuthorizations: active.length },
    l3: { label: 'L3 破坏/外传：始终拒绝', tone: 'error' },
  }
}

/** @param {any[]} tasks */
export function taskRows(tasks = []) {
  return tasks.map((task) => ({
    id: task.id,
    title: String(task.title ?? '').slice(0, 160),
    state: task.state,
    workflow: task.workflowId ?? task.workflow ?? null,
    target: task.targetPath ? String(task.targetPath).split(/[\\/]/).pop() : null,
    evidence: task.stats?.evidence ?? 0,
    findings: task.stats?.findings ?? 0,
    report: task.report ? { format: task.report.format, path: task.report.path, sha256: task.report.sha256 } : null,
    updatedAt: task.updatedAt ?? null,
    createdAt: task.createdAt ?? null,
  }))
}

/** @param {any[]} findings */
export function findingRows(findings = []) {
  return findings.map((finding) => ({
    id: finding.id,
    title: String(finding.title ?? '').slice(0, 200),
    severity: finding.severity ?? 'info',
    verification: finding.verification ?? 'unverified',
    cwe: finding.cwe ?? null,
    target: finding.target ? String(finding.target).slice(0, 200) : null,
  }))
}

/**
 * Group capabilities by domain for the tool center. External tools are only
 * names until HealthService probes them; the UI must not present them as installed.
 * @param {any[]} capabilities
 * @param {any} isolation
 */
export function toolsPresentation(capabilities = [], isolation = null) {
  const domains = {}
  for (const capability of capabilities) {
    const domain = capability.domain ?? 'unknown'
    domains[domain] ??= { domain, capabilities: [], externalTools: new Set() }
    domains[domain].capabilities.push({ id: capability.id, title: capability.title, riskLevel: capability.riskLevel, targetKind: capability.targetKind })
    for (const tool of capability.externalTools ?? []) domains[domain].externalTools.add(tool)
  }
  return {
    isolation: isolationPresentation(isolation),
    domains: Object.values(domains).map((item) => ({
      domain: item.domain,
      capabilityCount: item.capabilities.length,
      capabilities: item.capabilities,
      externalTools: [...item.externalTools].map((name) => ({ name, availability: 'not-probed' })),
    })),
  }
}

/** @param {any} queueSnapshot */
export function queueRows(queueSnapshot = []) {
  return (Array.isArray(queueSnapshot) ? queueSnapshot : []).map((entry) => ({
    taskId: entry.taskId,
    state: entry.state,
    queued: Boolean(entry.queued),
    startedAt: entry.startedAt ?? null,
    finishedAt: entry.finishedAt ?? null,
    error: entry.error ?? null,
  }))
}
