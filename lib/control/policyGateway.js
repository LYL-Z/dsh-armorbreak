/**
 * ArmorBreak V2 Policy Gateway (AB2-M1-03).
 *
 * One explicit route for every tool/UI/system action. The gateway is deliberately
 * narrower than the runners: unknown actions are denied, model identities cannot
 * authorize, L3 is always denied, and RESOURCE_READ is kept separate from L2.
 * It delegates the actual path/network checks to the existing ScopePolicy.
 * @module dsh-armorbreak/lib/control/policyGateway
 */
export const PERMISSIONS = Object.freeze({
  READ: 'READ',
  ANALYZE: 'ANALYZE',
  AUTHORIZE: 'AUTHORIZE',
  TASK: 'TASK',
  SUPPLY_CHAIN: 'SUPPLY_CHAIN',
  RESOURCE_READ: 'RESOURCE_READ',
})

/** Every model-facing tool has exactly one entry here. */
export const TOOL_ROUTES = Object.freeze({
  armorbreak_health: { permission: PERMISSIONS.READ, riskLevel: 'L0', target: false },
  armorbreak_capabilities: { permission: PERMISSIONS.READ, riskLevel: 'L0', target: false },
  armorbreak_scope: { permission: PERMISSIONS.AUTHORIZE, riskLevel: 'L2', target: false, operatorOnly: true, control: true },
  armorbreak_files: { permission: PERMISSIONS.READ, riskLevel: 'L0', target: false },
  armorbreak_task: { permission: PERMISSIONS.TASK, riskLevel: 'L0', target: false },
  armorbreak_analyze: { permission: PERMISSIONS.ANALYZE, riskLevel: 'dynamic', target: true },
  armorbreak_workflow: { permission: PERMISSIONS.ANALYZE, riskLevel: 'dynamic', target: true },
  armorbreak_evidence: { permission: PERMISSIONS.READ, riskLevel: 'L0', target: false },
  armorbreak_report: { permission: PERMISSIONS.READ, riskLevel: 'L0', target: false },
  armorbreak_environment: { permission: PERMISSIONS.READ, riskLevel: 'L0', target: false, verifyOperatorOnly: true },
})

/** UI actions are loopback, L0-only; installation/authorization is never UI-auto. */
export const UI_ROUTES = Object.freeze({
  'ui.tasks.create': { permission: PERMISSIONS.TASK, riskLevel: 'L0' },
  'ui.tasks.cancel': { permission: PERMISSIONS.TASK, riskLevel: 'L0' },
  'ui.tasks.retry': { permission: PERMISSIONS.TASK, riskLevel: 'L0' },
  'ui.tasks.resume': { permission: PERMISSIONS.TASK, riskLevel: 'L0' },
  'ui.evaluations.run': { permission: PERMISSIONS.TASK, riskLevel: 'L0' },
  'ui.install.plan': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L0' },
  'ui.install.stage': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L0' },
  'ui.install.verify': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L0' },
  // Approval is an operator action and must be issued through a trusted host
  // surface. A loopback UI request is never an approval authority.
  'ui.install.approve': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L2', operatorOnly: true },
  'ui.install.activate': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L0' },
  'ui.install.rollback': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L0' },
})

export const SYSTEM_ROUTES = Object.freeze({
  'resource.read': { permission: PERMISSIONS.RESOURCE_READ, riskLevel: 'L0' },
  'supplychain.install': { permission: PERMISSIONS.SUPPLY_CHAIN, riskLevel: 'L2', operatorOnly: true, install: true },
})

const ALL_ROUTES = { ...TOOL_ROUTES, ...UI_ROUTES, ...SYSTEM_ROUTES }

/** @param {string} action */
export function routeOf(action) {
  const text = String(action ?? '').trim()
  if (ALL_ROUTES[text]) return { action: text, route: ALL_ROUTES[text] }
  if (text.startsWith('tool.')) {
    const name = text.slice(5)
    if (TOOL_ROUTES[name]) return { action: text, route: TOOL_ROUTES[name] }
  }
  return null
}

export class PolicyGateway {
  /**
   * @param {{scope: any, resourceConnectors?: string[], audit?: (entry: object) => Promise<void>|void}} input
   */
  constructor(input) {
    this.scope = input.scope
    this.resourceConnectors = new Set(input.resourceConnectors ?? [])
    this.audit = input.audit ?? null
  }

  catalog() {
    return Object.entries(ALL_ROUTES).map(([action, route]) => ({ action, ...route }))
  }

  /** @param {object} decision */
  async record(decision) {
    try {
      await this.audit?.(decision)
    } catch {
      /* audit must not erase a decision; caller records independently */
    }
    return decision
  }

  /**
   * @param {{
   *   action: string,
   *   identity?: {kind?: 'model'|'operator'|'ui', id?: string},
   *   permission?: string,
   *   riskLevel?: 'L0'|'L1'|'L2'|'L3',
   *   target?: string|null,
   *   targetKind?: 'file'|'directory',
   *   workspaceRoot?: string|null,
   *   taskId?: string|null,
   *   approvalId?: string|null,
   *   connector?: string|null,
   *   planHash?: string|null,
   *   options?: object,
   *   context?: object,
   * }} input
   */
  async decide(input) {
    const identity = { kind: input.identity?.kind ?? 'model', id: input.identity?.id ?? null }
    const base = { action: input.action, identity, target: input.target ?? null, riskLevel: null }
    const resolved = routeOf(input.action)
    if (!resolved) return this.record({ ...base, allowed: false, code: 'UNKNOWN_ACTION', reason: 'action is not in the V2 policy catalog' })
    const { route } = resolved
    const declaredRisk = input.riskLevel ?? route.riskLevel
    base.riskLevel = declaredRisk

    if (input.permission && route.permission && input.permission !== route.permission) {
      return this.record({ ...base, allowed: false, code: 'PERMISSION_DENIED', reason: `action requires ${route.permission}, got ${input.permission}` })
    }
    if (declaredRisk === 'L3' || route.riskLevel === 'L3') {
      return this.record({ ...base, allowed: false, code: 'L3_DENIED', reason: 'L3 operations have no automatic execution channel' })
    }
    if (route.operatorOnly && identity.kind !== 'operator') {
      return this.record({ ...base, allowed: false, code: 'MODEL_CANNOT_AUTHORIZE', reason: 'only a trusted operator identity may perform this action; model-supplied authorization is never accepted' })
    }
    if (route.install) {
      if (!input.planHash) return this.record({ ...base, allowed: false, code: 'INSTALL_PLAN_REQUIRED', reason: 'installation requires an immutable planHash approved by an operator' })
      return this.record({ ...base, allowed: false, code: 'INSTALLER_NOT_IMPLEMENTED', reason: 'transactional installer is a M2 deliverable; no code may execute before it exists' })
    }
    if (route.permission === PERMISSIONS.RESOURCE_READ) {
      const connector = String(input.connector ?? '')
      if (!connector || !this.resourceConnectors.has(connector)) {
        return this.record({ ...base, allowed: false, code: 'RESOURCE_CONNECTOR_DENIED', reason: 'only explicitly allowlisted read-only connectors may be used; this does not grant L2' })
      }
      return this.record({ ...base, allowed: true, code: 'RESOURCE_READ_ALLOWED', reason: 'read-only resource connector; L2 active-testing authorization is separate', activeTesting: false })
    }
    if (route.control) {
      return this.record({ ...base, allowed: true, code: 'OPERATOR_CONTROL_ALLOWED', reason: 'operator control action; target authorization is still enforced by ScopePolicy' })
    }

    const riskLevel = input.riskLevel ?? route.riskLevel
    if (!['L0', 'L1', 'L2'].includes(riskLevel)) {
      return this.record({ ...base, allowed: false, code: 'RISK_REQUIRED', reason: 'dynamic actions must declare L0/L1/L2 risk from the resolved capability/workflow; L3 is never allowed' })
    }
    base.riskLevel = riskLevel

    if (riskLevel === 'L0') {
      if (!route.target || !input.target) {
        return this.record({ ...base, allowed: true, code: 'L0_OK', reason: 'offline read/metadata action' })
      }
      if (!input.workspaceRoot || !input.taskId) {
        return this.record({ ...base, allowed: false, code: 'TASK_CONTEXT_REQUIRED', reason: 'file/directory L0 action needs a task workspace for containment checks' })
      }
      const check = await this.scope.checkFile({ taskId: input.taskId, targetPath: input.target, workspaceRoot: input.workspaceRoot })
      return this.record({ ...base, ...check, riskLevel: 'L0' })
    }

    const approvalId = input.approvalId ?? null
    if (!approvalId) {
      return this.record({ ...base, allowed: false, code: riskLevel === 'L1' ? 'EXECUTION_APPROVAL_REQUIRED' : 'NETWORK_APPROVAL_REQUIRED', reason: `${riskLevel} requires an operator approval bound to the exact target` })
    }
    if (riskLevel === 'L1') {
      const check = await this.scope.checkExecution({
        taskId: input.taskId,
        targetPath: input.target ?? '',
        workspaceRoot: input.workspaceRoot,
        isolationAvailable: input.context?.isolationAvailable !== false,
        approvalId,
      })
      return this.record({ ...base, ...check, riskLevel: 'L1' })
    }
    const check = await this.scope.checkNetwork({ taskId: input.taskId, target: input.target, approvalId })
    return this.record({ ...base, ...check, riskLevel: 'L2' })
  }
}
