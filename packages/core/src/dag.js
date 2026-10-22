/**
 * Dependency graph (DAG) compilation for workflow tasks.
 *
 * A step may declare `dependsOn: string[]`. When it does not, it depends on the
 * previous step, so all v1.0.x sequential workflows keep their exact semantics
 * without rewriting their definitions. The runner only executes a step when all
 * of its dependencies are DONE; dependents of a failed step are skipped under
 * every policy except explicit fail-fast (which also skips unrelated steps).
 * @module dsh-armorbreak/lib/core/dag
 */

export const FAILURE_POLICIES = Object.freeze(['fail-fast', 'continue-independent', 'skip-dependent', 'retry-transient'])

/** @typedef {{
 *   id: string,
 *   title: string,
 *   capabilityId: string,
 *   options: Record<string, unknown>,
 *   dependsOn: string[],
 *   failurePolicy: 'fail-fast'|'continue-independent'|'skip-dependent'|'retry-transient',
 *   retryPolicy: {maxAttempts: number, backoffMs: number},
 *   timeoutMs: number|null,
 * }} PlanStep
 * @typedef {{steps: PlanStep[], byId: Map<string, PlanStep>, roots: string[]}} ExecutionPlan */

/** @param {unknown} value */
function asNonNegativeInt(value, fallback) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : fallback
}

/**
 * Compile and validate a step list into an execution plan.
 * @param {Array<Record<string, any>>} steps
 * @returns {ExecutionPlan}
 */
export function compilePlan(steps = []) {
  if (!Array.isArray(steps)) throw new Error('workflow steps must be an array')
  /** @type {PlanStep[]} */
  const plan = []
  const seen = new Set()
  steps.forEach((step, index) => {
    const id = String(step?.id ?? `step-${index + 1}`).trim()
    if (!id) throw new Error(`workflow step ${index + 1} has an empty id`)
    if (seen.has(id)) throw new Error(`duplicate workflow step id: ${id}`)
    seen.add(id)
    const capabilityId = String(step?.capabilityId ?? '').trim()
    if (!capabilityId) throw new Error(`workflow step ${id} has no capabilityId`)
    const failurePolicy = FAILURE_POLICIES.includes(step?.failurePolicy) ? step.failurePolicy : 'skip-dependent'
    const maxAttempts = failurePolicy === 'retry-transient'
      ? Math.min(5, Math.max(2, asNonNegativeInt(step?.retryPolicy?.maxAttempts, 2)))
      : Math.min(3, Math.max(1, asNonNegativeInt(step?.retryPolicy?.maxAttempts, 1)))
    plan.push({
      id,
      title: String(step?.title ?? capabilityId).slice(0, 300),
      capabilityId,
      options: step?.options && typeof step.options === 'object' ? step.options : {},
      dependsOn: [],
      failurePolicy,
      retryPolicy: { maxAttempts, backoffMs: Math.min(10_000, Math.max(0, asNonNegativeInt(step?.retryPolicy?.backoffMs, 250))) },
      timeoutMs: step?.timeoutMs === null || step?.timeoutMs === undefined ? null : Math.max(1000, Math.min(Number(step.timeoutMs), 15 * 60 * 1000)),
    })
  })
  const byId = new Map(plan.map((step) => [step.id, step]))
  plan.forEach((step, index) => {
    const raw = steps[index]?.dependsOn
    const dependsOn = Array.isArray(raw)
      ? [...new Set(raw.map(String))]
      : index === 0 ? [] : [plan[index - 1].id]
    for (const dependency of dependsOn) {
      if (!byId.has(dependency)) throw new Error(`workflow step ${step.id} depends on unknown step ${dependency}`)
      if (dependency === step.id) throw new Error(`workflow step ${step.id} depends on itself`)
    }
    step.dependsOn = dependsOn
  })
  // Cycle detection (Kahn).
  const indegree = new Map(plan.map((step) => [step.id, step.dependsOn.length]))
  const dependents = new Map(plan.map((step) => [step.id, []]))
  for (const step of plan) {
    for (const dependency of step.dependsOn) dependents.get(dependency).push(step.id)
  }
  const queue = plan.filter((step) => indegree.get(step.id) === 0).map((step) => step.id)
  let visited = 0
  while (queue.length > 0) {
    const id = queue.shift()
    visited += 1
    for (const child of dependents.get(id)) {
      indegree.set(child, indegree.get(child) - 1)
      if (indegree.get(child) === 0) queue.push(child)
    }
  }
  if (visited !== plan.length) throw new Error('workflow step dependency graph contains a cycle')
  return { steps: plan, byId, roots: plan.filter((step) => step.dependsOn.length === 0).map((step) => step.id) }
}

/**
 * Steps that are currently runnable: PENDING with all dependencies DONE.
 * @param {ExecutionPlan} plan
 * @param {Map<string, string>} statusById
 */
export function readySteps(plan, statusById) {
  return plan.steps.filter((step) => {
    if (statusById.get(step.id) !== 'PENDING') return false
    return step.dependsOn.every((dependency) => statusById.get(dependency) === 'DONE')
  })
}

/**
 * PENDING steps whose dependency graph can never complete (a dependency FAILED,
 * SKIPPED or CANCELLED). These become SKIPPED.
 * @param {ExecutionPlan} plan
 * @param {Map<string, string>} statusById
 */
export function blockedSteps(plan, statusById) {
  const doomed = new Set(['FAILED', 'SKIPPED', 'CANCELLED'])
  return plan.steps.filter((step) => {
    if (statusById.get(step.id) !== 'PENDING') return false
    return step.dependsOn.some((dependency) => doomed.has(statusById.get(dependency)))
  })
}

/**
 * All PENDING steps (used by fail-fast).
 * @param {ExecutionPlan} plan
 * @param {Map<string, string>} statusById
 */
export function pendingSteps(plan, statusById) {
  return plan.steps.filter((step) => statusById.get(step.id) === 'PENDING')
}

/** @param {ExecutionPlan} plan */
export function planSummary(plan) {
  return {
    steps: plan.steps.map((step) => ({ id: step.id, capabilityId: step.capabilityId, dependsOn: step.dependsOn, failurePolicy: step.failurePolicy, maxAttempts: step.retryPolicy.maxAttempts, timeoutMs: step.timeoutMs })),
    roots: plan.roots,
    parallelizable: plan.steps.some((step) => step.dependsOn.length === 0) && plan.steps.length > plan.roots.length,
  }
}
