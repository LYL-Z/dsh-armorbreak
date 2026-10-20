/**
 * Durable analysis task store and the explicit task state machine.
 *
 * States follow the task specification:
 *   CREATED →SCOPE_VALIDATION →ENVIRONMENT_CHECK →PLANNING
 *   →(APPROVAL_REQUIRED →REJECTED | EXECUTING) →COLLECTING_EVIDENCE →VERIFYING
 *   →REPORTING →COMPLETED
 * Exceptional terminal states: FAILED, TIMED_OUT, CANCELLED, PARTIAL_SUCCESS.
 * @module dsh-armorbreak/lib/core/tasks
 */
import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { EvidenceStore } from './evidence.js'
import { ensureDir, newId, nowIso, readJson, sha256, withFileMutex, writeJsonAtomic } from './util.js'

export const TASK_STATES = /** @type {const} */ ([
  'CREATED',
  'SCOPE_VALIDATION',
  'ENVIRONMENT_CHECK',
  'PLANNING',
  'APPROVAL_REQUIRED',
  'EXECUTING',
  'COLLECTING_EVIDENCE',
  'VERIFYING',
  'REPORTING',
  'COMPLETED',
  'REJECTED',
  'FAILED',
  'TIMED_OUT',
  'CANCELLED',
  'PARTIAL_SUCCESS',
])

/** Terminal states never leave. */
export const TERMINAL_STATES = new Set(['COMPLETED', 'REJECTED', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'PARTIAL_SUCCESS'])

/** Allowed state transitions; anything else throws. */
const TRANSITIONS = {
  CREATED: ['SCOPE_VALIDATION', 'CANCELLED', 'FAILED'],
  SCOPE_VALIDATION: ['ENVIRONMENT_CHECK', 'REJECTED', 'FAILED', 'CANCELLED'],
  ENVIRONMENT_CHECK: ['PLANNING', 'APPROVAL_REQUIRED', 'FAILED', 'CANCELLED'],
  PLANNING: ['APPROVAL_REQUIRED', 'EXECUTING', 'REJECTED', 'FAILED', 'CANCELLED'],
  APPROVAL_REQUIRED: ['EXECUTING', 'REJECTED', 'CANCELLED', 'FAILED'],
  EXECUTING: ['COLLECTING_EVIDENCE', 'VERIFYING', 'PARTIAL_SUCCESS', 'FAILED', 'TIMED_OUT', 'CANCELLED'],
  COLLECTING_EVIDENCE: ['VERIFYING', 'EXECUTING', 'PARTIAL_SUCCESS', 'FAILED', 'TIMED_OUT', 'CANCELLED'],
  VERIFYING: ['REPORTING', 'COMPLETED', 'PARTIAL_SUCCESS', 'FAILED', 'CANCELLED'],
  REPORTING: ['COMPLETED', 'PARTIAL_SUCCESS', 'FAILED', 'CANCELLED'],
  COMPLETED: [],
  REJECTED: [],
  FAILED: [],
  TIMED_OUT: [],
  CANCELLED: [],
  PARTIAL_SUCCESS: [],
}

export const STEP_STATES = /** @type {const} */ (['PENDING', 'RUNNING', 'DONE', 'FAILED', 'SKIPPED', 'CANCELLED'])

/**
 * @param {string} workspaceRoot
 * @returns {string}
 */
export function taskStateRoot(workspaceRoot) {
  return join(workspaceRoot, '.armorbreak')
}

export class TaskStore {
  /**
   * @param {{workspaceRoot: string, audit?: import('./audit.js').AuditLog}} options
   */
  constructor(options) {
    this.workspaceRoot = options.workspaceRoot
    this.root = taskStateRoot(options.workspaceRoot)
    this.tasksDir = join(this.root, 'tasks')
    this.audit = options.audit
  }

  /** @param {string} taskId */
  taskDir(taskId) {
    return join(this.tasksDir, taskId)
  }

  /** @param {string} taskId */
  taskFile(taskId) {
    return join(this.taskDir(taskId), 'task.json')
  }

  /** @param {string} taskId */
  evidenceStore(taskId) {
    return new EvidenceStore({ taskId, taskDir: this.taskDir(taskId), audit: this.audit })
  }

  /**
   * @param {{
   *   title: string,
   *   objective?: string,
   *   workflowId?: string|null,
   *   targetPath?: string|null,
   *   targetKind?: 'file'|'directory'|'none',
   *   operator?: string,
   *   steps?: Array<{id: string, title: string, capabilityId: string, options?: Record<string, unknown>}>,
   *   tags?: string[],
   * }} input
   */
  async create(input) {
    const steps = (input.steps ?? []).map((step, index) => ({
      id: step.id || `step-${index + 1}`,
      title: step.title ?? step.capabilityId,
      capabilityId: step.capabilityId,
      options: step.options ?? {},
      status: 'PENDING',
      startedAt: null,
      finishedAt: null,
      error: null,
      summary: null,
      evidenceIds: [],
      findingIds: [],
      durationMs: null,
      attempt: 0,
    }))
    const id = newId('task')
    const task = {
      id,
      title: String(input.title ?? 'Untitled analysis').slice(0, 300),
      objective: String(input.objective ?? '').slice(0, 4000),
      workflowId: input.workflowId ?? null,
      targetPath: input.targetPath ?? null,
      targetKind: input.targetKind ?? 'file',
      operator: input.operator ?? 'local-user',
      tags: Array.isArray(input.tags) ? input.tags.slice(0, 20) : [],
      workspace: this.workspaceRoot,
      state: 'CREATED',
      stateHistory: [{ state: 'CREATED', at: nowIso(), reason: 'task created' }],
      steps: steps.length > 0 ? steps : [],
      currentStep: 0,
      riskMax: 'L0',
      approvals: [],
      notes: [],
      createdAt: nowIso(),
      updatedAt: nowIso(),
      completedAt: null,
      error: null,
      report: null,
      stats: { evidence: 0, findings: 0, stepsDone: 0, stepsFailed: 0 },
    }
    await ensureDir(this.taskDir(id))
    await this.save(task)
    await this.audit?.append({ action: 'task.create', taskId: id, title: task.title, workflowId: task.workflowId, target: task.targetPath })
    return task
  }

  /** @param {any} task */
  async save(task) {
    return withFileMutex(this.taskFile(task.id), async () => {
      task.updatedAt = nowIso()
      await ensureDir(this.taskDir(task.id))
      await writeJsonAtomic(this.taskFile(task.id), task)
      return task
    })
  }

  /** @param {string} taskId */
  async get(taskId) {
    const file = this.taskFile(taskId)
    const task = await readJson(file, null)
    if (!task) throw new Error(`task not found: ${taskId} (workspace ${this.workspaceRoot})`)
    return task
  }

  /** @returns {Promise<any[]>} */
  async list(limit = 50) {
    let entries = []
    try {
      entries = await readdir(this.tasksDir, { withFileTypes: true })
    } catch {
      return []
    }
    const tasks = []
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const task = await readJson(join(this.tasksDir, entry.name, 'task.json'), null)
      if (task) tasks.push(task)
    }
    tasks.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)))
    return tasks.slice(0, limit)
  }

  /**
   * Move a task to another state, rejecting illegal transitions.
   * @param {any} task
   * @param {string} to
   * @param {string} [reason]
   */
  async transition(task, to, reason = '') {
    if (!TASK_STATES.includes(to)) throw new Error(`unknown task state: ${to}`)
    const allowed = TRANSITIONS[task.state] ?? []
    if (!allowed.includes(to)) {
      throw new Error(`illegal task transition ${task.state} →${to} for task ${task.id}`)
    }
    task.state = to
    task.stateHistory.push({ state: to, at: nowIso(), reason })
    if (TERMINAL_STATES.has(to)) task.completedAt = nowIso()
    await this.save(task)
    await this.audit?.append({ action: 'task.transition', taskId: task.id, to, reason })
    return task
  }

  /**
   * @param {any} task
   * @param {string} stepId
   * @param {Record<string, any>} patch
   */
  async updateStep(task, stepId, patch) {
    const step = task.steps.find((item) => item.id === stepId)
    if (!step) throw new Error(`step not found: ${stepId}`)
    Object.assign(step, patch)
    if (patch.status === 'DONE') task.stats.stepsDone += 1
    if (patch.status === 'FAILED') task.stats.stepsFailed += 1
    await this.save(task)
    return step
  }

  /** @param {any} task @param {string} note */
  async addNote(task, note) {
    task.notes.push({ at: nowIso(), note: String(note).slice(0, 4000) })
    await this.save(task)
    return task
  }

  /** @param {any} task @param {string} reason */
  async cancel(task, reason = 'cancelled by operator') {
    if (TERMINAL_STATES.has(task.state)) return task
    for (const step of task.steps) {
      if (step.status === 'RUNNING' || step.status === 'PENDING') step.status = 'CANCELLED'
    }
    return this.transition(task, 'CANCELLED', reason)
  }

  /**
   * Recompute evidence/finding counters from disk.
   * @param {any} task
   */
  async refreshStats(task) {
    const store = this.evidenceStore(task.id)
    const evidence = await store.readEvidence(10000)
    const { findings } = await store.readFindings()
    task.stats.evidence = evidence.length
    task.stats.findings = findings.length
    await this.save(task)
    return task
  }

  /**
   * Compact, model-facing summary of a task.
   * @param {any} task
   * @param {{includeSteps?: boolean}} [opts]
   */
  summary(task, opts = {}) {
    const summary = {
      id: task.id,
      title: task.title,
      state: task.state,
      workflow: task.workflowId,
      target: task.targetPath,
      workspace: task.workspace,
      riskMax: task.riskMax,
      currentStep: task.steps[task.currentStep]?.id ?? null,
      stats: task.stats,
      createdAt: task.createdAt,
      updatedAt: task.updatedAt,
      completedAt: task.completedAt,
      error: task.error,
      report: task.report,
      approvals: task.approvals,
    }
    if (opts.includeSteps) {
      summary.steps = task.steps.map((step) => ({
        id: step.id,
        capability: step.capabilityId,
        status: step.status,
        summary: step.summary,
        error: step.error,
        durationMs: step.durationMs,
      }))
    }
    return summary
  }

  /**
   * Stable fingerprint of task identity and plan (used in reports).
   * @param {any} task
   */
  fingerprint(task) {
    return sha256(`${task.id}|${task.createdAt}|${task.workflowId ?? ''}`)
  }
}

export default TaskStore
