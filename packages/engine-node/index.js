/**
 * @armorbreak/engine-node (P1 slice)
 *
 * The Engine is the only host-facing entry that resolves a trusted principal and
 * workspace before touching task state. A model-provided principal/operator is
 * never trusted: principals come from constructor configuration controlled by the
 * embedding host. Request ids are idempotent and replaying a different payload is
 * rejected rather than silently creating a second task.
 */
import { createHash } from 'node:crypto'
import { ArmorBreakRuntime } from '../../lib/core/runtime.js'
import { ApprovalAuthority } from '../../lib/control/approvalAuthority.js'
import { validateInvocation } from '../protocol/index.js'
import { createEvidenceEnvelope, createEventEnvelope, CORE_VERSION } from '../core/index.js'

const MAX_TITLE = 300
const MAX_OBJECTIVE = 5000
const MAX_TARGET = 4096
const MAX_IDEMPOTENCY = 10_000

function hash(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

export class EngineError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'EngineError'
    this.code = code
  }
}

export class TrustedEngine {
  /**
   * @param {{stateRoot: string, principals: Array<{id:string, kind:'local-user'|'service'|'verified-host', workspaces:string[]}>}} options
   */
  constructor(options) {
    if (!options?.stateRoot) throw new Error('stateRoot is required')
    if (!Array.isArray(options.principals) || options.principals.length === 0) throw new Error('at least one trusted principal is required')
    this.stateRoot = options.stateRoot
    this.principals = new Map()
    for (const principal of options.principals) {
      if (!principal?.id || !['local-user', 'service', 'verified-host'].includes(principal.kind)) throw new Error('invalid trusted principal')
      if (!Array.isArray(principal.workspaces) || principal.workspaces.length === 0) throw new Error(`principal ${principal.id} needs workspaces`)
      this.principals.set(principal.id, { ...principal, workspaces: new Set(principal.workspaces) })
    }
    this.idempotency = new Map()
    this.approvalAuthority = options.approvalAuthority ?? new ApprovalAuthority({ stateRoot: this.stateRoot })
    this.requestTimeoutMs = Number(options.requestTimeoutMs ?? 30_000)
    this.runtime = new ArmorBreakRuntime({ stateRoot: this.stateRoot })
  }

  async init() {
    await this.runtime.init()
    return this
  }

  async close() {
    await this.runtime.close?.()
  }

  bounded(ctx, operation) {
    const signal = ctx?.cancellation ?? ctx?.signal
    if (signal?.aborted) return Promise.reject(new EngineError('CANCELLED', 'request was cancelled before execution'))
    let timer
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new EngineError('TIMEOUT', `request exceeded ${this.requestTimeoutMs}ms`)), this.requestTimeoutMs)
      timer.unref?.()
    })
    let abortHandler
    const aborted = new Promise((_, reject) => {
      if (!signal) return
      abortHandler = () => reject(new EngineError('CANCELLED', 'request aborted'))
      signal.addEventListener('abort', abortHandler, { once: true })
    })
    const running = typeof operation === 'function' ? operation() : operation
    return Promise.race([running, timeout, aborted]).finally(() => {
      clearTimeout(timer)
      if (signal && abortHandler) signal.removeEventListener('abort', abortHandler)
    })
  }

  authenticate(ctx) {
    if (ctx?.cancellation?.aborted || ctx?.signal?.aborted) throw new EngineError('CANCELLED', 'request was cancelled')
    const validation = validateInvocation(ctx)
    if (!validation.ok) throw new EngineError('INVALID_REQUEST', validation.issues.join('; '))
    const configured = this.principals.get(ctx.principal.id)
    if (!configured || configured.kind !== ctx.principal.kind) throw new EngineError('POLICY_DENIED', 'unknown principal or kind mismatch')
    if (!configured.workspaces.has('*') && !configured.workspaces.has(ctx.workspaceId)) throw new EngineError('POLICY_DENIED', 'principal is not allowed to access this workspace')
    return configured
  }

  checkIdempotency(principal, ctx, payload) {
    const key = `${principal.id}:${ctx.workspaceId}:${ctx.requestId}`
    const digest = hash(payload)
    const existing = this.idempotency.get(key)
    if (existing) {
      if (existing.digest !== digest) throw new EngineError('INVALID_REQUEST', 'requestId reused with a different payload')
      return existing.promise
    }
    if (this.idempotency.size >= MAX_IDEMPOTENCY) throw new EngineError('ENGINE_UNAVAILABLE', 'idempotency cache is full')
    return null
  }

  /**
   * Create a task. It intentionally accepts only a trusted principal as operator;
   * an `operator` supplied in the payload must equal that principal or be absent.
   */
  async createTask(ctx, input = {}) {
    const principal = this.authenticate(ctx)
    if (input.operator !== undefined && input.operator !== principal.id) throw new EngineError('POLICY_DENIED', 'model-supplied operator cannot override the trusted principal')
    const title = String(input.title ?? '').trim()
    const objective = String(input.objective ?? '').trim()
    if (!title || title.length > MAX_TITLE) throw new EngineError('INVALID_REQUEST', `title must be 1..${MAX_TITLE} chars`)
    if (objective.length > MAX_OBJECTIVE) throw new EngineError('INVALID_REQUEST', `objective exceeds ${MAX_OBJECTIVE} chars`)
    if (input.targetPath !== undefined && String(input.targetPath).length > MAX_TARGET) throw new EngineError('INVALID_REQUEST', 'targetPath is too long')
    const payload = { title, objective, workflowId: input.workflowId ?? null, targetPath: input.targetPath ?? null, targetKind: input.targetKind ?? 'none', steps: input.steps ?? [] }
    const replay = this.checkIdempotency(principal, ctx, payload)
    if (replay) return replay
    const promise = this.runtime.workspace(ctx.workspaceId).taskStore.create({ ...payload, operator: principal.id })
    this.idempotency.set(`${principal.id}:${ctx.workspaceId}:${ctx.requestId}`, { digest: hash(payload), promise })
    return promise
  }

  /** Verify and consume a human/platform approval; model text is never an approval. */
  async verifyApproval(ctx, { riskLevel, taskId, target, approvalToken } = {}) {
    const principal = this.authenticate(ctx)
    if (!['L1', 'L2'].includes(riskLevel)) throw new EngineError('INVALID_REQUEST', 'approval is only valid for L1/L2')
    if (!approvalToken) throw new EngineError('APPROVAL_REQUIRED', 'an approval token is required')
    if (!taskId || !target) throw new EngineError('INVALID_REQUEST', 'taskId and target are required')
    const result = this.approvalAuthority.consume(String(approvalToken), { taskId: String(taskId), target: String(target), riskLevel, operator: principal.id, sessionId: ctx.principal.sessionId })
    if (!result.valid) throw new EngineError(result.code ?? 'POLICY_DENIED', result.reason ?? 'approval rejected')
    return { approvalId: result.payload.id, riskLevel, operator: principal.id, expiresAt: result.payload.expiresAt, taskId: String(taskId) }
  }

  /** Persist a sanitized event/evidence envelope into the existing evidence chain. */
  async recordEnvelope(ctx, taskId, { origin = 'sdk', targetHash, payload = {}, event } = {}) {
    return this.bounded(ctx, async () => {
      this.authenticate(ctx)
      const store = this.runtime.workspace(ctx.workspaceId).taskStore
      const task = await store.get(String(taskId))
      if (!task || task.workspace !== ctx.workspaceId) throw new EngineError('POLICY_DENIED', 'task is outside the authorized workspace')
      const envelope = event
        ? createEventEnvelope({ ctx, taskId: task.id, origin, targetHash, event, payload })
        : createEvidenceEnvelope({ ctx, taskId: task.id, origin, targetHash, payload })
      const record = await store.evidenceStore(task.id).addEvidence({ title: event ? `event:${event}`.slice(0, 200) : 'evidence-envelope', kind: 'event-envelope', excerpt: JSON.stringify(envelope), meta: { traceId: ctx.traceId, principalId: ctx.principal.id, origin, targetHash, payloadSha256: envelope.payloadSha256 }, targetSha256: targetHash })
      return { envelope, evidenceId: record.id }
    })
  }

  async getTask(ctx, taskId) {
    const principal = this.authenticate(ctx)
    let task
    try { task = await this.runtime.workspace(ctx.workspaceId).taskStore.get(String(taskId)) } catch { throw new EngineError('POLICY_DENIED', 'task is outside the authorized workspace') }
    if (!task || task.workspace !== ctx.workspaceId) throw new EngineError('POLICY_DENIED', 'task is outside the authorized workspace')
    return task
  }

  async listTasks(ctx) {
    this.authenticate(ctx)
    return this.runtime.workspace(ctx.workspaceId).taskStore.list(20)
  }

  async cancelTask(ctx, taskId, reason = 'cancelled by trusted principal') {
    const principal = this.authenticate(ctx)
    const store = this.runtime.workspace(ctx.workspaceId).taskStore
    let task
    try { task = await store.get(String(taskId)) } catch { throw new EngineError('POLICY_DENIED', 'task is outside the authorized workspace') }
    if (!task || task.workspace !== ctx.workspaceId) throw new EngineError('POLICY_DENIED', 'task is outside the authorized workspace')
    await store.cancel(task, reason.slice(0, 300))
    return { taskId: task.id, state: 'CANCELLED', principalId: principal.id, traceId: ctx.traceId }
  }

  async capabilities(ctx) {
    this.authenticate(ctx)
    return this.runtime.registry.list()
  }

  async health(ctx) {
    this.authenticate(ctx)
    return this.runtime.stateSummary(ctx.workspaceId)
  }
}

export async function createEngine(options) {
  return new TrustedEngine(options).init()
}

export { CORE_VERSION }

