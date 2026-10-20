/**
 * In-process background task queue for ArmorBreak workflows.
 *
 * The queue owns execution leases in this process; a task only counts as running
 * while its entry is in this map. On restart the queue is empty, so the task store
 * marks previous EXECUTING/COLLECTING_EVIDENCE tasks as INTERRUPTED/RECOVERABLE
 * instead of trusting stale RUNNING steps. Concurrency is bounded per process
 * (L0 analysis can run a couple of tasks; heavy L1 work should be serialized by
 * the operator). Cancellation aborts the runner signal and waits for the task to
 * settle before reporting success.
 * @module dsh-armorbreak/lib/core/taskQueue
 */
import { nowIso } from './util.js'

const TERMINAL = new Set(['COMPLETED', 'REJECTED', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'PARTIAL_SUCCESS'])

/** @param {number} ms */
function delay(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms))
}

export class TaskQueue {
  /**
   * @param {{runtime: any, concurrency?: number, leaseMs?: number}} options
   */
  constructor(options) {
    this.runtime = options.runtime
    this.concurrency = Math.max(1, Math.min(Number(options.concurrency ?? 2), 8))
    this.leaseMs = Math.max(10_000, Number(options.leaseMs ?? 60_000))
    /** @type {Map<string, any>} */
    this.entries = new Map()
    this.active = 0
    /** @type {Array<() => void>} */
    this.waiters = []
    this.sequence = 0
  }

  /** @param {string} taskId */
  isLive(taskId) {
    const entry = this.entries.get(taskId)
    return Boolean(entry && !entry.settled)
  }

  /** @returns {any[]} */
  snapshot() {
    return [...this.entries.values()]
      .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
      .map((entry) => this.entrySummary(entry))
  }

  /** @param {string} taskId */
  status(taskId) {
    const entry = this.entries.get(taskId)
    return entry ? this.entrySummary(entry) : null
  }

  /** @param {any} entry */
  entrySummary(entry) {
    return {
      taskId: entry.taskId,
      workspace: entry.workspace,
      state: entry.state,
      queued: entry.state === 'WAITING',
      startedAt: entry.startedAt,
      finishedAt: entry.finishedAt,
      error: entry.error,
      attempts: entry.attempts,
      lease: entry.lease,
    }
  }

  /** @param {any} entry */
  async acquire(entry) {
    if (this.active < this.concurrency) {
      this.active += 1
      return
    }
    entry.state = 'WAITING'
    await new Promise((resolvePromise) => this.waiters.push(resolvePromise))
    this.active += 1
  }

  release() {
    this.active = Math.max(0, this.active - 1)
    const next = this.waiters.shift()
    if (next) next()
  }

  /**
   * Start a prepared task in the background.
   * @param {any} task
   * @param {{requestApproval?: Function, maxSteps?: number, concurrency?: number}} [opts]
   */
  async start(task, opts = {}) {
    if (!task || !task.id) throw new Error('task queue start needs a task')
    if (TERMINAL.has(task.state)) throw new Error(`task ${task.id} is already terminal (${task.state})`)
    const existing = this.entries.get(task.id)
    if (existing && !existing.settled) throw new Error(`task ${task.id} is already queued/running`)
    const controller = new AbortController()
    if (opts.signal) {
      if (opts.signal.aborted) controller.abort()
      else opts.signal.addEventListener('abort', () => controller.abort(), { once: true })
    }
    const entry = {
      taskId: task.id,
      workspace: task.workspace,
      state: 'WAITING',
      createdAt: nowIso(),
      startedAt: null,
      finishedAt: null,
      error: null,
      attempts: 1,
      settled: false,
      controller,
      lease: { owner: `queue-${process.pid}-${(this.sequence += 1)}`, heartbeatAt: nowIso() },
      promise: null,
    }
    this.entries.set(task.id, entry)
    entry.promise = this.#run(entry, task, opts)
    return this.entrySummary(entry)
  }

  /** @param {any} entry @param {any} task @param {any} opts */
  async #run(entry, task, opts) {
    await this.acquire(entry)
    entry.state = 'RUNNING'
    entry.startedAt = nowIso()
    entry.lease.heartbeatAt = nowIso()
    const heartbeat = setInterval(() => {
      entry.lease.heartbeatAt = nowIso()
    }, Math.max(5_000, Math.floor(this.leaseMs / 3)))
    // A tiny yield ensures start() returns before the first capability runs, so
    // callers always receive a WAITING/RUNNING handle rather than a finished task.
    await delay(0)
    try {
      const updated = await this.runtime.runner.runWorkflow(task, {
        requestApproval: opts.requestApproval,
        maxSteps: opts.maxSteps ?? 50,
        generateReport: true,
        signal: entry.controller.signal,
        concurrency: opts.concurrency ?? 1,
      })
      entry.state = updated.state
      entry.finishedAt = nowIso()
      return updated
    } catch (error) {
      entry.error = String(/** @type {any} */ (error)?.message ?? error).slice(0, 1200)
      try {
        const store = this.runtime.workspace(task.workspace).taskStore
        const latest = await store.get(task.id).catch(() => task)
        if (!TERMINAL.has(latest.state)) await store.cancel(latest, `background execution failed: ${entry.error}`)
        entry.state = latest.state
      } catch {
        entry.state = 'FAILED'
      }
      entry.finishedAt = nowIso()
      throw error
    } finally {
      clearInterval(heartbeat)
      entry.settled = true
      this.release()
    }
  }

  /**
   * Cancel a queued/running task. Returns after the runner settles (bounded wait).
   * @param {string} taskId
   * @param {{reason?: string}} [options]
   */
  async cancel(taskId, options = {}) {
    const entry = this.entries.get(taskId)
    if (!entry || entry.settled) {
      const task = await this.runtime.workspace(this.runtime.lastWorkspace ?? this.runtime.defaultWorkspace()).taskStore.get(taskId).catch(() => null)
      if (task && !TERMINAL.has(task.state)) {
        const store = this.runtime.workspace(task.workspace).taskStore
        await store.cancel(task, options.reason ?? 'cancelled via task queue')
      }
      return { taskId, cancelled: Boolean(task), taskState: task?.state ?? null, queueState: null }
    }
    entry.controller.abort()
    await Promise.race([
      entry.promise.catch(() => {}),
      delay(10_000),
    ])
    const store = this.runtime.workspace(entry.workspace).taskStore
    const task = await store.get(taskId).catch(() => null)
    if (task && !TERMINAL.has(task.state)) await store.cancel(task, options.reason ?? 'cancelled via task queue')
    entry.state = 'CANCELLED'
    entry.settled = true
    entry.finishedAt = nowIso()
    return { taskId, cancelled: true, taskState: task?.state ?? null, queueState: 'CANCELLED' }
  }

  /**
   * Wait for a background task to settle (bounded).
   * @param {string} taskId
   * @param {number} [timeoutMs]
   */
  async wait(taskId, timeoutMs = 120_000) {
    const entry = this.entries.get(taskId)
    if (!entry) return null
    const limit = Math.max(1000, Math.min(timeoutMs, 600_000))
    await new Promise((resolvePromise) => {
      const timer = setTimeout(resolvePromise, limit)
      entry.promise.catch(() => {}).finally(() => {
        clearTimeout(timer)
        resolvePromise()
      })
    })
    return this.entrySummary(entry)
  }

  /**
   * Recover stale tasks in a workspace. Call before starting background work.
   * @param {string} workspaceRoot
   */
  async recover(workspaceRoot) {
    const store = this.runtime.workspace(workspaceRoot).taskStore
    return store.recoverInterrupted({ isLive: (task) => this.isLive(task.id) })
  }

  /**
   * Resume an INTERRUPTED/RECOVERABLE task from its pending steps.
   * @param {any} task
   * @param {any} [opts]
   */
  async resume(task, opts = {}) {
    const store = this.runtime.workspace(task.workspace).taskStore
    if (!['RECOVERABLE', 'INTERRUPTED', 'PAUSED'].includes(task.state)) {
      throw new Error(`task ${task.id} is not resumable (${task.state}); expected RECOVERABLE/INTERRUPTED/PAUSED`)
    }
    await store.transition(task, 'EXECUTING', 'resumed from interrupted state')
    return this.start(task, opts)
  }
}

export default TaskQueue
