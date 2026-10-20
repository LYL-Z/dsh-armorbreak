/**
 * Execution runner: the single choke point between a model request and any
 * analyzer capability. It enforces scope policy, platform approval, isolation,
 * timeouts, input caps, evidence collection, and audit logging.
 * @module dsh-armorbreak/lib/core/runner
 */
import { readdir, stat } from 'node:fs/promises'
import { realpathSync } from 'node:fs'
import { join } from 'node:path'
import { isPathInside, looksTextual, nowIso, readBounded, redactDeep, sanitizeText, sha256, textOf } from './util.js'
import { getWorkflow } from './workflows.js'

/** Resolve a path to its real filesystem target when it exists (symlink/junction safe). */
function realpathOf(target) {
  try {
    return realpathSync.native(target)
  } catch {
    try {
      return realpathSync(target)
    } catch {
      return target
    }
  }
}

/** Denied by policy — never converted into a successful result. */
export class PolicyDeniedError extends Error {
  /** @param {string} code @param {string} message */
  constructor(code, message) {
    super(message)
    this.name = 'PolicyDeniedError'
    this.code = code
  }
}

/** Execution failed in a way the caller can act on. */
export class ExecutionError extends Error {
  /** @param {string} code @param {string} message @param {{detail?: unknown}} [opts] */
  constructor(code, message, opts = {}) {
    super(message)
    this.name = 'ExecutionError'
    this.code = code
    this.detail = opts.detail ?? null
  }
}

const TERMINAL = new Set(['COMPLETED', 'REJECTED', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'PARTIAL_SUCCESS'])
const SKIP_DIRS = new Set(['.git', 'node_modules', '.armorbreak', 'dist', 'build', 'out', '.venv', 'venv', '__pycache__', '.next', '.cache', 'target'])

/**
 * Truncate deeply nested result values until their JSON fits the byte budget.
 * @param {unknown} value
 * @param {number} budget
 */
export function truncateDeep(value, budget = 256 * 1024) {
  try {
    if (JSON.stringify(value).length <= budget) return value
  } catch {
    return { error: 'result not serializable' }
  }
  /** @param {unknown} inner @param {number} depth @returns {unknown} */
  const walk = (inner, depth) => {
    if (depth > 6) return '[depth-limit]'
    if (typeof inner === 'string') return inner.length > 2000 ? `${inner.slice(0, 2000)}…[truncated]` : inner
    if (Array.isArray(inner)) return inner.slice(0, 50).map((item) => walk(item, depth + 1))
    if (inner && typeof inner === 'object') {
      /** @type {Record<string, unknown>} */
      const out = {}
      let count = 0
      for (const [key, child] of Object.entries(inner)) {
        if (count >= 60) {
          out._truncatedKeys = Object.keys(inner).length - count
          break
        }
        out[key] = walk(child, depth + 1)
        count += 1
      }
      return out
    }
    return inner
  }
  return { truncated: true, note: `result exceeded ${budget} bytes and was truncated`, data: walk(value, 0) }
}

/**
 * @param {Promise<any>} promise
 * @param {number} timeoutMs
 * @param {() => void} onTimeout
 * @returns {Promise<any>}
 */
function withTimeout(promise, timeoutMs, onTimeout) {
  let timer
  const timeout = new Promise((_resolve, reject) => {
    timer = setTimeout(() => {
      onTimeout()
      reject(new ExecutionError('TIMEOUT', `capability exceeded its ${timeoutMs} ms budget and was cancelled`, {}))
    }, timeoutMs)
    if (typeof timer.unref === 'function') timer.unref()
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

export class ExecutionRunner {
  /**
   * @param {import('./runtime.js').ArmorBreakRuntime} runtime
   */
  constructor(runtime) {
    this.runtime = runtime
  }

  /** @param {string} workspaceRoot */
  context(workspaceRoot) {
    return this.runtime.workspace(workspaceRoot)
  }

  /**
   * Compute the highest risk level across a list of capability ids.
   * @param {string[]} capabilityIds
   */
  riskMaxOf(capabilityIds) {
    const order = ['L0', 'L1', 'L2', 'L3']
    let max = 'L0'
    for (const id of capabilityIds) {
      const capability = this.runtime.registry.get(id)
      if (!capability) continue
      if (order.indexOf(capability.riskLevel) > order.indexOf(max)) max = capability.riskLevel
    }
    return max
  }

  /**
   * Advance CREATED → EXECUTING, validating scope and environment and collecting
   * the approval a non-L0 task needs before any step may run.
   * @param {any} task
   * @param {{requestApproval?: Function, approvalTarget?: string|null, signal?: AbortSignal}} [opts]
   */
  async prepareTask(task, opts = {}) {
    const ctx = this.context(task.workspace)
    const store = ctx.taskStore
    const scope = ctx.scope
    const audit = ctx.audit
    if (TERMINAL.has(task.state)) throw new ExecutionError('TASK_TERMINAL', `task ${task.id} is ${task.state} and cannot run`)
    if (task.state === 'EXECUTING' || task.state === 'COLLECTING_EVIDENCE') return task
    if (task.state === 'CREATED') await store.transition(task, 'SCOPE_VALIDATION', 'validating authorization scope')
    if (task.state === 'SCOPE_VALIDATION') {
      if (task.targetKind === 'file' || task.targetKind === 'directory' || !task.targetKind) {
        if (!task.targetPath) throw new ExecutionError('TARGET_REQUIRED', 'this task has no target path; pass targetPath when creating it')
        const check = await scope.checkFile({ taskId: task.id, targetPath: task.targetPath, workspaceRoot: task.workspace })
        if (!check.allowed) {
          await store.transition(task, 'REJECTED', check.reason)
          await audit.append({ action: 'policy.denied', taskId: task.id, code: check.code, reason: check.reason, target: task.targetPath })
          throw new PolicyDeniedError(check.code, check.reason)
        }
        task.targetPath = check.resolved
      }
      await store.transition(task, 'ENVIRONMENT_CHECK', 'scope validated')
    }
    if (task.state === 'ENVIRONMENT_CHECK') {
      await this.runtime.registry.load()
      const missing = task.steps.filter((step) => !this.runtime.registry.get(step.capabilityId)).map((step) => step.capabilityId)
      if (missing.length > 0) {
        const reason = `capabilities unavailable: ${missing.join(', ')}. Run armorbreak_capabilities to list valid ids.`
        await store.transition(task, 'FAILED', reason)
        throw new ExecutionError('CAPABILITY_MISSING', reason)
      }
      // Target-kind compatibility: fail at planning, before any step executes.
      const taskKind = task.targetKind === 'file' || task.targetKind === 'directory' ? task.targetKind : null
      if (taskKind) {
        const mismatched = []
        for (const step of task.steps) {
          const stepCapability = this.runtime.registry.get(step.capabilityId)
          const declared = stepCapability?.targetKind ?? 'file'
          if (declared !== taskKind) mismatched.push(`${step.id} (${step.capabilityId}) declares ${declared}`)
        }
        if (mismatched.length > 0) {
          const supported = this.runtime.registry.list().filter((item) => item.targetKind === taskKind).map((item) => item.id)
          const hint = supported.length > 0
            ? `capabilities that accept a ${taskKind} target: ${supported.join(', ')}`
            : `no registered capability declares targetKind="${taskKind}"`
          const reason = `target kind mismatch: task target is a ${taskKind}, but steps expect another kind: ${mismatched.join('; ')}. ${hint}. Choose a matching workflow/capability or fix the capability manifest to declare targetKind.`
          await store.transition(task, 'FAILED', reason)
          throw new ExecutionError('TARGET_KIND_MISMATCH', reason)
        }
      }
      task.riskMax = this.riskMaxOf(task.steps.map((step) => step.capabilityId))
      await store.transition(task, 'PLANNING', `environment checked; riskMax=${task.riskMax}`)
    }
    if (task.state === 'PLANNING') {
      if (task.riskMax === 'L3') {
        const reason = 'task requires an L3 capability (destructive/exfiltration/persistence); L3 operations are always denied'
        await store.transition(task, 'REJECTED', reason)
        throw new PolicyDeniedError('L3_DENIED', reason)
      }
      if (task.riskMax === 'L1' || task.riskMax === 'L2') {
        await store.transition(task, 'APPROVAL_REQUIRED', `${task.riskMax} capability requires platform approval`)
        const target = opts.approvalTarget ?? task.targetPath ?? '(target declared per step)'
        const grant = await this.requestApprovalGate({
          task,
          riskLevel: task.riskMax,
          target,
          requestApproval: opts.requestApproval,
          signal: opts.signal,
          reason: `ArmorBreak ${task.riskMax} operation requested for task "${task.title}"`,
        })
        if (!grant.allowed) {
          await store.transition(task, 'REJECTED', grant.reason)
          throw new PolicyDeniedError('APPROVAL_REJECTED', grant.reason)
        }
        await store.transition(task, 'EXECUTING', `approval ${grant.approvalId} granted`)
      } else {
        await store.transition(task, 'EXECUTING', 'planned; offline L0 analysis')
      }
    }
    return task
  }

  /**
   * Ask the platform approval service through the caller-provided closure and
   * record the grant. Fail closed when no channel exists.
   * @param {{task: any, riskLevel: string, target: string, requestApproval?: Function, signal?: AbortSignal, reason: string}} input
   */
  async requestApprovalGate(input) {
    if (typeof input.requestApproval !== 'function') {
      return { allowed: false, reason: 'no approval channel is available in this composition; L1/L2 operations fail closed. Use offline analysis or ask the operator to enable approvals.' }
    }
    let outcome
    try {
      outcome = await input.requestApproval({
        riskLevel: input.riskLevel,
        target: input.target,
        reason: input.reason,
        signal: input.signal,
      })
    } catch (error) {
      return { allowed: false, reason: `approval request failed: ${String(/** @type {any} */ (error)?.message ?? error)}` }
    }
    if (outcome !== 'allowed-once') {
      return { allowed: false, reason: `platform approval outcome was "${outcome}" (only allowed-once grants). Nothing executed.` }
    }
    const ctx = this.context(input.task.workspace)
    const record = await ctx.scope.recordApproval({
      kind: input.riskLevel,
      taskId: input.task.id,
      target: String(input.target),
      source: 'platform',
      outcome,
    })
    if (!input.task.approvals.includes(record.id)) input.task.approvals.push(record.id)
    await ctx.taskStore.save(input.task)
    await ctx.audit.append({ action: 'approval.granted', taskId: input.task.id, riskLevel: input.riskLevel, approvalId: record.id, target: String(input.target) })
    return { allowed: true, approvalId: record.id, reason: 'platform approval granted' }
  }

  /**
   * Reuse an active, matching approval for this task, else request one.
   * @param {{task: any, riskLevel: string, target: string, requestApproval?: Function, signal?: AbortSignal}} input
   */
  async ensureApproval(input) {
    const ctx = this.context(input.task.workspace)
    const approvals = await ctx.scope.listApprovals()
    const match = approvals.find((approval) => approval.active && approval.taskId === input.task.id && approval.riskLevel === input.riskLevel && approval.target === input.target)
    if (match) return { allowed: true, approvalId: match.id, reason: 'reused active approval' }
    return this.requestApprovalGate({ ...input, reason: `ArmorBreak ${input.riskLevel} operation on "${input.target}" (task ${input.task.id})` })
  }

  /**
   * Build the input object handed to one capability and its bounded environment helpers.
   * @param {{task: any, capability: any, targetPath: string|null, options: Record<string, any>, controller: AbortController, log: string[]}} input
   */
  async buildCapabilityInput(input) {
    const { task, capability, controller } = input
    const ctx = this.context(task.workspace)
    const limits = { ...this.runtime.limits }
    const targetKind = capability.targetKind ?? 'file'
    const log = (/** @type {string} */ message) => {
      if (input.log.length < 200) input.log.push(sanitizeText(message, 500))
    }
    const env = {
      signal: controller.signal,
      workspaceRoot: task.workspace,
      nowIso: nowIso(),
      log,
      listFiles: null,
      readFile: null,
      // Set only for allowed L2 calls: the resolved addresses captured at policy
      // time, so the capability can pin its connection instead of re-resolving.
      networkPolicy: input.networkPolicy ?? null,
    }
    let buffer = null
    let text = null
    let targetPath = input.targetPath ? task.targetPath && input.targetPath === task.targetPath ? task.targetPath : input.targetPath : null
    if (targetKind === 'file') {
      if (!input.targetPath) throw new ExecutionError('TARGET_REQUIRED', `capability ${capability.id} needs a file target; pass target (absolute path)`)
      const info = await stat(input.targetPath).catch(() => null)
      if (!info) throw new ExecutionError('TARGET_NOT_FOUND', `target file not found: ${input.targetPath}`)
      if (info.isDirectory()) {
        const directoryCapabilities = this.runtime.registry.list().filter((item) => item.targetKind === 'directory').map((item) => item.id)
        const hint = directoryCapabilities.length > 0
          ? `directory-capable capabilities: ${directoryCapabilities.join(', ')}`
          : 'no registered capability declares directory support'
        throw new ExecutionError('TARGET_NOT_FILE', `capability ${capability.id} only accepts a file target but received a directory: ${input.targetPath}. ${hint}; or run a directory workflow (WebCodeSecurityReview / DependencyAudit) instead.`)
      }
      const read = await readBounded(input.targetPath, limits.maxInputBytes)
      buffer = read.buffer
      text = looksTextual(read.buffer) ? textOf(read.buffer) : null
      if (read.truncated) log(`input truncated to ${limits.maxInputBytes} bytes (file is ${read.size} bytes)`)
      env.targetTruncated = read.truncated
      env.targetSize = read.size
    } else if (targetKind === 'directory') {
      if (!input.targetPath) throw new ExecutionError('TARGET_REQUIRED', `capability ${capability.id} needs a directory target`)
      const info = await stat(input.targetPath).catch(() => null)
      if (!info || !info.isDirectory()) throw new ExecutionError('TARGET_NOT_DIRECTORY', `capability ${capability.id} expects a directory target: ${input.targetPath}`)
      targetPath = input.targetPath
      const root = input.targetPath
      const realRoot = realpathOf(root)
      env.listFiles = async (/** @type {string} */ start, opts = {}) => {
        const requested = start ? start : root
        const resolvedStart = realpathOf(requested)
        if (!isPathInside(root, requested) || !isPathInside(realRoot, resolvedStart)) {
          throw new ExecutionError('PATH_ESCAPE', `listFiles start path escapes the target directory: ${requested}`)
        }
        const maxFiles = Math.min(Number(opts.maxFiles ?? 2000), 5000)
        const maxDepth = Math.min(Number(opts.maxDepth ?? 5), 8)
        const files = []
        /** @param {string} dir @param {number} depth */
        const walk = async (dir, depth) => {
          if (files.length >= maxFiles || controller.signal.aborted) return
          const entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
          for (const entry of entries) {
            if (files.length >= maxFiles || controller.signal.aborted) return
            if (entry.name.startsWith('.') && entry.name !== '.env') continue
            if (SKIP_DIRS.has(entry.name)) continue
            const full = join(dir, entry.name)
            // Dirent.isFile() is false for symlinks, so links are never enumerated.
            if (entry.isDirectory()) {
              if (depth < maxDepth) await walk(full, depth + 1)
            } else if (entry.isFile()) {
              files.push(full)
            }
          }
        }
        await walk(resolvedStart, 0)
        return files
      }
      env.readFile = async (/** @type {string} */ absPath, /** @type {number} */ maxBytes = 512 * 1024) => {
        const resolved = realpathOf(absPath)
        // Both the lexical path and its real target must stay inside the analyzed root:
        // a symlink/junction planted below the root can never redirect a read outside it.
        if (!isPathInside(root, absPath) || !isPathInside(realRoot, resolved)) {
          throw new ExecutionError('PATH_ESCAPE', `readFile target escapes the analyzed directory (resolved to ${resolved}): ${absPath}`)
        }
        if (controller.signal.aborted) throw new ExecutionError('CANCELLED', 'execution cancelled')
        const read = await readBounded(resolved, Math.min(maxBytes, limits.maxFileReadBytes))
        // Contract (docs/CONTRACT.md): env.readFile resolves to a Buffer.
        if (read.truncated) env.targetTruncated = true
        return read.buffer
      }
    }
    return {
      targetPath,
      buffer,
      text,
      options: input.options ?? {},
      limits,
      env,
    }
  }

  /**
   * Resolve the network target string for an L2 capability.
   * @param {any} capability
   * @param {Record<string, any>} options
   */
  networkTargetOf(capability, options) {
    if (typeof capability.networkTarget === 'function') return String(capability.networkTarget(options))
    return String(options.url ?? options.target ?? options.host ?? '')
  }

  /**
   * Run one capability through policy, input caps, evidence collection, and audit.
   * @param {{
   *   task: any,
   *   capabilityId: string,
   *   targetPath?: string|null,
   *   options?: Record<string, any>,
   *   stepId?: string|null,
   *   requestApproval?: Function,
   *   signal?: AbortSignal,
   * }} request
   */
  async runCapability(request) {
    const ctx = this.context(request.task.workspace)
    const { task } = request
    const audit = ctx.audit
    const scope = ctx.scope
    const store = ctx.taskStore
    await this.runtime.registry.load()
    const capability = this.runtime.registry.get(request.capabilityId)
    if (!capability) {
      throw new ExecutionError('CAPABILITY_UNKNOWN', `unknown capability "${request.capabilityId}"; run armorbreak_capabilities for the list`)
    }
    if (TERMINAL.has(task.state)) throw new ExecutionError('TASK_TERMINAL', `task ${task.id} is ${task.state}`)
    if (!['EXECUTING', 'COLLECTING_EVIDENCE'].includes(task.state)) {
      await this.prepareTask(task, {
        requestApproval: request.requestApproval,
        approvalTarget: request.targetPath ?? this.networkTargetOf(capability, request.options ?? {}),
        signal: request.signal,
      })
    }
    if (task.state === 'COLLECTING_EVIDENCE') await store.transition(task, 'EXECUTING', 'next capability')
    const options = request.options ?? {}
    const targetPath = request.targetPath ?? task.targetPath ?? null
    const targetKind = capability.targetKind ?? 'file'
    let policyResult = { allowed: true, code: 'L0_OK', reason: 'offline analysis' }
    if (capability.riskLevel === 'L3') {
      policyResult = { allowed: false, code: 'L3_DENIED', reason: 'L3 operations are always denied and have no automatic execution channel' }
    } else if (capability.riskLevel === 'L0') {
      if (targetKind === 'file' || targetKind === 'directory') {
        if (!targetPath) {
          policyResult = { allowed: false, code: 'TARGET_REQUIRED', reason: `capability ${capability.id} needs a ${targetKind} target` }
        } else {
          policyResult = await scope.checkFile({ taskId: task.id, targetPath, workspaceRoot: task.workspace })
        }
      }
    } else if (capability.riskLevel === 'L2') {
      const networkTarget = this.networkTargetOf(capability, options)
      if (!networkTarget) {
        policyResult = { allowed: false, code: 'TARGET_REQUIRED', reason: `capability ${capability.id} is L2 and needs a network target (url/host option)` }
      } else {
        const gate = await this.ensureApproval({ task, riskLevel: 'L2', target: networkTarget, requestApproval: request.requestApproval, signal: request.signal })
        if (!gate.allowed) {
          policyResult = { allowed: false, code: 'NETWORK_APPROVAL_REQUIRED', reason: gate.reason }
        } else {
          const check = await scope.checkNetwork({ taskId: task.id, target: networkTarget, approvalId: gate.approvalId })
          if (check.allowed) await scope.consumeApproval(gate.approvalId)
          policyResult = check
        }
      }
    } else if (capability.riskLevel === 'L1') {
      const isolation = await this.runtime.health.isolation()
      if (!isolation.available) {
        policyResult = { allowed: false, code: 'ISOLATION_UNAVAILABLE', reason: isolation.reason }
      } else {
        const gate = await this.ensureApproval({ task, riskLevel: 'L1', target: targetPath ?? '(no sample)', requestApproval: request.requestApproval, signal: request.signal })
        if (!gate.allowed) {
          policyResult = { allowed: false, code: 'EXECUTION_APPROVAL_REQUIRED', reason: gate.reason }
        } else {
          policyResult = await scope.checkExecution({
            taskId: task.id,
            targetPath: targetPath ?? '',
            workspaceRoot: task.workspace,
            isolationAvailable: isolation.available,
            approvalId: gate.approvalId,
          })
        }
      }
    }
    if (!policyResult.allowed) {
      await audit.append({ action: 'policy.denied', taskId: task.id, capability: capability.id, code: policyResult.code, reason: policyResult.reason, target: targetPath })
      if (request.stepId) {
        await store.updateStep(task, request.stepId, { status: 'FAILED', error: `${policyResult.code}: ${policyResult.reason}`, finishedAt: nowIso() })
      }
      throw new PolicyDeniedError(policyResult.code, policyResult.reason)
    }

    const controller = new AbortController()
    const onAbort = () => controller.abort()
    if (request.signal) {
      if (request.signal.aborted) controller.abort()
      else request.signal.addEventListener('abort', onAbort, { once: true })
    }
    const startedAt = Date.now()
    const log = []
    let targetSha = null
    await audit.append({
      action: 'capability.run.start',
      taskId: task.id,
      stepId: request.stepId ?? null,
      capability: capability.id,
      riskLevel: capability.riskLevel,
      policy: policyResult.code,
      target: targetPath,
      options: redactDeep(options),
    })
    try {
      const input = await this.buildCapabilityInput({
        task,
        capability,
        targetPath,
        options,
        controller,
        log,
        networkPolicy: policyResult.allowed && capability.riskLevel === 'L2'
          ? { resolvedIps: policyResult.resolvedIps ?? [], code: policyResult.code }
          : null,
      })
      if (input.buffer) targetSha = sha256(input.buffer)
      const timeoutMs = Math.min(Number(options.timeoutMs ?? this.runtime.limits.timeoutMs), 5 * 60 * 1000)
      const raw = await withTimeout(Promise.resolve().then(() => capability.run(input)), timeoutMs, () => controller.abort())
      // A body that observes cancellation and settles normally is still a cancelled call.
      if (controller.signal.aborted || request.signal?.aborted) {
        throw new ExecutionError('CANCELLED', `capability ${capability.id} was cancelled before its result was recorded`)
      }
      const result = await this.recordResult({ task, capability, raw, targetPath, targetSha, log, durationMs: Date.now() - startedAt, stepId: request.stepId ?? null })
      await audit.append({
        action: 'capability.run.end',
        taskId: task.id,
        capability: capability.id,
        status: 'ok',
        durationMs: Date.now() - startedAt,
        evidence: result.evidenceIds.length,
        findings: result.findings.length,
        targetSha256: targetSha,
      })
      return result
    } catch (error) {
      const durationMs = Date.now() - startedAt
      const message = error instanceof PolicyDeniedError
        ? `${error.code}: ${error.message}`
        : error instanceof ExecutionError
          ? `${error.code}: ${error.message}`
          : String(/** @type {any} */ (error)?.message ?? error)
      await audit.append({ action: 'capability.run.end', taskId: task.id, capability: capability.id, status: 'error', durationMs, error: message, targetSha256: targetSha })
      if (request.stepId) {
        await store.updateStep(task, request.stepId, { status: 'FAILED', error: message, finishedAt: nowIso(), durationMs })
      }
      if (error instanceof PolicyDeniedError || error instanceof ExecutionError) throw error
      throw new ExecutionError('CAPABILITY_FAILED', `capability ${capability.id} failed: ${message}`, { detail: { capability: capability.id } })
    } finally {
      request.signal?.removeEventListener('abort', onAbort)
    }
  }

  /**
   * Persist artifacts/evidence/findings and normalize the model-facing result.
   * @param {{task: any, capability: any, raw: any, targetPath: string|null, targetSha: string|null, log: string[], durationMs: number, stepId: string|null}} input
   */
  async recordResult(input) {
    const ctx = this.context(input.task.workspace)
    const store = ctx.taskStore
    const evidenceStore = store.evidenceStore(input.task.id)
    const raw = input.raw && typeof input.raw === 'object' ? input.raw : {}
    const summary = sanitizeText(String(raw.summary ?? '(capability returned no summary)'), 4000)
    const data = truncateDeep(raw.data ?? {}, this.runtime.limits.maxResultBytes)
    const rawEvidence = Array.isArray(raw.evidence) ? raw.evidence.slice(0, this.runtime.limits.maxItems) : []
    const rawFindings = Array.isArray(raw.findings) ? raw.findings.slice(0, this.runtime.limits.maxFindings) : []
    const artifacts = Array.isArray(raw.artifacts) ? raw.artifacts.slice(0, 20) : []

    /** @type {string[]} */
    const evidenceIds = []
    const executionEvidence = await evidenceStore.addEvidence({
      title: `${input.capability.id} execution`,
      kind: 'execution',
      excerpt: summary,
      capabilityId: input.capability.id,
      targetPath: input.targetPath,
      targetSha256: input.targetSha,
      meta: { durationMs: input.durationMs, riskLevel: input.capability.riskLevel, log: input.log.slice(0, 40), meta: redactDeep(raw.meta ?? {}) },
    })
    evidenceIds.push(executionEvidence.id)
    for (const item of rawEvidence) {
      if (!item || typeof item !== 'object') continue
      const record = await evidenceStore.addEvidence({
        title: item.title ?? 'evidence',
        kind: item.kind ?? 'observation',
        excerpt: item.excerpt ?? '',
        meta: redactDeep(item.meta ?? {}),
        capabilityId: input.capability.id,
        targetPath: input.targetPath,
        targetSha256: input.targetSha,
      })
      evidenceIds.push(record.id)
    }
    /** @type {Array<{id: string, title: string, severity: string, verification: string}>} */
    const findings = []
    for (const finding of rawFindings) {
      if (!finding || typeof finding !== 'object') continue
      const findingEvidenceIds = []
      for (const item of Array.isArray(finding.evidence) ? finding.evidence.slice(0, 10) : []) {
        const record = await evidenceStore.addEvidence({
          title: item.title ?? `evidence for: ${finding.title ?? 'finding'}`,
          kind: 'finding-evidence',
          excerpt: item.excerpt ?? '',
          meta: redactDeep(item.meta ?? {}),
          capabilityId: input.capability.id,
          targetPath: input.targetPath,
          targetSha256: input.targetSha,
        })
        findingEvidenceIds.push(record.id)
      }
      const saved = await evidenceStore.addFinding(finding, {
        evidenceIds: [...findingEvidenceIds, executionEvidence.id],
        capabilityId: input.capability.id,
        targetPath: input.targetPath,
      })
      findings.push({ id: saved.finding.id, title: saved.finding.title, severity: saved.finding.severity, verification: saved.finding.verification })
    }
    /** @type {any[]} */
    const artifactPaths = []
    for (const artifact of artifacts) {
      if (!artifact || typeof artifact.name !== 'string' || typeof artifact.content !== 'string') continue
      const safeName = artifact.name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120)
      if (!safeName) continue
      const { writeFile, mkdir } = await import('node:fs/promises')
      const dir = join(store.taskDir(input.task.id), 'artifacts')
      await mkdir(dir, { recursive: true })
      const file = join(dir, safeName)
      await writeFile(file, artifact.content.slice(0, this.runtime.limits.maxArtifactBytes), 'utf8')
      artifactPaths.push({ name: safeName, path: file, contentType: artifact.contentType ?? 'text/plain' })
    }
    await store.refreshStats(input.task)
    if (input.stepId) {
      await store.updateStep(input.task, input.stepId, {
        status: 'DONE',
        summary: summary.slice(0, 1000),
        evidenceIds,
        findingIds: findings.map((finding) => finding.id),
        finishedAt: nowIso(),
        durationMs: input.durationMs,
      })
    }
    return {
      capability: input.capability.id,
      domain: input.capability.domain,
      riskLevel: input.capability.riskLevel,
      summary,
      data,
      findings,
      evidenceIds,
      artifacts: artifactPaths,
      durationMs: input.durationMs,
      target: input.targetPath,
      targetSha256: input.targetSha,
      truncated: Boolean(data?.truncated),
    }
  }

  /**
   * Run pending workflow steps until the plan finishes or maxSteps is reached.
   * @param {any} task
   * @param {{maxSteps?: number, requestApproval?: Function, signal?: AbortSignal, generateReport?: boolean}} [opts]
   */
  async runWorkflow(task, opts = {}) {
    const ctx = this.context(task.workspace)
    const store = ctx.taskStore
    if (TERMINAL.has(task.state)) return task
    if (!['EXECUTING', 'COLLECTING_EVIDENCE'].includes(task.state)) {
      await this.prepareTask(task, { requestApproval: opts.requestApproval, signal: opts.signal })
    }
    let executed = 0
    const maxSteps = Math.max(1, Math.min(opts.maxSteps ?? 50, 50))
    while (executed < maxSteps) {
      if (opts.signal?.aborted) {
        await store.cancel(task, 'cancelled during workflow execution')
        return task
      }
      const step = task.steps.find((item) => item.status === 'PENDING')
      if (!step) break
      if (task.state === 'COLLECTING_EVIDENCE') await store.transition(task, 'EXECUTING', 'next step')
      step.status = 'RUNNING'
      step.startedAt = nowIso()
      step.attempt = (step.attempt ?? 0) + 1
      await store.save(task)
      const started = Date.now()
      try {
        const result = await this.runCapability({
          task,
          capabilityId: step.capabilityId,
          targetPath: task.targetPath,
          options: step.options ?? {},
          stepId: step.id,
          requestApproval: opts.requestApproval,
          signal: opts.signal,
        })
        step.status = 'DONE'
        step.summary = result.summary.slice(0, 1000)
        step.evidenceIds = result.evidenceIds
        step.findingIds = result.findings.map((finding) => finding.id)
      } catch (error) {
        step.status = /** @type {any} */ (error)?.code === 'CANCELLED' || opts.signal?.aborted ? 'CANCELLED' : 'FAILED'
        step.error = error instanceof PolicyDeniedError ? `${error.code}: ${error.message}` : String(/** @type {any} */ (error)?.message ?? error)
      } finally {
        step.finishedAt = nowIso()
        step.durationMs = Date.now() - started
        await store.save(task)
      }
      await store.refreshStats(task)
      task.currentStep = task.steps.filter((item) => item.status !== 'PENDING').length
      if (!TERMINAL.has(task.state)) await store.transition(task, 'COLLECTING_EVIDENCE', 'step evidence collected')
      executed += 1
    }
    const pending = task.steps.some((item) => item.status === 'PENDING' || item.status === 'RUNNING')
    if (!pending && !TERMINAL.has(task.state)) {
      await this.finalizeTask(task, { generateReport: opts.generateReport !== false })
    }
    return task
  }

  /**
   * Close out a task: verify, generate the default report, and pick the terminal state.
   * @param {any} task
   * @param {{generateReport?: boolean}} [opts]
   */
  async finalizeTask(task, opts = {}) {
    const ctx = this.context(task.workspace)
    const store = ctx.taskStore
    const audit = ctx.audit
    if (TERMINAL.has(task.state)) return task
    if (task.state === 'EXECUTING' || task.state === 'COLLECTING_EVIDENCE') {
      await store.transition(task, 'VERIFYING', 'all steps settled')
    }
    if (task.state !== 'VERIFYING') return task
    await store.refreshStats(task)
    const evidenceStore = store.evidenceStore(task.id)
    const chain = await evidenceStore.verifyChain()
    await store.addNote(task, `evidence chain ${chain.valid ? 'verified' : `BROKEN at ${chain.brokenAt}`} (${chain.records} records)`)
    await store.transition(task, 'REPORTING', 'generating report')
    let reportFailure = null
    if (opts.generateReport !== false) {
      try {
        const { generateTaskReport } = await import('./reports.js')
        const report = await generateTaskReport(this.runtime, task, { format: 'markdown' })
        task.report = { format: report.format, path: report.path, sha256: report.sha256, at: report.generatedAt }
        await store.save(task)
        await store.addNote(task, `report generated: ${report.path}`)
      } catch (error) {
        reportFailure = String(/** @type {any} */ (error)?.message ?? error)
        await store.addNote(task, `report generation failed: ${reportFailure}`)
      }
    }
    const failedSteps = task.steps.filter((item) => item.status === 'FAILED').length
    const partial = failedSteps > 0 || Boolean(reportFailure)
    const terminal = partial ? 'PARTIAL_SUCCESS' : 'COMPLETED'
    if (partial && task.stats.evidence === 0 && task.stats.findings === 0 && failedSteps > 0) {
      await store.transition(task, 'FAILED', `all steps failed or nothing collected: ${failedSteps} failed step(s)`)
    } else {
      await store.transition(task, terminal, partial ? 'finished with failed steps; collected results preserved' : 'analysis completed')
    }
    await audit.append({
      action: 'task.finalize',
      taskId: task.id,
      terminal: task.state,
      evidence: task.stats.evidence,
      findings: task.stats.findings,
      failedSteps,
      evidenceChain: chain,
      report: task.report,
    })
    return task
  }
}

export default ExecutionRunner
