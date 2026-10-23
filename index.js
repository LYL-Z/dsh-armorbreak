/**
 * ArmorBreak Host half.
 *
 * Provides one read-only HTTP route, `/armorbreak/state`, that the browser panel
 * (client.js) reads to render mode status, capability inventory, policy state and
 * recent tasks. The route:
 *   - accepts GET/HEAD only;
 *   - rejects non-loopback peers (the panel is a local desktop surface);
 *   - never accepts a caller-supplied workspace (it always reports the process
 *     MRU workspace, so it cannot enumerate other directories' tasks);
 *   - returns only secret-free runtime snapshots: no evidence excerpts, no
 *     credentials, no raw authorization records.
 * All analysis tools are registered by the preset-scoped `./tools` plugin.
 * @module dsh-armorbreak
 */
import { getRuntime } from './packages/core/index.js'
import { readTaskReport } from './packages/engine-node/index.js'
import { getWorkflow, listWorkflows } from './lib/core/workflows.js'
import { createMockTarget, runScenario } from './lib/aisec/evaluator.js'
import { buildEvaluationDashboard } from './lib/aisec/reportDashboard.js'

export const inject = ['webServer']

export const STATE_PATH = '/armorbreak/state'

/**
 * @param {import('node:http').IncomingMessage} req
 * @returns {boolean}
 */
export function isLoopbackPeer(req) {
  const address = String(req?.socket?.remoteAddress ?? '')
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

/**
 * Resolve an optional session parameter to a workspace recorded by actual tool
 * activity. Unknown/invalid session ids fall back to the MRU workspace; a query
 * can never name an arbitrary directory.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 * @param {import('node:http').IncomingMessage} req
 * @param {string} fallbackUrl
 */
function resolveSessionWorkspace(runtime, req, fallbackUrl) {
  try {
    const url = new URL(String(req?.url ?? fallbackUrl), 'http://127.0.0.1')
    const raw = url.searchParams.get('session')
    if (!raw || !/^[A-Za-z0-9_-]{1,128}$/.test(raw)) return { sessionId: null, workspace: null }
    return { sessionId: raw, workspace: runtime.sessionWorkspace(raw) }
  } catch {
    return { sessionId: null, workspace: null }
  }
}

/**
 * Build the state handler. Exported for tests so the access-control behaviour can
 * be asserted without a listener.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createStateHandler(runtime) {
  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  return async function handleState(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? STATE_PATH), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        denied(res, 'workspace parameter is not accepted; the route reports only the current MRU workspace')
        return
      }
      const session = resolveSessionWorkspace(runtime, req, STATE_PATH)
      const state = await runtime.stateSummary(session.workspace ?? undefined)
      sendJson(res, 200, {
        ...state,
        workspaceBinding: session.workspace ? 'session-bound (recorded from tool activity)' : state.workspaceBinding,
        session: session.sessionId,
        sessionBound: Boolean(session.workspace),
        route: STATE_PATH,
      })
    } catch (error) {
      sendError(res, error)
    }
  }
}

/** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
/**
 * Same-origin fence for loopback routes. Absent Origin is allowed for the
 * Electron/CLI fetch path; a present Origin must match the request Host and be a
 * loopback authority. This blocks a malicious same-host page/CSRF form.
 * @param {import('node:http').IncomingMessage} req
 */
export function isAllowedOrigin(req) {
  const origin = String(req?.headers?.origin ?? '').trim()
  if (!origin) return true
  try {
    const parsed = new URL(origin)
    const host = String(req?.headers?.host ?? '').toLowerCase()
    return ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)
      && parsed.host.toLowerCase() === host
  } catch {
    return false
  }
}

function guard(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', allow: 'GET, HEAD' })
    res.end(JSON.stringify({ error: 'method not allowed' }))
    return false
  }
  if (!isLoopbackPeer(req)) {
    denied(res, 'route is loopback-only')
    return false
  }
  if (!isAllowedOrigin(req)) {
    denied(res, 'origin is not the local workbench authority')
    return false
  }
  return true
}

/** @param {import('node:http').ServerResponse} res @param {string} message */
function denied(res, message) {
  res.writeHead(403, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify({ error: message }))
}

/** @param {import('node:http').ServerResponse} res @param {number} status @param {any} value */
function sendJson(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-length': Buffer.byteLength(body),
  })
  res.end(body)
}

/** @param {import('node:http').ServerResponse} res @param {any} error */
function sendError(res, error) {
  sendJson(res, 500, { error: String(error?.message ?? error) })
}

/**
 * Read-only task center: MRU workspace list, plus per-task detail (steps, finding
 * metadata, report pointer) when `?id=` is provided. No workspace enumeration.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createTasksHandler(runtime) {
  return async function handleTasks(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/tasks'), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        denied(res, 'workspace parameter is not accepted; the route reports only the current MRU workspace')
        return
      }
      const taskId = url.searchParams.get('id')
      const session = resolveSessionWorkspace(runtime, req, '/armorbreak/tasks')
      if (!taskId) {
        const state = await runtime.stateSummary(session.workspace ?? undefined)
        sendJson(res, 200, {
          workspace: state.workspace,
          workspaceBinding: session.workspace ? 'session-bound (recorded from tool activity)' : state.workspaceBinding,
          session: session.sessionId,
          sessionBound: Boolean(session.workspace),
          queue: state.queue,
          ui: { tasks: state.ui.tasks },
          tasks: state.ui.tasks,
        })
        return
      }
      const workspaceRoot = session.workspace ?? runtime.lastWorkspace ?? runtime.defaultWorkspace()
      const ctx = runtime.workspace(workspaceRoot)
      const task = await ctx.taskStore.get(taskId)
      const { findings } = await ctx.taskStore.evidenceStore(taskId).readFindings()
      sendJson(res, 200, {
        workspace: workspaceRoot,
        task: ctx.taskStore.summary(task, { includeSteps: true }),
        findings: findings.slice(0, 100).map((finding) => ({
          id: finding.id,
          title: String(finding.title ?? '').slice(0, 200),
          severity: finding.severity ?? 'info',
          verification: finding.verification ?? 'unverified',
          cwe: finding.cwe ?? null,
          target: finding.target ? String(finding.target).slice(0, 200) : null,
        })),
        findingCount: findings.length,
        queue: runtime.queue.status(taskId),
        route: '/armorbreak/tasks',
      })
    } catch (error) {
      sendError(res, error)
    }
  }
}

/**
 * Read-only tool center: capability domains and isolation state. External tools
 * are listed as names only unless `?probe=1` performs a bounded health probe.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createToolsHandler(runtime) {
  return async function handleTools(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/tools'), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        denied(res, 'workspace parameter is not accepted; the route reports only the current MRU workspace')
        return
      }
      const session = resolveSessionWorkspace(runtime, req, '/armorbreak/tools')
      const state = await runtime.stateSummary(session.workspace ?? undefined)
      const probe = url.searchParams.get('probe') === '1'
      const tools = probe ? await runtime.health.toolMatrix() : null
      sendJson(res, 200, {
        workspace: state.workspace,
        isolation: state.ui.isolation,
        domains: state.ui.tools.domains,
        environment: state.environment,
        workflows: listWorkflows(),
        externalTools: tools,
        probed: Boolean(tools),
        session: session.sessionId,
        sessionBound: Boolean(session.workspace),
        route: '/armorbreak/tools',
      })
    } catch (error) {
      sendError(res, error)
    }
  }
}

// ---------------------------------------------------------------------------
// v1.2.0 environment/provider diagnostics (read-only)
// ---------------------------------------------------------------------------

/** @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime */
export function createEnvironmentHandler(runtime) {
  return async function handleEnvironment(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/environment'), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        denied(res, 'workspace parameter is not accepted; environment diagnostics are process-scoped')
        return
      }
      const fresh = url.searchParams.get('fresh') === '1'
      const diagnosis = await runtime.isolationProviders.diagnose({ fresh })
      const session = resolveSessionWorkspace(runtime, req, '/armorbreak/environment')
      sendJson(res, 200, {
        ...diagnosis,
        workspace: runtime.lastWorkspace ?? null,
        session: session.sessionId,
        sessionBound: Boolean(session.workspace),
        route: '/armorbreak/environment',
      })
    } catch (error) {
      sendError(res, error)
    }
  }
}

// ---------------------------------------------------------------------------
// Stage D write actions (loopback + explicit same-origin UI header)
// ---------------------------------------------------------------------------

/** @param {import('node:http').IncomingMessage} req @param {number} [limit] */
async function readJsonBody(req, limit = 64 * 1024) {
  const chunks = []
  let total = 0
  for await (const chunk of req) {
    total += chunk.length
    if (total > limit) throw new Error('request body exceeds 64 KiB')
    chunks.push(chunk)
  }
  if (chunks.length === 0) return {}
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw new Error('request body is not valid JSON')
  }
}

/** @param {any[]} steps @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime */
function planRiskMax(steps, runtime) {
  let riskMax = 'L0'
  const order = { L0: 0, L1: 1, L2: 2, L3: 3 }
  for (const step of steps) {
    const capability = runtime.registry.get(step.capabilityId)
    if (!capability) throw new Error(`unknown capability in workflow: ${step.capabilityId}`)
    if (order[capability.riskLevel] > order[riskMax]) riskMax = capability.riskLevel
  }
  return riskMax
}

/**
 * Task actions initiated from the local workbench: create an L0 task, cancel,
 * retry failed steps, or resume an interrupted task. Requires loopback peer,
 * POST, `x-armorbreak-ui: 1` and application/json (same-origin local UI only).
 * L1/L2 workflows are rejected here because a browser has no platform approval
 * channel; they must run through the conversation tools.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createActionHandler(runtime) {
  return async function handleAction(req, res) {
    if (!isLoopbackPeer(req)) {
      denied(res, 'route is loopback-only')
      return
    }
    if (!isAllowedOrigin(req)) {
      denied(res, 'origin is not the local workbench authority')
      return
    }
    if (req.method !== 'POST') {
      res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', allow: 'POST' })
      res.end(JSON.stringify({ error: 'method not allowed' }))
      return
    }
    if (String(req.headers?.['x-armorbreak-ui'] ?? '') !== '1' || !String(req.headers?.['content-type'] ?? '').includes('application/json')) {
      denied(res, 'write actions require the local UI header x-armorbreak-ui: 1 and application/json')
      return
    }
    try {
      const body = await readJsonBody(req)
      const action = String(body.action ?? '')
      const uiRoute = action === 'evaluate' ? 'ui.evaluations.run' : action.startsWith('install.') ? `ui.${action}` : `ui.tasks.${action}`
      const uiPermission = action.startsWith('install.') ? 'SUPPLY_CHAIN' : 'TASK'
      const uiDecision = await runtime.policyGateway.decide({ action: uiRoute, identity: { kind: 'ui' }, permission: uiPermission })
      if (!uiDecision.allowed) {
        denied(res, `${uiDecision.code}: ${uiDecision.reason}`)
        return
      }
      const session = resolveSessionWorkspace(runtime, req, '/armorbreak/actions')
      const workspaceRoot = session.workspace ?? runtime.lastWorkspace ?? runtime.defaultWorkspace()
      const ctx = runtime.workspace(workspaceRoot)
      if (action === 'create') {
        const workflow = getWorkflow(String(body.workflow ?? ''))
        const target = body.target ? String(body.target) : null
        if (workflow.targetKind !== 'none' && !target) throw new Error('target path is required for this workflow')
        const riskMax = planRiskMax(workflow.steps, runtime)
        if (riskMax !== 'L0') throw new Error(`workbench creation supports L0 workflows only; ${workflow.id} is ${riskMax}. Use the conversation tools with platform approval.`)
        const task = await ctx.taskStore.create({
          title: String(body.title ?? `${workflow.title}${target ? ` — ${target.split(/[\\/]/).pop()}` : ''}`),
          objective: workflow.description,
          workflowId: workflow.id,
          targetPath: target,
          targetKind: workflow.targetKind,
          steps: workflow.steps,
        })
        await runtime.runner.prepareTask(task)
        sendJson(res, 200, { ok: true, action, workspace: workspaceRoot, task: ctx.taskStore.summary(task, { includeSteps: true }) })
        return
      }
      if (action === 'evaluate') {
        const prompt = String(body.prompt ?? '').slice(0, 4000)
        const category = String(body.category ?? 'prompt-injection')
        if (!prompt) throw new Error('prompt is required')
        if (!['prompt-injection', 'tool-abuse', 'data-exfiltration', 'memory-poisoning', 'multimodal', 'jailbreak-research'].includes(category)) throw new Error('unsupported evaluation category')
        const target = createMockTarget('workbench-mock')
        const result = await runScenario({
          scenario: { id: 'workbench-' + Date.now().toString(36), title: 'workbench evaluation', category, targetId: target.id, authorizationRequired: true, prompt },
          target,
        })
        const stored = await runtime.evaluationStore.append(result)
        sendJson(res, 200, { ok: true, action, evaluation: stored })
        return
      }
      if (action.startsWith('install.')) {
        const planId = String(body.planId ?? '')
        if (action === 'install.plan') {
          const artifactPath = String(body.artifactPath ?? '')
          if (!artifactPath) throw new Error('artifactPath is required')
          const plan = await runtime.installer.plan({
            artifactPath,
            repo: body.repo,
            commit: body.commit,
            version: body.version,
            license: body.license,
            components: Array.isArray(body.components) ? body.components : [],
          })
          if (plan.status === 'REJECTED') {
            sendJson(res, 200, { ok: false, action, plan })
            return
          }
          await runtime.installer.persist(plan)
          sendJson(res, 200, { ok: true, action, plan })
          return
        }
        if (!planId) throw new Error('planId is required')
        const plan = await runtime.installer.get(planId)
        if (action === 'install.stage') {
          const staged = await runtime.installer.stage(plan)
          sendJson(res, 200, { ok: true, action, plan: staged })
          return
        }
        if (action === 'install.verify') {
          const verified = await runtime.installer.verify(plan)
          sendJson(res, 200, { ok: true, action, plan: verified })
          return
        }
        if (action === 'install.approve') {
          denied(res, 'installation approval must be issued by the interactive host CLI')
          return
        }
        if (action === 'install.activate') {
          const active = await runtime.installer.activate(plan)
          sendJson(res, 200, { ok: true, action, plan: active })
          return
        }
        if (action === 'install.rollback') {
          const rolled = await runtime.installer.rollback(plan)
          sendJson(res, 200, { ok: true, action, plan: rolled })
          return
        }
      }
      const taskId = String(body.taskId ?? '')
      if (!taskId) throw new Error('taskId is required')
      const task = await ctx.taskStore.get(taskId)
      if (action === 'cancel') {
        const result = await runtime.queue.cancel(taskId, { reason: 'cancelled from workbench' })
        sendJson(res, 200, { ok: true, action, result, task: ctx.taskStore.summary(await ctx.taskStore.get(taskId).catch(() => task)) })
        return
      }
      if (action === 'retry') {
        if (planRiskMax(task.steps, runtime) !== 'L0') throw new Error('workbench retry supports L0 tasks only; use the conversation tools for L1/L2 approval')
        await ctx.taskStore.resetFailedSteps(task)
        await runtime.queue.start(task, { maxSteps: 50, concurrency: 2 })
        sendJson(res, 200, { ok: true, action, queue: runtime.queue.status(taskId), task: ctx.taskStore.summary(await ctx.taskStore.get(taskId)) })
        return
      }
      if (action === 'resume') {
        if (planRiskMax(task.steps, runtime) !== 'L0') throw new Error('workbench resume supports L0 tasks only')
        await runtime.queue.recover(workspaceRoot)
        const latest = await ctx.taskStore.get(taskId)
        if (!['RECOVERABLE', 'INTERRUPTED', 'PAUSED'].includes(latest.state)) throw new Error(`task is not resumable (${latest.state})`)
        await runtime.queue.resume(latest, { maxSteps: 50, concurrency: 2 })
        sendJson(res, 200, { ok: true, action, queue: runtime.queue.status(taskId), task: ctx.taskStore.summary(latest) })
        return
      }
      throw new Error(`unsupported action: ${action}`)
    } catch (error) {
      sendJson(res, 400, { error: String(error?.message ?? error) })
    }
  }
}

/**
 * Evidence explorer data for one task: bounded evidence metadata + finding rows,
 * optional severity/verification filters, and evidence hash-chain status.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createEvidenceHandler(runtime) {
  return async function handleEvidence(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/evidence'), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        denied(res, 'workspace parameter is not accepted')
        return
      }
      const taskId = String(url.searchParams.get('taskId') ?? '')
      if (!taskId) throw new Error('taskId is required')
      const session = resolveSessionWorkspace(runtime, req, '/armorbreak/tasks-data')
      const workspaceRoot = session.workspace ?? runtime.lastWorkspace ?? runtime.defaultWorkspace()
      const ctx = runtime.workspace(workspaceRoot)
      const task = await ctx.taskStore.get(taskId)
      const evidenceStore = ctx.taskStore.evidenceStore(taskId)
      const evidence = await evidenceStore.readEvidence(1000)
      const { findings } = await evidenceStore.readFindings()
      const severity = url.searchParams.get('severity')
      const verification = url.searchParams.get('verification')
      const filtered = findings.filter((finding) => (!severity || finding.severity === severity) && (!verification || finding.verification === verification))
      const chain = await evidenceStore.verifyChain()
      sendJson(res, 200, {
        workspace: workspaceRoot,
        task: ctx.taskStore.summary(task),
        chain,
        evidence: evidence.slice(0, 200).map((record) => ({ id: record.id, title: String(record.title ?? '').slice(0, 200), kind: record.kind ?? 'observation', at: record.at ?? null, excerpt: String(record.excerpt ?? '').slice(0, 300) })),
        findings: filtered.slice(0, 200).map((finding) => ({
          id: finding.id,
          title: String(finding.title ?? '').slice(0, 200),
          severity: finding.severity,
          verification: finding.verification,
          cwe: finding.cwe ?? null,
          target: finding.target ? String(finding.target).slice(0, 200) : null,
          description: String(finding.description ?? '').slice(0, 500),
        })),
        counts: { evidence: evidence.length, findings: findings.length, filteredFindings: filtered.length },
        truncated: evidence.length > 200 || filtered.length > 200,
        route: '/armorbreak/evidence',
      })
    } catch (error) {
      sendJson(res, 400, { error: String(error?.message ?? error) })
    }
  }
}

/**
 * Report preview for one task (bounded markdown/html text). HTML is returned as
 * text and must never be injected as HTML by the client (XSS boundary).
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createReportHandler(runtime) {
  return async function handleReport(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/report'), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        denied(res, 'workspace parameter is not accepted')
        return
      }
      const taskId = String(url.searchParams.get('taskId') ?? '')
      if (!taskId) throw new Error('taskId is required')
      const requestedFormat = String(url.searchParams.get('format') ?? 'markdown')
      if (!['markdown', 'html'].includes(requestedFormat)) throw new Error('format must be markdown or html')
      const workspaceRoot = runtime.lastWorkspace ?? runtime.defaultWorkspace()
      const ctx = runtime.workspace(workspaceRoot)
      const task = await ctx.taskStore.get(taskId)
      if (!task.report?.path) throw new Error('task has no generated report yet')
      const text = await readTaskReport(ctx.taskStore, { ...task.report, taskId: task.id })
      sendJson(res, 200, {
        taskId,
        path: task.report.path,
        format: task.report.format,
        sha256: task.report.sha256,
        bytes: Buffer.byteLength(text),
        text: text.slice(0, 256 * 1024),
        truncated: text.length > 256 * 1024,
        route: '/armorbreak/report',
      })
    } catch (error) {
      sendJson(res, 400, { error: String(error?.message ?? error) })
    }
  }
}

/**
 * Host plugin entry.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 */
/**
 * Workbench evaluations list (read-only, bounded).
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createEvaluationsHandler(runtime) {
  return async function handleEvaluations(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/evaluations'), 'http://127.0.0.1')
      const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit') ?? 20) || 20, 100))
      const items = await runtime.evaluationStore.list(limit)
      sendJson(res, 200, { items, count: items.length })
    } catch (error) { sendJson(res, 400, { error: String(error?.message ?? error) }) }
  }
}

/**
 * Read-only lexical knowledge search.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createKnowledgeHandler(runtime) {
  return async function handleKnowledge(req, res) {
    if (!guard(req, res)) return
    try {
      const url = new URL(String(req.url ?? '/armorbreak/knowledge'), 'http://127.0.0.1')
      const q = String(url.searchParams.get('q') ?? '').slice(0, 500)
      const limit = Math.max(1, Math.min(Number(url.searchParams.get('limit') ?? 20) || 20, 100))
      const results = q ? runtime.knowledgeIndex.search(q, { limit }) : []
      sendJson(res, 200, { backend: runtime.knowledgeIndex.backend, query: q, results, count: results.length })
    } catch (error) { sendJson(res, 400, { error: String(error?.message ?? error) }) }
  }
}

/**
 * Read-only connector catalog (metadata only, no installation).
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createCatalogHandler(runtime) {
  return async function handleCatalog(req, res) {
    if (!guard(req, res)) return
    try {
      const items = runtime.resourceSync.list().map((item) => ({ ...item, metadataOnly: true, executable: false }))
      sendJson(res, 200, { items, count: items.length, automaticInstall: false })
    } catch (error) { sendJson(res, 400, { error: String(error?.message ?? error) }) }
  }
}

/**
 * Read-only installation list.
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createInstallationsHandler(runtime) {
  return async function handleInstallations(req, res) {
    if (!guard(req, res)) return
    try {
      const items = await runtime.installer.list()
      sendJson(res, 200, { items, count: items.length, executePackageCode: false })
    } catch (error) { sendJson(res, 400, { error: String(error?.message ?? error) }) }
  }
}

/**
 * LLM evaluation dashboard (mock results explicitly labelled).
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
export function createLLMReportHandler(runtime) {
  return async function handleLLMReport(req, res) {
    if (!guard(req, res)) return
    try {
      const records = await runtime.evaluationStore.list(100)
      sendJson(res, 200, buildEvaluationDashboard(records))
    } catch (error) { sendJson(res, 400, { error: String(error?.message ?? error) }) }
  }
}

export function apply(ctx) {
  const runtime = getRuntime()
  void runtime.init().catch(() => {
    /* capability loading is retried lazily by every tool/route call */
  })
  let dispose = null
  try {
    const routes = [
      { path: STATE_PATH, handler: createStateHandler(runtime) },
      { path: '/armorbreak/tasks', handler: createTasksHandler(runtime) },
      { path: '/armorbreak/tools', handler: createToolsHandler(runtime) },
      { path: '/armorbreak/environment', handler: createEnvironmentHandler(runtime) },
      { path: '/armorbreak/actions', handler: createActionHandler(runtime) },
      { path: '/armorbreak/evidence', handler: createEvidenceHandler(runtime) },
      { path: '/armorbreak/report', handler: createReportHandler(runtime) },
      { path: '/armorbreak/evaluations', handler: createEvaluationsHandler(runtime) },
      { path: '/armorbreak/knowledge', handler: createKnowledgeHandler(runtime) },
      { path: '/armorbreak/catalog', handler: createCatalogHandler(runtime) },
      { path: '/armorbreak/installations', handler: createInstallationsHandler(runtime) },
      { path: '/armorbreak/llm-report', handler: createLLMReportHandler(runtime) },
    ]
    const disposers = routes.map((route) => ctx.webServer.register({ kind: 'exact', path: route.path, handler: route.handler }))
    dispose = () => {
      for (const disposeRoute of disposers) {
        try {
          disposeRoute()
        } catch {
          /* already removed */
        }
      }
    }
  } catch (error) {
    try {
      ctx.logger?.warn?.(`[armorbreak] state route registration failed: ${String(/** @type {any} */ (error)?.message ?? error)}`)
    } catch {
      /* logging must not break activation */
    }
  }
  if (dispose) {
    try {
      ctx.on('dispose', () => {
        try {
          dispose()
        } catch {
          /* already removed */
        }
      })
    } catch {
      /* a composition without the event still works; the route lives with the plugin generation */
    }
  }
}

export default { inject, apply }
