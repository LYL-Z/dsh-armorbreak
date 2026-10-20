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
import { getRuntime } from './lib/core/runtime.js'

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
      const state = await runtime.stateSummary()
      sendJson(res, 200, { ...state, route: STATE_PATH })
    } catch (error) {
      sendError(res, error)
    }
  }
}

/** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
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
      if (!taskId) {
        const state = await runtime.stateSummary()
        sendJson(res, 200, {
          workspace: state.workspace,
          workspaceBinding: state.workspaceBinding,
          queue: state.queue,
          ui: { tasks: state.ui.tasks },
          tasks: state.ui.tasks,
        })
        return
      }
      const workspaceRoot = runtime.lastWorkspace ?? runtime.defaultWorkspace()
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
 * are listed as names only; they are NOT reported as installed without a probe.
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
      const state = await runtime.stateSummary()
      sendJson(res, 200, {
        workspace: state.workspace,
        isolation: state.ui.isolation,
        domains: state.ui.tools.domains,
        environment: state.environment,
        route: '/armorbreak/tools',
      })
    } catch (error) {
      sendError(res, error)
    }
  }
}

/**
 * Host plugin entry.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 */
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
