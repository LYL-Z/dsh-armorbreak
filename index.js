/**
 * ArmorBreak Host half.
 *
 * Provides one read-only HTTP route, `/armorbreak/state`, that the browser panel
 * (client.js) reads to render mode status, capability inventory, policy state and
 * recent tasks. The route returns only secret-free runtime snapshots: no task
 * content beyond titles/summaries, no evidence excerpts, no credentials.
 * All analysis tools are registered by the preset-scoped `./tools` plugin.
 * @module dsh-armorbreak
 */
import { getRuntime } from './lib/core/runtime.js'

export const inject = ['webServer']

const STATE_PATH = '/armorbreak/state'

/**
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 */
async function handleState(req, res, runtime) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', allow: 'GET, HEAD' })
    res.end(JSON.stringify({ error: 'method not allowed' }))
    return
  }
  try {
    const url = new URL(String(req.url ?? STATE_PATH), 'http://127.0.0.1')
    const workspace = url.searchParams.get('workspace') ?? undefined
    const state = await runtime.stateSummary(workspace)
    const body = JSON.stringify({ ...state, route: STATE_PATH })
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'content-length': Buffer.byteLength(body),
    })
    if (req.method === 'HEAD') res.end()
    else res.end(body)
  } catch (error) {
    const message = String(/** @type {any} */ (error)?.message ?? error)
    const body = JSON.stringify({ error: message })
    res.writeHead(500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
    res.end(body)
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
    dispose = ctx.webServer.register({
      kind: 'exact',
      path: STATE_PATH,
      handler: (req, res) => handleState(req, res, runtime),
    })
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
