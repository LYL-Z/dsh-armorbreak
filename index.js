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
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', allow: 'GET, HEAD' })
      res.end(JSON.stringify({ error: 'method not allowed' }))
      return
    }
    if (!isLoopbackPeer(req)) {
      res.writeHead(403, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
      res.end(JSON.stringify({ error: 'state route is loopback-only' }))
      return
    }
    try {
      const url = new URL(String(req.url ?? STATE_PATH), 'http://127.0.0.1')
      if (url.searchParams.has('workspace')) {
        res.writeHead(403, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
        res.end(JSON.stringify({ error: 'workspace parameter is not accepted; the route reports only the current MRU workspace' }))
        return
      }
      const state = await runtime.stateSummary()
      const body = JSON.stringify({ ...state, route: STATE_PATH })
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
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
      handler: createStateHandler(runtime),
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
