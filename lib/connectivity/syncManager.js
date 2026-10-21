/**
 * AB2-M1-05 / M2-05 Host resource sync manager.
 *
 * Read-only and separate from L2 testing: only allowlisted connectors, one
 * request per sync, no redirects/arbitrary URLs, no credentials. A failed source
 * is isolated by ConnectorHealth and never blocks another source. Successful
 * payloads are staged and activated through LayeredCache.
 */
import { join } from 'node:path'
import { LayeredCache } from './layeredCache.js'

export class ResourceSyncManager {
  /**
   * @param {{fetcher:any, networkState:any, connectorHealth:any, cacheRoot:string, clock?:()=>number}} input
   */
  constructor(input) {
    this.fetcher = input.fetcher
    this.networkState = input.networkState
    this.connectorHealth = input.connectorHealth
    this.cache = new LayeredCache({ root: input.cacheRoot })
    this.clock = input.clock ?? Date.now
    for (const connector of this.fetcher.list()) this.connectorHealth.register(connector.id)
  }

  list() {
    return this.fetcher.list()
  }

  async sync(connectorId) {
    if (!this.fetcher.list().some((connector) => connector.id === connectorId)) throw new Error(`unknown resource connector: ${connectorId}`)
    if (!this.fetcher.allowNetwork) throw new Error('RESOURCE_READ is disabled by policy; no network request was made')
    this.connectorHealth.register(connectorId)
    if (!this.connectorHealth.canAttempt(connectorId)) {
      return { connectorId, state: 'SKIPPED', reason: 'circuit breaker open or backoff active' }
    }
    if (this.networkState.state === 'UNKNOWN') this.networkState.probe(true)
    if (!['HEALTHY', 'DEGRADED', 'OFFLINE'].includes(this.networkState.state)) {
      return { connectorId, state: 'DEFERRED', reason: `network state is ${this.networkState.state}` }
    }
    this.networkState.startStaging()
    try {
      const result = await this.fetcher.fetch(connectorId)
      const payload = Buffer.from(result.data === null ? result.text ?? '' : JSON.stringify(result.data))
      const staged = await this.cache.stage({
        layer: 'cloud',
        version: `${connectorId}-${Date.now()}`,
        files: { 'payload.json': payload, 'source.json': JSON.stringify({ connector: connectorId, sha256: result.sha256, fetchedAt: result.fetchedAt, etag: result.etag, license: result.license }) },
      })
      const active = await this.cache.activate({ layer: 'cloud', stagingId: staged.stagingId })
      this.connectorHealth.recordSuccess(connectorId)
      this.networkState.endStaging(true)
      return { connectorId, state: 'SYNCED', sha256: result.sha256, bytes: result.bytes, activeVersion: active.version, activeTesting: false }
    } catch (error) {
      this.connectorHealth.recordFailure(connectorId, { message: error?.message })
      try { this.networkState.endStaging(false) } catch { /* state may already have failed */ }
      return { connectorId, state: 'FAILED', reason: String(error?.message ?? error).slice(0, 300), activeTesting: false }
    }
  }

  /** Sync multiple sources; one failure is returned as data and never blocks the rest. */
  async syncAll(connectorIds) {
    const ids = Array.isArray(connectorIds) ? connectorIds : this.list().map((connector) => connector.id)
    const results = []
    for (const id of ids) results.push(await this.sync(id))
    return { results, synced: results.filter((item) => item.state === 'SYNCED').length, failed: results.filter((item) => item.state === 'FAILED').length }
  }
}
