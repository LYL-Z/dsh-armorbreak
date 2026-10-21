/**
 * AB2-M1-05 read-only resource connectors (RESOURCE_READ).
 *
 * This is deliberately not an L2 active-testing client. It can only GET a URL
 * from a fixed connector registry, never follows redirects, never forwards
 * credentials, enforces timeout/size bounds and returns content hashes and
 * freshness metadata. User-supplied arbitrary URLs are rejected.
 */
import { createHash } from 'node:crypto'

export const RESOURCE_CONNECTORS = Object.freeze({
  'cisa-kev': {
    title: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    license: 'US Government work (verify before redistribution)',
    contentType: 'application/json',
  },
  'first-epss': {
    title: 'FIRST EPSS',
    url: 'https://api.first.org/data/v1/epss?cve=CVE-2021-44228',
    license: 'FIRST terms — verify before redistribution',
    contentType: 'application/json',
  },
  osv: {
    title: 'OSV',
    url: 'https://api.osv.dev/v1/vulns/OSV-2020-111',
    license: 'Apache-2.0 (data terms separate)',
    contentType: 'application/json',
  },
})

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

export class ResourceFetcher {
  /**
   * @param {{connectors?: Record<string, any>, allowNetwork?: boolean, fetchImpl?: Function, maxBytes?: number}} input
   */
  constructor(input = {}) {
    this.connectors = input.connectors ?? RESOURCE_CONNECTORS
    this.allowNetwork = input.allowNetwork === true
    this.fetchImpl = input.fetchImpl ?? null
    this.maxBytes = input.maxBytes ?? 8 * 1024 * 1024
  }

  list() {
    return Object.entries(this.connectors).map(([id, connector]) => ({ id, title: connector.title, license: connector.license, url: connector.url }))
  }

  /**
   * @param {string} connectorId
   * @param {{timeoutMs?: number, maxBytes?: number, etag?: string|null}} [options]
   */
  async fetch(connectorId, options = {}) {
    const connector = this.connectors[connectorId]
    if (!connector) throw new Error(`resource connector is not allowlisted: ${connectorId}`)
    if (!this.allowNetwork) throw new Error('RESOURCE_READ is disabled by policy; no network request was made')
    let url
    try {
      url = new URL(connector.url)
    } catch {
      throw new Error(`connector ${connectorId} has an invalid URL`)
    }
    if (url.protocol !== 'https:') throw new Error('resource connectors must use https')
    const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs ?? 15_000), 120_000))
    const maxBytes = Math.max(1024, Math.min(Number(options.maxBytes ?? this.maxBytes), 32 * 1024 * 1024))
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
      const fetchImpl = this.fetchImpl ?? globalThis.fetch
      const response = await fetchImpl(url.toString(), {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'user-agent': 'ArmorBreak/2.0 resource-read (read-only)',
          accept: connector.contentType ?? 'application/json',
        },
      })
      if (response.status >= 300 && response.status < 400) throw new Error(`resource connector returned redirect ${response.status}; redirects are not followed`)
      if (!response.ok) throw new Error(`resource connector returned HTTP ${response.status}`)
      const length = Number(response.headers.get('content-length') ?? 0)
      if (length && length > maxBytes) throw new Error(`resource response exceeds ${maxBytes} bytes`)
      const array = Buffer.from(await response.arrayBuffer())
      if (array.length > maxBytes) throw new Error(`resource response exceeds ${maxBytes} bytes`)
      const text = array.toString('utf8')
      let json = null
      try { json = JSON.parse(text) } catch { /* non-JSON source */ }
      return {
        connector: connectorId,
        title: connector.title,
        status: response.status,
        contentType: response.headers.get('content-type') ?? connector.contentType ?? null,
        etag: response.headers.get('etag') ?? null,
        lastModified: response.headers.get('last-modified') ?? null,
        bytes: array.length,
        sha256: sha256(array),
        fetchedAt: new Date().toISOString(),
        license: connector.license,
        data: json,
        text: json === null ? text.slice(0, 2000) : null,
        permission: 'RESOURCE_READ',
        activeTesting: false,
      }
    } finally {
      clearTimeout(timer)
    }
  }
}
