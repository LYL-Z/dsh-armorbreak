/**
 * Capability registry: discovers analyzer domain manifests, validates their
 * contracts, and exposes dependency-aware descriptors to tools and health.
 * @module dsh-armorbreak/lib/core/capabilities
 */
import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { RISK_LEVELS } from './scope.js'

const CAPABILITY_ID = /^[a-z0-9-]+\.[a-z0-9][a-z0-9._-]*$/
const DOMAIN_ID = /^[a-z0-9-]+$/

const INTELLIGENCE_SUPPORT = {
  'artifact.identify': { supportedLevels: ['S1'], limitations: ['Format identification is a bounded candidate classification, not proof of provenance or safety.'] },
  'artifact.inventory': { supportedLevels: ['S1'], limitations: ['Archive contents are indexed within configured limits and are not executed or extracted to disk.'] },
  'source.symbols': { supportedLevels: ['S2'], limitations: ['Semantic coverage is limited to the parsers and language constructs reported by the result.'] },
  'binary.program_ir': { supportedLevels: ['S3'], limitations: ['Native analysis is static and bounded; Ghidra-backed detail depends on the installed backend and result status.'] },
  'security.correlate': { supportedLevels: ['S4'], limitations: ['Corroborates imported evidence but does not establish vulnerability confirmation or fetch advisory data.'] },
  'rebuild.contract': { supportedLevels: ['S5'], limitations: ['Normalizes caller-supplied observations; it does not infer a complete contract from arbitrary source.'] },
  'rebuild.compare': { supportedLevels: ['S5'], limitations: ['Compares pre-generated finite JSON outcomes and does not execute either implementation.'] },
}

function intelligenceStatus(capability) {
  const support = INTELLIGENCE_SUPPORT[capability.id]
  if (!support) return {}
  return {
    supportedLevels: [...support.supportedLevels],
    engine: 'ArmorBreak offline analyzer',
    backendVersion: null,
    status: 'REGISTERED_NOT_EXECUTED',
    reason: 'This catalog confirms registration only; per-target completeness, backend availability, and truncation are reported by the analysis result.',
    limitations: [...support.limitations],
  }
}

/**
 * @typedef {{id: string, title: string, description: string, riskLevel: 'L0'|'L1'|'L2'|'L3', params?: object, externalTools?: string[], targetKind?: 'file'|'directory'|'network'|'none', networkTarget?: (options: Record<string, any>) => string, run: (input: any) => Promise<any>}} Capability
 */

export class CapabilityRegistry {
  /**
   * @param {{analyzersDir: string, health?: import('./health.js').HealthService}} options
   */
  constructor(options) {
    this.analyzersDir = options.analyzersDir
    this.health = options.health
    /** @type {Map<string, Capability>} */
    this.capabilities = new Map()
    /** @type {Map<string, string>} */
    this.domains = new Map()
    /** @type {Array<{domain: string, package: string, message: string}>} */
    this.diagnostics = []
    this.loaded = false
  }

  async load() {
    if (this.loaded) return this
    this.loaded = true
    let entries = []
    try {
      entries = await readdir(this.analyzersDir, { withFileTypes: true })
    } catch (error) {
      this.diagnostics.push({ domain: '*', package: this.analyzersDir, message: `analyzers directory unreadable: ${String(error)}` })
      return this
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue
      if (!DOMAIN_ID.test(entry.name)) {
        this.diagnostics.push({ domain: entry.name, package: entry.name, message: 'invalid domain directory name' })
        continue
      }
      const manifestPath = join(this.analyzersDir, entry.name, 'manifest.js')
      try {
        const module = await import(pathToFileURL(manifestPath).href)
        const manifest = module.default
        this.registerManifest(entry.name, manifest)
      } catch (error) {
        this.diagnostics.push({ domain: entry.name, package: manifestPath, message: `${/** @type {any} */ (error)?.message ?? String(error)}` })
      }
    }
    return this
  }

  /**
   * @param {string} dirDomain
   * @param {any} manifest
   */
  registerManifest(dirDomain, manifest) {
    if (!manifest || typeof manifest !== 'object') {
      this.diagnostics.push({ domain: dirDomain, package: dirDomain, message: 'manifest default export must be an object' })
      return
    }
    const domain = typeof manifest.domain === 'string' ? manifest.domain : dirDomain
    if (!DOMAIN_ID.test(domain)) {
      this.diagnostics.push({ domain, package: dirDomain, message: 'manifest.domain must be kebab-case' })
      return
    }
    if (domain !== dirDomain) {
      this.diagnostics.push({ domain, package: dirDomain, message: `manifest.domain "${domain}" does not match directory "${dirDomain}"` })
    }
    const list = Array.isArray(manifest.capabilities) ? manifest.capabilities : []
    if (list.length === 0) {
      this.diagnostics.push({ domain, package: dirDomain, message: 'manifest declares no capabilities' })
      return
    }
    for (const raw of list) {
      const errors = []
      if (!raw || typeof raw !== 'object') {
        errors.push('capability must be an object')
      } else {
        if (typeof raw.id !== 'string' || !CAPABILITY_ID.test(raw.id)) errors.push('id must match <domain>.<action>')
        if (typeof raw.title !== 'string' || raw.title.trim() === '') errors.push('title is required')
        if (typeof raw.description !== 'string' || raw.description.trim().length < 10) errors.push('description (>=10 chars) is required')
        if (!RISK_LEVELS.includes(raw.riskLevel)) errors.push('riskLevel must be one of L0/L1/L2/L3')
        if (raw.params !== undefined && (typeof raw.params !== 'object' || raw.params === null)) errors.push('params must be a JSON Schema object')
        if (raw.targetKind !== undefined && !['file', 'directory', 'network', 'none'].includes(raw.targetKind)) errors.push('targetKind invalid')
        if (typeof raw.run !== 'function') errors.push('run(input) function is required')
        if (typeof raw.id === 'string' && this.capabilities.has(raw.id)) errors.push(`duplicate capability id: ${raw.id}`)
        if (raw.networkTarget !== undefined && typeof raw.networkTarget !== 'function') errors.push('networkTarget must be a function')
      }
      if (errors.length > 0) {
        this.diagnostics.push({ domain, package: raw?.id ?? dirDomain, message: errors.join('; ') })
        continue
      }
      this.capabilities.set(raw.id, { ...raw, domain: raw.domain ?? domain })
    }
    this.domains.set(domain, dirDomain)
  }

  /** @param {string} id */
  get(id) {
    return this.capabilities.get(id)
  }

  /**
   * @param {{domain?: string, riskLevel?: string}} [filter]
   * @returns {Capability[]}
   */
  list(filter = {}) {
    let items = [...this.capabilities.values()]
    if (filter.domain) items = items.filter((capability) => capability.domain === filter.domain)
    if (filter.riskLevel) items = items.filter((capability) => capability.riskLevel === filter.riskLevel)
    return items.sort((a, b) => a.id.localeCompare(b.id)).map((capability) => ({ ...capability, ...intelligenceStatus(capability) }))
  }

  /** @param {string} domain */
  byDomain(domain) {
    return this.list({ domain })
  }

  /** @returns {string[]} */
  domainsList() {
    return [...new Set(this.list().map((capability) => capability.domain))].sort()
  }

  /**
   * Build a model/UI-facing descriptor including declared external tool status.
   * @param {Capability} capability
   * @param {{probe?: boolean}} [opts]
   */
  async describe(capability, opts = {}) {
    const externalTools = []
    for (const toolId of capability.externalTools ?? []) {
      const status = this.health ? await this.health.probe(toolId, { version: opts.probe === true }) : { found: false, reason: 'health service not mounted' }
      externalTools.push({ id: toolId, ...status })
    }
    return {
      id: capability.id,
      domain: capability.domain,
      title: capability.title,
      description: capability.description,
      riskLevel: capability.riskLevel,
      targetKind: capability.targetKind ?? 'file',
      params: capability.params ?? { type: 'object', properties: {}, additionalProperties: false },
      externalTools,
      available: true,
      ...intelligenceStatus(capability),
    }
  }

  /**
   * Dependency status for one external tool id; used by describe/health.
   * @param {string} toolId
   * @param {{version?: boolean}} [opts]
   */
  async dependency(toolId, opts = {}) {
    if (!this.health) return { id: toolId, found: false, reason: 'health service not mounted' }
    return this.health.probe(toolId, opts)
  }

  diagnosticsReport() {
    return {
      loaded: this.loaded,
      capabilities: this.capabilities.size,
      domains: this.domainsList(),
      diagnostics: this.diagnostics,
    }
  }
}

export default CapabilityRegistry
