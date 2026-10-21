/**
 * Process-level ArmorBreak runtime: one capability registry, one health probe
 * cache, one policy store, and lazily created per-workspace task contexts.
 * @module dsh-armorbreak/lib/core/runtime
 */
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { AuditLog } from './audit.js'
import { CapabilityRegistry } from './capabilities.js'
import { HealthService } from './health.js'
import { IsolationProviderManager } from './isolation.js'
import { ApprovalAuthority } from '../control/approvalAuthority.js'
import { PolicyGateway } from '../control/policyGateway.js'
import { ResourceFetcher, RESOURCE_CONNECTORS } from '../connectivity/resourceFetcher.js'
import { NetworkStateMachine } from '../connectivity/networkState.js'
import { ConnectorHealth } from '../connectivity/connectorHealth.js'
import { ResourceSyncManager } from '../connectivity/syncManager.js'
import { ExecutionRunner } from './runner.js'
import { ScopePolicy } from './scope.js'
import { TaskQueue } from './taskQueue.js'
import { TaskStore } from './tasks.js'
import { isolationPresentation, policyPresentation, taskRows, toolsPresentation } from './presentation.js'
import { ensureDir, nowIso, resolveStateRoot } from './util.js'

const ANALYZERS_DIR = fileURLToPath(new URL('../analyzers/', import.meta.url))

export class ArmorBreakRuntime {
  /** @param {{stateRoot?: string}} [options] */
  constructor(options = {}) {
    this.stateRoot = options.stateRoot ?? resolveStateRoot()
    this.health = new HealthService({ stateRoot: this.stateRoot })
    this.registry = new CapabilityRegistry({ analyzersDir: ANALYZERS_DIR, health: this.health })
    this.approvalAuthority = new ApprovalAuthority({ stateRoot: this.stateRoot })
    this.scope = new ScopePolicy({ stateRoot: this.stateRoot, approvalAuthority: this.approvalAuthority })
    this.policyGateway = new PolicyGateway({ scope: this.scope, resourceConnectors: Object.keys(RESOURCE_CONNECTORS) })
    this.resourceFetcher = new ResourceFetcher({ allowNetwork: process.env.ARMORBREAK_RESOURCE_READ === '1', connectors: RESOURCE_CONNECTORS })
    this.networkState = new NetworkStateMachine()
    this.connectorHealth = new ConnectorHealth()
    for (const connectorId of Object.keys(RESOURCE_CONNECTORS)) this.connectorHealth.register(connectorId)
    this.resourceSync = new ResourceSyncManager({ fetcher: this.resourceFetcher, networkState: this.networkState, connectorHealth: this.connectorHealth, cacheRoot: join(this.stateRoot, 'resource-cache') })
    this.runner = new ExecutionRunner(this)
    this.isolationProviders = new IsolationProviderManager()
    this.lastWorkspaceFile = join(this.stateRoot, 'last-workspace.json')
    /** Background workflow queue (in-process leases; empty after restart by design). */
    this.queue = new TaskQueue({ runtime: this, concurrency: 2 })
    this.limits = {
      maxInputBytes: 32 * 1024 * 1024,
      // Alias documented in docs/CONTRACT.md for analyzer authors.
      maxBytes: 32 * 1024 * 1024,
      maxFileReadBytes: 4 * 1024 * 1024,
      maxItems: 300,
      maxStrings: 1000,
      maxFindings: 200,
      maxResultBytes: 256 * 1024,
      maxArtifactBytes: 1024 * 1024,
      timeoutMs: 60_000,
    }
    /** @type {Map<string, {root: string, audit: AuditLog, taskStore: TaskStore, scope: ScopePolicy}>} */
    this.workspaces = new Map()
    /** Most recently used workspace in this process (UI/health default). */
    this.lastWorkspace = null
    try {
      const persisted = JSON.parse(readFileSync(this.lastWorkspaceFile, 'utf8'))
      if (persisted && typeof persisted.workspace === 'string' && existsSync(persisted.workspace)) this.lastWorkspace = resolve(persisted.workspace)
    } catch {
      /* no previous workspace, or unreadable state file */
    }
    /** Session id → workspace, recorded when that session invokes an ArmorBreak tool. */
    this.sessionWorkspaces = new Map()
    this.initialized = null
  }

  /** Load analyzers/policy once. */
  async init() {
    if (!this.initialized) {
      this.initialized = (async () => {
        await this.registry.load()
        await this.scope.load()
        return this
      })()
    }
    return this.initialized
  }

  /** Default workspace: explicit env override, else the host process cwd. */
  defaultWorkspace() {
    return resolve(process.env.ARMORBREAK_WORKSPACE || process.cwd())
  }

  /**
   * Resolve and cache one workspace context.
   * @param {string} workspaceRoot
   */
  workspace(workspaceRoot) {
    const root = resolve(workspaceRoot ?? this.defaultWorkspace())
    this.lastWorkspace = root
    try {
      mkdirSync(dirname(this.lastWorkspaceFile), { recursive: true })
      writeFileSync(this.lastWorkspaceFile, `${JSON.stringify({ workspace: root, savedAt: nowIso() })}\n`)
    } catch {
      /* persistence is best-effort; analysis must still work */
    }
    const cached = this.workspaces.get(root)
    if (cached) return cached
    const stateDir = join(root, '.armorbreak')
    const audit = new AuditLog({ file: join(stateDir, 'audit.jsonl') })
    const taskStore = new TaskStore({ workspaceRoot: root, audit })
    const context = { root, stateDir, audit, taskStore, scope: this.scope }
    this.workspaces.set(root, context)
    // A task that says EXECUTING in a process that has no live queue entry can
    // only be a leftover from a previous process; do not trust its RUNNING steps.
    void taskStore.recoverInterrupted({ isLive: (task) => this.queue?.isLive(task.id) }).catch(() => {})
    return context
  }

  /**
   * Validate a workspace path supplied by the model.
   * @param {string|undefined|null} input
   */
  resolveWorkspace(input) {
    const root = input ? resolve(input) : this.defaultWorkspace()
    if (!existsSync(root)) throw new Error(`workspace does not exist: ${root}`)
    return root
  }

  /**
   * Record the workspace a session actually used. Only written from tool
   * execution (never from an HTTP query), so a route cannot use it to enumerate
   * arbitrary directories.
   * @param {string} sessionId
   * @param {string} workspaceRoot
   */
  recordSessionWorkspace(sessionId, workspaceRoot) {
    const id = String(sessionId ?? '').trim()
    if (!id || id.length > 200) return false
    try {
      const root = resolve(workspaceRoot)
      if (!existsSync(root)) return false
      this.sessionWorkspaces.set(id, root)
      while (this.sessionWorkspaces.size > 50) {
        const oldest = this.sessionWorkspaces.keys().next().value
        this.sessionWorkspaces.delete(oldest)
      }
      return true
    } catch {
      return false
    }
  }

  /**
   * Resolve a session-bound workspace, if this process saw that session use a tool.
   * @param {string|undefined|null} sessionId
   */
  sessionWorkspace(sessionId) {
    const id = String(sessionId ?? '').trim()
    if (!id) return null
    const root = this.sessionWorkspaces.get(id)
    return root && existsSync(root) ? root : null
  }

  /**
   * A public, secret-free state snapshot for the health tool and the UI panel.
   * @param {string} [workspaceRoot]
   */
  async stateSummary(workspaceRoot) {
    await this.init()
    const fallback = this.lastWorkspace && existsSync(this.lastWorkspace) ? this.lastWorkspace : this.defaultWorkspace()
    const root = this.resolveWorkspace(workspaceRoot ?? fallback)
    const ctx = this.workspace(root)
    const [tasks, policy, environment, providerDiagnosis, diagnostics] = await Promise.all([
      ctx.taskStore.list(20),
      this.scope.snapshot(),
      this.health.environment(),
      this.isolationProviders.diagnose(),
      Promise.resolve(this.registry.diagnosticsReport()),
    ])
    const l1 = providerDiagnosis?.l1 ?? { available: false, verified: false, provider: null, state: 'Unavailable', reason: 'no isolation provider' }
    const isolation = {
      available: l1.available === true,
      provider: l1.provider ?? null,
      reason: l1.reason ?? null,
      state: l1.state ?? 'Unavailable',
      verified: l1.verified === true,
      selfTested: l1.verified === true,
    }
    const capabilities = this.registry.list().map((capability) => ({
      id: capability.id,
      domain: capability.domain,
      title: capability.title,
      riskLevel: capability.riskLevel,
      targetKind: capability.targetKind ?? 'file',
      externalTools: capability.externalTools ?? [],
    }))
    return {
      version: '1.2.0',
      generatedAt: nowIso(),
      workspace: root,
      workspaceBinding: 'most-recently-used (call an ArmorBreak tool to bind this session)',
      environment,
      isolation,
      connectivity: {
        state: this.networkState.snapshot(),
        connectors: this.connectorHealth.all(),
        resources: this.resourceSync.list(),
      },
      policy,
      registry: diagnostics,
      capabilities,
      tasks: tasks.map((task) => ({
        id: task.id,
        title: task.title,
        state: task.state,
        workflow: task.workflowId,
        target: task.targetPath,
        createdAt: task.createdAt,
        updatedAt: task.updatedAt,
        stats: task.stats,
        report: task.report,
      })),
      queue: this.queue.snapshot(),
      ui: {
        isolation: isolationPresentation(isolation),
        policy: policyPresentation(policy),
        tasks: taskRows(tasks),
        tools: toolsPresentation(capabilities, isolation),
      },
    }
  }
}

const RUNTIME_SYMBOL = Symbol.for('dsh.armorbreak.runtime')

/**
 * Process-wide singleton (survives duplicate module instances).
 * @param {{stateRoot?: string}} [options]
 */
export function getRuntime(options = {}) {
  const holder = /** @type {any} */ (globalThis)
  if (!holder[RUNTIME_SYMBOL]) holder[RUNTIME_SYMBOL] = new ArmorBreakRuntime(options)
  return holder[RUNTIME_SYMBOL]
}

export default ArmorBreakRuntime
