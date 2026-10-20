/**
 * Process-level ArmorBreak runtime: one capability registry, one health probe
 * cache, one policy store, and lazily created per-workspace task contexts.
 * @module dsh-armorbreak/lib/core/runtime
 */
import { fileURLToPath } from 'node:url'
import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { AuditLog } from './audit.js'
import { CapabilityRegistry } from './capabilities.js'
import { HealthService } from './health.js'
import { ExecutionRunner } from './runner.js'
import { ScopePolicy } from './scope.js'
import { TaskStore } from './tasks.js'
import { ensureDir, nowIso, resolveStateRoot } from './util.js'

const ANALYZERS_DIR = fileURLToPath(new URL('../analyzers/', import.meta.url))

export class ArmorBreakRuntime {
  /** @param {{stateRoot?: string}} [options] */
  constructor(options = {}) {
    this.stateRoot = options.stateRoot ?? resolveStateRoot()
    this.health = new HealthService({ stateRoot: this.stateRoot })
    this.registry = new CapabilityRegistry({ analyzersDir: ANALYZERS_DIR, health: this.health })
    this.scope = new ScopePolicy({ stateRoot: this.stateRoot })
    this.runner = new ExecutionRunner(this)
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
    const cached = this.workspaces.get(root)
    if (cached) return cached
    const stateDir = join(root, '.armorbreak')
    const audit = new AuditLog({ file: join(stateDir, 'audit.jsonl') })
    const taskStore = new TaskStore({ workspaceRoot: root, audit })
    const context = { root, stateDir, audit, taskStore, scope: this.scope }
    this.workspaces.set(root, context)
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
   * A public, secret-free state snapshot for the health tool and the UI panel.
   * @param {string} [workspaceRoot]
   */
  async stateSummary(workspaceRoot) {
    await this.init()
    const fallback = this.lastWorkspace && existsSync(this.lastWorkspace) ? this.lastWorkspace : this.defaultWorkspace()
    const root = this.resolveWorkspace(workspaceRoot ?? fallback)
    const ctx = this.workspace(root)
    const [tasks, policy, environment, isolation, diagnostics] = await Promise.all([
      ctx.taskStore.list(20),
      this.scope.snapshot(),
      this.health.environment(),
      this.health.isolation(),
      Promise.resolve(this.registry.diagnosticsReport()),
    ])
    const capabilities = this.registry.list().map((capability) => ({
      id: capability.id,
      domain: capability.domain,
      title: capability.title,
      riskLevel: capability.riskLevel,
      targetKind: capability.targetKind ?? 'file',
      externalTools: capability.externalTools ?? [],
    }))
    return {
      version: '1.0.3',
      generatedAt: nowIso(),
      workspace: root,
      environment,
      isolation,
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
