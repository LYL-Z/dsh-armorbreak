/**
 * @armorbreak/core facade (P1 slice).
 *
 * This is deliberately a thin, host-neutral entry over the existing engine
 * implementation. It imports no Cordis/DSH/DOM/Electron module. The legacy
 * DSH plugin remains in index.js/tools.js and will be converted to adapter-dsh
 * only after this boundary is contract-tested.
 */
import { ArmorBreakRuntime } from '../../lib/core/runtime.js'
import { CapabilityRegistry } from '../../lib/core/capabilities.js'
import { TaskStore } from '../../lib/core/tasks.js'
import { EvidenceStore } from '../../lib/core/evidence.js'
import { PolicyGateway } from '../../lib/control/policyGateway.js'
import { PROTOCOL_VERSION, validateInvocation } from '../protocol/index.js'

export const CORE_VERSION = '0.1.0-p1'
export { ArmorBreakRuntime, CapabilityRegistry, TaskStore, EvidenceStore, PolicyGateway, PROTOCOL_VERSION, validateInvocation }

/**
 * Create one process-level Core. stateRoot is mandatory in multi-client use so
 * authorization/task facts are shared rather than duplicated per Engine.
 */
export async function createCore({ stateRoot, workspace } = {}) {
  if (!stateRoot) throw new Error('stateRoot is required for a Universal Core instance')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  return {
    version: CORE_VERSION,
    protocolVersion: PROTOCOL_VERSION,
    runtime,
    async capabilities(ctx) {
      const check = validateInvocation(ctx)
      if (!check.ok) throw new Error(`invalid invocation: ${check.issues.join('; ')}`)
      return runtime.registry.list()
    },
    async health(ctx) {
      const check = validateInvocation(ctx)
      if (!check.ok) throw new Error(`invalid invocation: ${check.issues.join('; ')}`)
      return runtime.stateSummary()
    },
    async close() {
      await runtime.close?.()
    },
  }
}
