/** CLI host composition, deliberately unavailable as an HTTP/MCP approval issuer. */
import { randomUUID } from 'node:crypto'
import { isAbsolute, resolve } from 'node:path'
import { readBounded } from '../core/src/util.js'
import { planSyntheticConfiguration } from '../core/src/syntheticConfiguration.js'
import { reopenSyntheticMaintenance } from '../core/src/syntheticMaintenance.js'
import { requestTrustedHostApproval } from './approvalPrompt.js'

export async function configurationLabCommand({ runtime, workspace, operator, operation, options, dependencies }) {
  const allowed = operation === 'stage' ? ['bundle','json'] : ['lab','plan','json']
  if (Object.keys(options).some(key => !allowed.includes(key))) throw new Error('CONFIG_LAB_UNKNOWN_OPTION')
  const sessionId = dependencies.sessionId ?? 'cli-preview'
  if (operation === 'stage') {
    if (typeof options.bundle !== 'string') throw new Error('CONFIG_LAB_BUNDLE_REQUIRED')
    const targetPath = resolve(options.bundle)
    const read = await readBounded(targetPath, 1024 * 1024, { authorize: () => runtime.scope.checkFile({ taskId: `config-lab-${randomUUID()}`, targetPath, workspaceRoot: workspace }) })
    if (read.truncated) throw new Error('CONFIG_LAB_INPUT_LIMIT')
    let input
    try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(read.buffer)) } catch { throw new Error('CONFIG_LAB_INVALID_JSON') }
    if (!input || Array.isArray(input) || typeof input !== 'object' || Object.keys(input).some(key => !['schema','configuration','profiles','selectedProfile','overlays','conflictPolicy'].includes(key)) || input.schema !== 'armorbreak.configuration-lab-request/v1') throw new Error('CONFIG_LAB_REQUEST_INVALID')
    const { schema, ...request } = input
    const { lab, plan, preview } = await planSyntheticConfiguration(runtime, { ...request, operator, sessionId })
    return { ...plan, lab: lab.root, preview, sessionBinding: 'HOST_SESSION_REQUIRED_FOR_APPLY', hostModified: false }
  }
  if (!['apply','revert','status'].includes(operation) || !isAbsolute(options.lab ?? '')) throw new Error('CONFIG_LAB_OPERATION_INVALID')
  if (operation !== 'status' && (!dependencies.sessionId || !dependencies.agent || !dependencies.callId || !dependencies.approvalProvider)) throw new Error('TRUSTED_APPROVAL_PROVIDER_REQUIRED')
  const lab = await reopenSyntheticMaintenance(runtime, options.lab, { operator, sessionId })
  const events = await lab.events()
  if (operation === 'status') return { mode: 'SYNTHETIC_ONLY', state: events.at(-1)?.state ?? 'UNKNOWN', planId: events.at(-1)?.planId ?? null, hostModified: false }
  if (typeof options.plan !== 'string' || !options.plan) throw new Error('CONFIG_LAB_PLAN_REQUIRED')
  const provider = { request: request => requestTrustedHostApproval(dependencies.approvalProvider, { ...request, agent: dependencies.agent, callId: dependencies.callId, sessionId: dependencies.sessionId }) }
  return operation === 'apply' ? lab.apply(options.plan, provider) : lab.rollback(options.plan, provider)
}
