/**
 * Pi native extension: expose ArmorBreak Universal Core tools directly.
 * Pi has no built-in MCP; this registers native tools instead.
 */
import { resolve, sep } from 'node:path'
import { Type } from 'typebox'
import { createEngine } from '../../packages/engine-node/index.js'

const stateRoot = process.env.ARMORBREAK_STATE_ROOT || 'D:/dsh-ABM/host-evidence/pi/state'
const workspace = resolve(process.env.ARMORBREAK_WORKSPACE || 'D:/dsh-ABM/armorbreak')
const principalId = process.env.ARMORBREAK_PRINCIPAL_ID || 'pi-host'
const principal = { id: principalId, kind: 'local-user', workspaces: [workspace] }
let enginePromise

function engine() {
  enginePromise ??= createEngine({ stateRoot, workspaceId: workspace, principal, principals: [principal] })
  return enginePromise
}

function ctx() {
  const now = Date.now()
  return { principal, workspaceId: workspace, requestId: `pi-${now}`, traceId: `trace-${now}` }
}

function textResult(value) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }], details: value }
}

function insideWorkspace(target) {
  const next = resolve(target)
  return next === workspace || next.startsWith(workspace + sep)
}

export default function armorbreakPi(pi) {
  pi.registerTool({
    name: 'armorbreak_health',
    label: 'ArmorBreak Health',
    description: 'Return ArmorBreak Core health, isolation denial and capability count.',
    promptSnippet: 'Check ArmorBreak Universal Core health.',
    parameters: Type.Object({}),
    async execute() { return textResult(await (await engine()).health(ctx())) },
  })

  pi.registerTool({
    name: 'armorbreak_analyze',
    label: 'ArmorBreak Analyze',
    description: 'Run a real ArmorBreak capability against a target inside the approved workspace.',
    promptSnippet: 'Run an ArmorBreak L0 capability on a workspace target.',
    parameters: Type.Object({
      capability: Type.String({ description: 'Capability id, for example forensics.hash' }),
      target: Type.String({ description: 'Absolute target path inside the workspace' }),
    }),
    async execute(_toolCallId, params) {
      if (!insideWorkspace(params.target)) throw new Error('target is outside the approved workspace')
      return textResult(await (await engine()).analyze(ctx(), { capability: params.capability, target: resolve(params.target), options: {} }))
    },
  })

  pi.registerTool({
    name: 'armorbreak_report',
    label: 'ArmorBreak Report',
    description: 'Read the evidence-backed report for an ArmorBreak task.',
    promptSnippet: 'Read an ArmorBreak task report.',
    parameters: Type.Object({ taskId: Type.String({ description: 'ArmorBreak task id' }) }),
    async execute(_toolCallId, params) { return textResult(await (await engine()).getReport(ctx(), params.taskId)) },
  })
}
