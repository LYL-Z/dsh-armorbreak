#!/usr/bin/env node
/** ArmorBreak native CLI (P2 slice): doctor/capabilities/analyze/task/mcp. */
import { createHash } from 'node:crypto'
import { createEngine } from '../engine-node/index.js'
import { makeApprovalId } from '../../lib/control/approvalAuthority.js'
import { createMcpServer } from '../mcp-server/index.js'

function parse(argv) {
  const positional = []
  const options = {}
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]
    if (token === '--json') options.json = true
    else if (token.startsWith('--')) {
      const key = token.slice(2)
      const value = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true
      options[key] = value
    } else positional.push(token)
  }
  return { command: positional.shift() ?? 'help', positional, options }
}

function print(value, json) {
  process.stdout.write(`${json ? JSON.stringify(value, null, 2) : String(value)}\n`)
}

function config() {
  const stateRoot = process.env.ARMORBREAK_STATE_ROOT
  const workspaceId = process.env.ARMORBREAK_WORKSPACE
  const principalId = process.env.ARMORBREAK_PRINCIPAL_ID ?? 'cli-local-user'
  if (!stateRoot || !workspaceId) throw new Error('ARMORBREAK_STATE_ROOT and ARMORBREAK_WORKSPACE are required')
  const principal = { id: principalId, kind: 'local-user', workspaces: [workspaceId] }
  return { stateRoot, workspaceId, principal, principals: [principal] }
}

async function main() {
  const { command, positional, options } = parse(process.argv.slice(2))
  if (command === 'help' || options.help) {
    print('armorbreak doctor|capabilities|analyze|task|workflow|approval|report|mcp [--json]', false)
    return
  }
  const cfg = config()
  const engine = await createEngine(cfg)
  try {
    const ctx = { principal: cfg.principal, workspaceId: cfg.workspaceId, requestId: `cli-${Date.now()}`, traceId: `trace-${Date.now()}` }
    if (command === 'doctor') return print(await engine.health(ctx), options.json)
    if (command === 'capabilities') return print(await engine.capabilities(ctx), options.json)
    if (command === 'approval' && positional[0] === 'issue') {
      const riskLevel = String(options.risk ?? '')
      const taskId = String(options['task-id'] ?? '')
      const target = String(options.target ?? '')
      const operator = String(options.operator ?? cfg.principal.id)
      if (!['L1', 'L2'].includes(riskLevel)) throw new Error('approval risk must be L1 or L2; L3 is always denied')
      if (!taskId || !target) throw new Error('approval issue requires --task-id and --target')
      const challenge = 'confirm-' + createHash('sha256').update([riskLevel, taskId, target, operator].join('|')).digest('hex').slice(0, 16)
      if (options.confirm === undefined) {
        process.exitCode = 2
        return print({ status: 'CONFIRMATION_REQUIRED', challenge, riskLevel, taskId, target, operator, warning: 'Run only after a human verifies the exact target; MCP/model text cannot confirm.' }, options.json)
      }
      if (String(options.confirm) !== challenge) throw new Error('approval confirmation challenge mismatch')
      const issued = engine.approvalAuthority.issue({ id: makeApprovalId(), riskLevel, taskId, target, operator, ttlMs: 5 * 60 * 1000 })
      return print({ status: 'ISSUED', ...issued }, options.json)
    }
    if (command === 'analyze') {
      if (!options.target || !options.capability) throw new Error('analyze requires --target and --capability')
      return print(await engine.analyze(ctx, { capability: String(options.capability), target: String(options.target), options: {} }), options.json)
    }
    if (command === 'report') {
      if (!positional[0]) throw new Error('report <task-id> is required')
      return print(await engine.getReport(ctx, positional[0]), options.json)
    }
    if (command === 'task') {
      if (positional[0] === 'list') return print(await engine.listTasks(ctx), options.json)
      if (positional[0] === 'cancel' && positional[1]) return print(await engine.cancelTask(ctx, positional[1]), options.json)
      if (positional[0] !== 'status' || !positional[1]) throw new Error('task status <task-id>, task list, or task cancel <task-id> is required')
      return print(await engine.getTask(ctx, positional[1]), options.json)
    }
    if (command === 'workflow') {
      if (positional[0] === 'list') return print(await engine.listWorkflows(ctx), options.json)
      if (positional[0] === 'cancel' && positional[1]) return print(await engine.cancelTask(ctx, positional[1]), options.json)
      throw new Error('workflow list or workflow cancel <task-id> is required')
    }
    if (command === 'mcp' && positional[0] === 'serve') {
      const { server } = await createMcpServer(cfg)
      await server.serve()
      return
    }
    throw new Error(`unknown command: ${command}`)
  } finally {
    await engine.close()
  }
}

main().catch((cause) => {
  process.stderr.write(`${String(cause?.message ?? cause)}\n`)
  process.exitCode = 1
})

