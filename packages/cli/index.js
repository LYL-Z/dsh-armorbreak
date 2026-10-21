#!/usr/bin/env node
/** ArmorBreak native CLI (P2 slice): doctor/capabilities/analyze/task/mcp. */
import { createEngine } from '../engine-node/index.js'
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
    print('armorbreak doctor|capabilities|analyze|task|mcp [--json]', false)
    return
  }
  const cfg = config()
  const engine = await createEngine(cfg)
  try {
    const ctx = { principal: cfg.principal, workspaceId: cfg.workspaceId, requestId: `cli-${Date.now()}`, traceId: `trace-${Date.now()}` }
    if (command === 'doctor') return print(await engine.health(ctx), options.json)
    if (command === 'capabilities') return print(await engine.capabilities(ctx), options.json)
    if (command === 'analyze') {
      if (!options.target || !options.capability) throw new Error('analyze requires --target and --capability')
      return print(await engine.analyze(ctx, { capability: String(options.capability), target: String(options.target), options: {} }), options.json)
    }
    if (command === 'task') {
      if (positional[0] !== 'status' || !positional[1]) throw new Error('task status <task-id> is required')
      return print(await engine.getTask(ctx, positional[1]), options.json)
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

