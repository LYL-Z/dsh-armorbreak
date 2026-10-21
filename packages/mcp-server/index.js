/**
 * @armorbreak/mcp-server (P2 slice)
 *
 * Newline-delimited JSON-RPC over stdio. stdout is reserved for protocol
 * frames; diagnostics go to stderr. The server obtains its principal and
 * workspace from trusted host configuration, never from tool arguments.
 */
import { randomUUID } from 'node:crypto'
import { createInterface } from 'node:readline'
import { pathToFileURL } from 'node:url'
import { createEngine } from '../engine-node/index.js'

const PROTOCOL_VERSION = '2025-06-18'
const SERVER_VERSION = '0.1.0-p2'
const MAX_LINE = 1024 * 1024

const TOOLS = [
  {
    name: 'armorbreak_health',
    description: 'Read ArmorBreak health for the configured trusted workspace.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'armorbreak_capabilities',
    description: 'List registered ArmorBreak capabilities for this Core.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'armorbreak_analyze',
    description: 'Run one L0 capability on a target inside the configured workspace and produce a report.',
    inputSchema: { type: 'object', required: ['capability', 'target'], properties: { capability: { type: 'string' }, target: { type: 'string' }, options: { type: 'object' } }, additionalProperties: false },
  },
  {
    name: 'armorbreak_task_get',
    description: 'Get one task visible to the configured principal/workspace.',
    inputSchema: { type: 'object', required: ['taskId'], properties: { taskId: { type: 'string' } }, additionalProperties: false },
  },
  {
    name: 'armorbreak_evidence',
    description: 'Read the evidence chain for one authorized task.',
    inputSchema: { type: 'object', required: ['taskId'], properties: { taskId: { type: 'string' } }, additionalProperties: false },
  },
  {
    name: 'armorbreak_report',
    description: 'Read the bounded Markdown report for one authorized task.',
    inputSchema: { type: 'object', required: ['taskId'], properties: { taskId: { type: 'string' } }, additionalProperties: false },
  },
  {
    name: 'armorbreak_task_list',
    description: 'List tasks visible to the configured principal and workspace.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
]

function error(id, code, message) {
  return { jsonrpc: '2.0', id, error: { code, message } }
}

export class McpServer {
  constructor({ engine, principal, workspaceId } = {}) {
    if (!engine) throw new Error('engine is required')
    if (!principal?.id || !principal?.kind) throw new Error('trusted principal is required')
    if (!workspaceId) throw new Error('workspaceId is required')
    this.engine = engine
    this.principal = principal
    this.workspaceId = workspaceId
    this.initialized = false
  }

  context(id) {
    return { principal: this.principal, workspaceId: this.workspaceId, requestId: `mcp-${id ?? randomUUID()}`, traceId: randomUUID() }
  }

  async dispatch(message) {
    if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
      return error(message?.id ?? null, -32600, 'invalid JSON-RPC request')
    }
    if (message.method === 'initialize') {
      this.initialized = true
      return {
        jsonrpc: '2.0', id: message.id ?? null,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'armorbreak', version: SERVER_VERSION },
        },
      }
    }
    if (message.method === 'notifications/initialized') return null
    if (!this.initialized) return error(message.id ?? null, -32002, 'server not initialized')
    if (message.method === 'tools/list') {
      return { jsonrpc: '2.0', id: message.id ?? null, result: { tools: TOOLS } }
    }
    if (message.method === 'tools/call') {
      const name = message.params?.name
      const args = message.params?.arguments ?? {}
      if (!TOOLS.some((tool) => tool.name === name)) return error(message.id ?? null, -32602, `unknown tool: ${String(name)}`)
      if (!args || typeof args !== 'object' || Array.isArray(args)) return error(message.id ?? null, -32602, 'tool arguments must be an object')
      try {
        const ctx = this.context(message.id)
        let value
        if (name === 'armorbreak_health') value = await this.engine.health(ctx)
        else if (name === 'armorbreak_capabilities') value = await this.engine.capabilities(ctx)
        else if (name === 'armorbreak_analyze') value = await this.engine.analyze(ctx, { capability: args.capability, target: args.target, options: args.options })
        else if (name === 'armorbreak_task_get') value = await this.engine.getTask(ctx, args.taskId)
        else if (name === 'armorbreak_evidence') value = await this.engine.getEvidence(ctx, args.taskId)
        else if (name === 'armorbreak_report') value = await this.engine.getReport(ctx, args.taskId)
        else if (name === 'armorbreak_task_list') value = { tasks: await this.engine.listTasks(ctx) }
        return { jsonrpc: '2.0', id: message.id ?? null, result: { content: [{ type: 'text', text: JSON.stringify(value) }], isError: false } }
      } catch (cause) {
        return { jsonrpc: '2.0', id: message.id ?? null, result: { content: [{ type: 'text', text: String(cause?.message ?? cause).slice(0, 2000) }], isError: true } }
      }
    }
    return error(message.id ?? null, -32601, `method not found: ${message.method}`)
  }

  async handleLine(line) {
    if (Buffer.byteLength(line) > MAX_LINE) return JSON.stringify(error(null, -32600, 'request too large'))
    let message
    try { message = JSON.parse(line) } catch { return JSON.stringify(error(null, -32700, 'parse error')) }
    const response = await this.dispatch(message)
    return response ? JSON.stringify(response) : null
  }

  async serve(input = process.stdin, output = process.stdout) {
    const rl = createInterface({ input, crlfDelay: Infinity })
    for await (const line of rl) {
      if (!line.trim()) continue
      const response = await this.handleLine(line)
      if (response) output.write(`${response}\n`)
    }
  }
}

export async function createMcpServer({ stateRoot, workspaceId, principal }) {
  const engine = await createEngine({ stateRoot, principals: [principal] })
  return { engine, server: new McpServer({ engine, principal, workspaceId }) }
}

async function main() {
  const stateRoot = process.env.ARMORBREAK_STATE_ROOT
  const workspaceId = process.env.ARMORBREAK_WORKSPACE
  const principalId = process.env.ARMORBREAK_PRINCIPAL_ID ?? 'mcp-local-user'
  if (!stateRoot || !workspaceId) {
    process.stderr.write('ARMORBREAK_STATE_ROOT and ARMORBREAK_WORKSPACE are required\n')
    process.exitCode = 2
    return
  }
  const { server, engine } = await createMcpServer({ stateRoot, workspaceId, principal: { id: principalId, kind: 'local-user', workspaces: [workspaceId] } })
  await server.serve()
  await engine.close()
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((cause) => { process.stderr.write(`${String(cause?.stack ?? cause)}\n`); process.exitCode = 1 })
}
