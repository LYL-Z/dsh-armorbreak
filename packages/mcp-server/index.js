/**
 * @armorbreak/mcp-server (P2 slice)
 *
 * Newline-delimited JSON-RPC over stdio. stdout is reserved for protocol
 * frames; diagnostics go to stderr. The server obtains its principal and
 * workspace from trusted host configuration, never from tool arguments.
 */
import { randomUUID } from 'node:crypto'
import { createInterface } from 'node:readline'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { constants as fsConstants, appendFileSync, mkdirSync } from 'node:fs'
import { lstat, open, readdir, realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { createEngine } from '../engine-node/index.js'

const PROTOCOL_VERSION = '2025-06-18'
const SERVER_VERSION = '0.1.0-p2'
const MAX_LINE = 1024 * 1024
const MAX_SKILL_BYTES = 1024 * 1024
const SKILLS_ROOT = resolve(fileURLToPath(new URL('../../skills/', import.meta.url)))
function relativeSegments(root, path) {
  const value = relative(root, path)
  if (!value || isAbsolute(value) || value === '..' || value.startsWith(`..${sep}`)) return null
  return value.split(sep)
}

function isSkillPath(path) {
  const parts = relativeSegments(SKILLS_ROOT, resolve(path))
  return Boolean(parts && parts.length === 2 && parts[0] && parts[1] === 'SKILL.md')
}

function samePath(left, right) {
  return relative(left, right) === '' && relative(right, left) === ''
}

function sameFile(left, right) {
  // Fail closed on filesystems that do not expose a stable file identity.
  return left.dev !== 0n && left.ino !== 0n && left.dev === right.dev && left.ino === right.ino
}

async function readSkillFile(path) {
  const candidate = resolve(path)
  if (!isSkillPath(candidate)) throw new Error('skill path outside skills root')

  const parts = relativeSegments(SKILLS_ROOT, candidate)
  const skillDirectory = join(SKILLS_ROOT, parts[0])
  const rootBefore = await lstat(SKILLS_ROOT, { bigint: true })
  if (!rootBefore.isDirectory() || rootBefore.isSymbolicLink()) throw new Error('skills root is not a real directory')
  const trustedRoot = await realpath(SKILLS_ROOT)
  if (!samePath(trustedRoot, SKILLS_ROOT)) throw new Error('skills root resolves outside its configured path')

  const [directoryBefore, fileBefore] = await Promise.all([
    lstat(skillDirectory, { bigint: true }),
    lstat(candidate, { bigint: true }),
  ])
  if (!directoryBefore.isDirectory() || directoryBefore.isSymbolicLink()) throw new Error('skill directory is not a real directory')
  if (!fileBefore.isFile() || fileBefore.isSymbolicLink() || fileBefore.nlink !== 1n || fileBefore.size > BigInt(MAX_SKILL_BYTES)) throw new Error('skill file must be a bounded singly linked regular file')

  // O_NOFOLLOW prevents a final-component symlink where the platform supports it.
  // The post-open path and file-identity checks below cover junctions and swaps in
  // parent components; content is read only from the already-validated handle.
  const noFollow = process.platform === 'win32' ? 0 : (fsConstants.O_NOFOLLOW ?? 0)
  const handle = await open(candidate, fsConstants.O_RDONLY | noFollow)
  try {
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || opened.nlink !== 1n || opened.size > BigInt(MAX_SKILL_BYTES)) throw new Error('opened skill is not a bounded singly linked regular file')

    const [rootAfter, rootRealAfter, directoryAfter, fileAfter, directoryReal, fileReal] = await Promise.all([
      lstat(SKILLS_ROOT, { bigint: true }),
      realpath(SKILLS_ROOT),
      lstat(skillDirectory, { bigint: true }),
      lstat(candidate, { bigint: true }),
      realpath(skillDirectory),
      realpath(candidate),
    ])
    if (!rootAfter.isDirectory() || rootAfter.isSymbolicLink() || !samePath(rootRealAfter, trustedRoot)) throw new Error('skills root changed while opening skill')
    if (!directoryAfter.isDirectory() || directoryAfter.isSymbolicLink()) throw new Error('skill directory changed while opening skill')
    if (!fileAfter.isFile() || fileAfter.isSymbolicLink() || fileAfter.nlink !== 1n) throw new Error('skill file changed while opening skill')

    const directoryParts = relativeSegments(trustedRoot, directoryReal)
    const fileParts = relativeSegments(trustedRoot, fileReal)
    if (!directoryParts || directoryParts.length !== 1 || !samePath(join(trustedRoot, directoryParts[0]), skillDirectory)) throw new Error('skill directory resolves outside skills root')
    if (!fileParts || fileParts.length !== 2 || fileParts[1] !== 'SKILL.md' || !samePath(join(trustedRoot, ...fileParts), candidate)) throw new Error('skill file resolves outside skills root')

    const resolvedStat = await stat(fileReal, { bigint: true })
    if (!sameFile(opened, resolvedStat) || !sameFile(opened, fileAfter)) throw new Error('skill file changed while opening skill')
    const buffer = Buffer.alloc(MAX_SKILL_BYTES + 1)
    let total = 0
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total)
      if (bytesRead === 0) break
      total += bytesRead
      if (total > MAX_SKILL_BYTES) throw new Error('skill file exceeds the read limit')
    }
    return buffer.subarray(0, total).toString('utf8')
  } finally {
    await handle.close()
  }
}

async function loadSkills() {
  const out = []
  let directories
  try { directories = await readdir(SKILLS_ROOT, { withFileTypes: true }) } catch { return out }
  for (const dir of directories) {
    if (!dir.isDirectory() || dir.isSymbolicLink()) continue
    const file = join(SKILLS_ROOT, dir.name, 'SKILL.md')
    try {
      const text = await readSkillFile(file)
      const match = /^---\n([\s\S]*?)\n---\n/.exec(text)
      if (!match) continue
      const name = /^name:\s*(\S+)$/m.exec(match[1])?.[1]
      let description = /^description:\s*(.+)$/m.exec(match[1])?.[1]
      if (description) description = description.replace(/^\"|\"$/g, '')
      if (!name || !description) continue
      const uri = pathToFileURL(file).href
      out.push({ uri, frontmatter: { name, description }, resources: [{ uri, size: Buffer.byteLength(text), digest: `sha256:${createHash('sha256').update(text).digest('hex')}` }] })
    } catch { /* missing SKILL.md */ }
  }
  return out
}

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
  constructor({ engine, principal, workspaceId, auditLog = null, connectionId = randomUUID() } = {}) {
    if (!engine) throw new Error('engine is required')
    if (!principal?.id || !principal?.kind) throw new Error('trusted principal is required')
    if (!workspaceId) throw new Error('workspaceId is required')
    if (typeof connectionId !== 'string' || !connectionId || connectionId.length > 200) throw new Error('trusted connectionId is required')
    this.engine = engine
    this.principal = principal
    this.workspaceId = workspaceId
    this.connectionId = connectionId
    this.auditLog = auditLog
    this.initialized = false
  }

  record(event) {
    if (!this.auditLog) return
    try {
      mkdirSync(dirname(this.auditLog), { recursive: true })
      appendFileSync(this.auditLog, `${JSON.stringify({ schemaVersion: 'armorbreak.mcp-audit/v1', at: new Date().toISOString(), pid: process.pid, principal: this.principal.id, workspace: this.workspaceId, runId: process.env.ARMORBREAK_RUN_ID ?? null, ...event })}\n`)
    } catch { /* audit must never break the protocol */ }
  }

  context(id) {
    return {
      principal: { ...this.principal, sessionId: this.connectionId },
      connectionId: this.connectionId,
      workspaceId: this.workspaceId,
      requestId: `mcp-${id ?? randomUUID()}`,
      traceId: randomUUID(),
    }
  }

  async dispatch(message) {
    try {
      return await this.#dispatchRequest(message)
    } catch {
      this.record({ event: 'dispatch/error', method: typeof message?.method === 'string' ? message.method : null, code: -32603 })
      return error(message?.id ?? null, -32603, 'internal error')
    }
  }

  async #dispatchRequest(message) {
    if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
      return error(message?.id ?? null, -32600, 'invalid JSON-RPC request')
    }
    if (message.method === 'initialize') {
      this.initialized = true
      this.record({
        event: 'initialize',
        protocolVersion: message.params?.protocolVersion ?? null,
        clientInfo: message.params?.clientInfo ? { name: message.params.clientInfo.name ?? null, version: message.params.clientInfo.version ?? null } : null,
      })
      return {
        jsonrpc: '2.0', id: message.id ?? null,
        result: {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false }, resources: { listChanged: false }, prompts: { listChanged: false }, extensions: { 'io.modelcontextprotocol/skills': { directoryRead: false } } },
          serverInfo: { name: 'armorbreak', version: SERVER_VERSION },
        },
      }
    }
    if (message.method === 'notifications/initialized') {
      this.record({ event: 'notifications/initialized' })
      return null
    }
    if (!this.initialized) return error(message.id ?? null, -32002, 'server not initialized')
    if (message.method === 'skills/list') {
      return { jsonrpc: '2.0', id: message.id ?? null, result: { skills: await loadSkills() } }
    }
    if (message.method === 'skills/get') {
      const found = (await loadSkills()).find((skill) => skill.uri === String(message.params?.uri ?? ''))
      if (!found) return error(message.id ?? null, -32602, 'unknown skill uri')
      return { jsonrpc: '2.0', id: message.id ?? null, result: { skill: found } }
    }
    if (message.method === 'resources/read') {
      const uri = String(message.params?.uri ?? '')
      if (uri.startsWith('file:')) {
        let path
        try { path = fileURLToPath(uri) } catch { return error(message.id ?? null, -32602, 'invalid file uri') }
        if (!isSkillPath(path)) return error(message.id ?? null, -32602, 'skill uri outside skills root')
        try {
          const text = await readSkillFile(path)
          return { jsonrpc: '2.0', id: message.id ?? null, result: { contents: [{ uri, mimeType: 'text/markdown', text }] } }
        } catch { return error(message.id ?? null, -32602, 'skill file not readable') }
      }
    }
    if (message.method === 'resources/list') {
      const tasks = await this.engine.listTasks(this.context(message.id))
      return {
        jsonrpc: '2.0', id: message.id ?? null,
        result: { resources: tasks.map((task) => ({ uri: `armorbreak://task/${task.id}`, name: task.title, mimeType: 'application/json' })) },
      }
    }
    if (message.method === 'resources/read') {
      const uri = String(message.params?.uri ?? '')
      const match = /^armorbreak:\/\/(task|report)\/(.+)$/.exec(uri)
      if (!match) return error(message.id ?? null, -32602, 'unsupported resource uri')
      const ctx = this.context(message.id)
      if (match[1] === 'task') {
        const task = await this.engine.getTask(ctx, match[2])
        return { jsonrpc: '2.0', id: message.id ?? null, result: { contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(task) }] } }
      }
      const report = await this.engine.getReport(ctx, match[2])
      return { jsonrpc: '2.0', id: message.id ?? null, result: { contents: [{ uri, mimeType: 'text/markdown', text: report.markdown }] } }
    }
    if (message.method === 'prompts/list') {
      return { jsonrpc: '2.0', id: message.id ?? null, result: { prompts: [{ name: 'armorbreak-triage', description: 'Plan an authorized L0-first ArmorBreak triage.', arguments: [{ name: 'target', required: true }] }] } }
    }
    if (message.method === 'prompts/get') {
      if (message.params?.name !== 'armorbreak-triage') return error(message.id ?? null, -32602, 'unknown prompt')
      return { jsonrpc: '2.0', id: message.id ?? null, result: { description: 'ArmorBreak triage', messages: [{ role: 'user', content: { type: 'text', text: 'Call armorbreak_capabilities, choose an L0 capability, analyze the authorized target, then verify task/evidence/report.' } }] } }
    }
    if (message.method === 'tools/list') {
      this.record({ event: 'tools/list', tools: TOOLS.length })
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
        this.record({ event: 'tools/call', tool: name, ok: true })
        return { jsonrpc: '2.0', id: message.id ?? null, result: { content: [{ type: 'text', text: JSON.stringify(value) }], isError: false } }
      } catch (cause) {
        this.record({ event: 'tools/call', tool: name, ok: false })
        return { jsonrpc: '2.0', id: message.id ?? null, result: { content: [{ type: 'text', text: String(cause?.message ?? cause).slice(0, 2000) }], isError: true } }
      }
    }
    return error(message.id ?? null, -32601, `method not found: ${message.method}`)
  }

  async handleLine(line) {
    if (Buffer.byteLength(line) > MAX_LINE) return JSON.stringify(error(null, -32600, 'request too large'))
    let message
    try { message = JSON.parse(line) } catch { return JSON.stringify(error(null, -32700, 'parse error')) }
    let response
    try { response = await this.dispatch(message) } catch { response = error(message?.id ?? null, -32603, 'internal error') }
    if (!response) return null
    try { return JSON.stringify(response) } catch { return JSON.stringify(error(message?.id ?? null, -32603, 'internal error')) }
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

export async function createMcpServer({ stateRoot, workspaceId, principal, auditLog = null, connectionId = randomUUID() }) {
  const engine = await createEngine({ stateRoot, principals: [principal] })
  return { engine, server: new McpServer({ engine, principal, workspaceId, auditLog, connectionId }) }
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
  const { server, engine } = await createMcpServer({ stateRoot, workspaceId, principal: { id: principalId, kind: 'local-user', workspaces: [workspaceId] }, auditLog: process.env.ARMORBREAK_MCP_AUDIT_LOG ?? null })
  await server.serve()
  await engine.close()
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((cause) => { process.stderr.write(`${String(cause?.stack ?? cause)}\n`); process.exitCode = 1 })
}
