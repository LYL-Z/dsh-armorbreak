#!/usr/bin/env node
/**
 * Strict real-provider / real-host retest.
 *
 * - No request by default; only local CLI/credential preparation checks.
 * - --run requires --confirm-auth for hosts; no yolo/skip-trust.
 * - Host tests are L0/read-only, use a unique run id and reject historical tasks.
 * - Provider tests are staged: connectivity, tool call, streaming, local error
 *   handling, and a bounded multi-turn tool loop.
 * - stdout/stderr/errors/evidence are redacted; secrets are never written.
 */
import { spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createProviderRouter } from '../../packages/provider-router/index.js'
import { createProviderClient } from '../../packages/provider-router/client.js'
import { runToolLoop } from '../../packages/provider-router/toolLoop.js'
import { createEngine } from '../../packages/engine-node/index.js'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const ROOT = resolve(new URL('../..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const TARGET = join(ROOT, 'README.md')
const AUDIT = {
  claude: process.env.CLAUDE_AUDIT_LOG || 'D:/dsh-ABM/host-evidence/claude/audit/mcp.jsonl',
  antigravity: process.env.ANTIGRAVITY_AUDIT_LOG || 'D:/dsh-ABM/host-evidence/antigravity/audit/mcp.jsonl',
  zcode: process.env.ZCODE_AUDIT_LOG || 'D:/dsh-ABM/host-evidence/zcode/audit/mcp.jsonl',
}
const OPERATOR = { claude: 'claude-host', antigravity: 'antigravity-host', zcode: 'zcode-host' }
const HOST_LABEL = { claude: 'Claude Code', antigravity: 'Antigravity', zcode: 'ZCode' }

export function redact(value, secrets = []) {
  let text = typeof value === 'string' ? value : JSON.stringify(value)
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 6) text = text.split(secret).join('[REDACTED]')
  }
  return text
    .replace(/\b(sk-[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, '[REDACTED]')
    .replace(/Bearer\s+[A-Za-z0-9._-]{8,}/gi, 'Bearer [REDACTED]')
    .replace(/eyJ[A-Za-z0-9._-]{20,}/g, '[REDACTED_JWT]')
    .replace(/((?:api[_-]?key|token|secret|password)\s*[=:]\s*)[^\s,;]+/gi, '$1[REDACTED]')
}

export function sanitize(value, secrets = [], maxString = 4000) {
  if (typeof value === 'string') return redact(value, secrets).slice(0, maxString)
  if (Array.isArray(value)) return value.map((item) => sanitize(item, secrets, maxString))
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item, secrets, maxString)]))
  return value
}

export function hostVerdict(states, workspaceClean) {
  const required = ['cliPresent', 'credentialPresent', 'mcpHandshake', 'accountAuth', 'modelExecution', 'taskCompleted']
  return states.userConfirmed === 'CONFIRMED' && required.every((key) => states[key] === 'PASS') && workspaceClean ? 'PASS' : 'FAIL'
}

export function newRunId(prefix = 'run') {
  return `${prefix}-${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`
}

export function hostArgs(key, prompt, root = ROOT) {
  if (key === 'claude') {
    return ['-p', prompt, '--permission-mode', 'plan', '--permission-prompts', 'none',
      '--allowedTools', 'mcp__armorbreak__armorbreak_health,mcp__armorbreak__armorbreak_analyze,mcp__armorbreak__armorbreak_report',
      '--disallowedTools', 'Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch']
  }
  if (key === 'antigravity') {
    return ['-p', prompt, '--approval-mode', 'plan', '--allowed-mcp-server-names', 'armorbreak']
  }
  if (key === 'zcode') {
    return [process.env.ZCODE_CLI || 'D:/dsh-ABM/tools/zcode/zcode.cjs', '-p', prompt, '--cwd', root,
      '--mode', 'plan', '--disallowed-tools', 'Bash Edit Write Read Glob Grep WebFetch WebSearch']
  }
  throw new Error(`unknown host: ${key}`)
}

export function validateTask({ taskId, beforeIds = new Set(), startedAt, operator, workspace = ROOT, root = ROOT }) {
  if (!/^task_[a-z0-9_]+$/.test(String(taskId ?? ''))) return { pass: false, reason: 'invalid task id' }
  if (beforeIds.has(taskId)) return { pass: false, reason: 'task existed before this run' }
  const dir = join(root, '.armorbreak/tasks', taskId)
  if (!existsSync(join(dir, 'task.json'))) return { pass: false, reason: 'task.json missing' }
  const task = JSON.parse(readFileSync(join(dir, 'task.json'), 'utf8'))
  const created = Date.parse(task.createdAt ?? task.updatedAt ?? '')
  if (!Number.isFinite(created) || created < Date.parse(startedAt) - 5000) return { pass: false, reason: 'task is outside this run window' }
  if (task.operator !== operator) return { pass: false, reason: `operator mismatch: ${task.operator}` }
  if (resolve(task.workspace) !== resolve(workspace)) return { pass: false, reason: 'workspace mismatch' }
  const expectedTarget = join(resolve(workspace), 'README.md')
  if (resolve(task.targetPath) !== expectedTarget) return { pass: false, reason: 'target is not exactly workspace/README.md' }
  if (!existsSync(expectedTarget)) return { pass: false, reason: 'workspace README missing' }
  let realWorkspace, realTarget
  try { realWorkspace = realpathSync(workspace); realTarget = realpathSync(expectedTarget) } catch { return { pass: false, reason: 'target realpath failed' } }
  if (realWorkspace !== resolve(workspace) || realTarget !== join(realWorkspace, 'README.md')) return { pass: false, reason: 'target realpath escapes workspace' }
  if (lstatSync(expectedTarget).isSymbolicLink()) return { pass: false, reason: 'target is a symlink' }
  if (task.state !== 'COMPLETED') return { pass: false, reason: `task state ${task.state}` }
  if (!task.report?.path || !existsSync(task.report.path)) return { pass: false, reason: 'report missing' }
  const reportSha = createHash('sha256').update(readFileSync(task.report.path)).digest('hex')
  if (reportSha !== task.report.sha256) return { pass: false, reason: 'report hash mismatch' }
  const evidenceLines = existsSync(join(dir, 'evidence.jsonl'))
    ? readFileSync(join(dir, 'evidence.jsonl'), 'utf8').split(/\r?\n/).filter(Boolean).length : 0
  if (evidenceLines === 0) return { pass: false, reason: 'evidence is empty' }
  return { pass: true, task, reportSha, evidenceLines }
}

export function auditHandshake(key, startedAt, { runId, operator, workspace, path = AUDIT[key] } = {}) {
  if (!runId || !operator || !workspace) return { pass: false, reason: 'audit binding inputs missing', path }
  if (!existsSync(path)) return { pass: false, reason: 'audit log missing', path }
  const lines = readFileSync(path, 'utf8').split(/\r?\n/).filter(Boolean).map((line) => {
    try { return JSON.parse(line) } catch { return null }
  }).filter(Boolean)
  const normalizedWorkspace = resolve(workspace).replaceAll('\\', '/')
  const fresh = lines.filter((entry) => entry.runId === runId && Date.parse(entry.at) >= Date.parse(startedAt))
  const initialize = fresh.filter((entry) => entry.event === 'initialize')
  const toolsList = fresh.filter((entry) => entry.event === 'tools/list')
  const toolCalls = fresh.filter((entry) => entry.event === 'tools/call' && entry.ok === true)
  const tools = [...new Set(toolCalls.map((entry) => entry.tool))]
  const pids = [...new Set(fresh.map((entry) => entry.pid).filter((pid) => Number.isInteger(pid)))]
  const principals = [...new Set(fresh.map((entry) => entry.principal).filter(Boolean))]
  const workspaces = [...new Set(fresh.map((entry) => String(entry.workspace ?? '').replaceAll('\\', '/')))]
  const requiredTools = ['armorbreak_health', 'armorbreak_analyze', 'armorbreak_report']
  const pass = Boolean(runId && initialize.length > 0 && toolsList.length > 0
    && requiredTools.every((tool) => tools.includes(tool))
    && pids.length === 1 && principals.length === 1 && principals[0] === operator
    && workspaces.length === 1 && workspaces[0] === normalizedWorkspace
    && initialize[0]?.clientInfo?.name)
  return {
    pass,
    runId,
    initialize: initialize.length,
    toolsList: toolsList.length,
    toolCalls: toolCalls.length,
    tools,
    requiredTools,
    pid: pids.length === 1 ? pids[0] : null,
    principal: principals.length === 1 ? principals[0] : null,
    workspace: workspaces.length === 1 ? workspaces[0] : null,
    clientInfo: initialize[0]?.clientInfo ?? null,
    path,
    reason: pass ? null : 'runId/client/pid/workspace/tool-call binding incomplete',
  }
}

function workspaceSnapshot() {
  const git = spawnSync('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: ROOT, encoding: 'utf8', timeout: 20_000 })
  return { status: git.stdout.trim(), readmeSha256: createHash('sha256').update(readFileSync(TARGET)).digest('hex') }
}

function readTaskIds() {
  return new Set(readdirSync(join(ROOT, '.armorbreak/tasks')).filter((name) => name.startsWith('task_')))
}

function hostSpec(key) {
  if (key === 'claude') return { binary: process.env.CLAUDE_BIN || 'claude', versionArgs: ['--version'] }
  if (key === 'antigravity') return { binary: process.env.GEMINI_BIN || 'gemini', versionArgs: ['--version'] }
  if (key === 'zcode') return {
    binary: process.env.NODE_BINARY || 'node',
    versionArgs: [process.env.ZCODE_CLI || 'D:/dsh-ABM/tools/zcode/zcode.cjs', '--version'],
  }
  throw new Error(`unknown host: ${key}`)
}

function credentialHint(key) {
  if (key === 'claude') return existsSync(join(homedir(), '.claude.json'))
  if (key === 'antigravity') return Boolean(process.env.GEMINI_API_KEY) || existsSync(join(homedir(), '.gemini/oauth_creds.json'))
  if (key === 'zcode') return existsSync(join(homedir(), '.zcode/cli/config.json'))
  return false
}

function writeEvidence(id, value, secrets) {
  const path = join(ROOT, 'docs/v2/acceptance/retest', `${id}.json`)
  mkdirSync(dirname(path), { recursive: true })
  const safe = sanitize(value, secrets)
  writeFileSync(path, `${JSON.stringify(safe, null, 2)}\n`)
  console.log(JSON.stringify({ id, status: safe.status, evidence: path, states: safe.states, details: safe.details ?? {} }, null, 2))
  return path
}

function updateHostMatrix(hostName, evidence) {
  const path = join(ROOT, 'docs/v2/acceptance/compatibility-matrix.json')
  const matrix = JSON.parse(readFileSync(path, 'utf8'))
  const row = matrix.hosts.find((item) => item.host === hostName)
  if (!row) return false
  Object.assign(row, {
    toolHandshake: 'PASS', taskRunState: 'L0_COMPLETED', evidenceLevel: 'real_verified',
    evidenceId: evidence.evidencePath, reportHash: evidence.task?.reportSha ?? null,
    testAt: evidence.at, limitation: `Real L0 via ${evidence.host}; strict plan/read-only; run ${evidence.runId}.`,
  })
  writeFileSync(path, `${JSON.stringify(matrix, null, 2)}\n`)
  return true
}

export async function runHost(key, { run = false, confirmAuth = false, root = ROOT } = {}) {
  const spec = hostSpec(key)
  const runId = newRunId(`host-${key}`)
  const startedAt = new Date().toISOString()
  const secrets = [process.env.OPENAI_API_KEY, process.env.ANTHROPIC_API_KEY, process.env.GEMINI_API_KEY, process.env.ZCODE_TOKEN, process.env.ZAI_API_KEY, process.env.GOOGLE_API_KEY, process.env.CLAUDE_CODE_OAUTH_TOKEN, process.env.ANTHROPIC_AUTH_TOKEN]
  const version = spawnSync(spec.binary, spec.versionArgs, { cwd: root, encoding: 'utf8', timeout: 20_000, shell: process.platform === 'win32' })
  const cliPresent = version.status === 0
  const credentialPresent = credentialHint(key)
  const states = {
    cliPresent: cliPresent ? 'PASS' : 'FAIL',
    userConfirmed: confirmAuth ? 'CONFIRMED' : 'NOT_CONFIRMED',
    credentialPresent: credentialPresent ? 'PASS' : 'FAIL',
    mcpHandshake: 'NOT_RUN',
    accountAuth: 'NOT_RUN',
    modelExecution: 'NOT_RUN',
    taskCompleted: 'NOT_RUN',
  }
  const base = {
    schemaVersion: 'armorbreak.real-retest/v2', kind: 'host', host: HOST_LABEL[key], hostKey: key,
    runId, startedAt, workspace: root, model: process.env.GEMINI_MODEL || process.env.CLAUDE_MODEL || 'host-default',
    states, cliVersion: redact((version.stdout ?? '').trim().split(/\r?\n/)[0] || '', secrets),
    evidencePath: `docs/v2/acceptance/retest/host-${key}.json`,
  }
  if (!run) return { ...base, status: cliPresent ? 'PREPARED' : 'CLI_MISSING' }
  if (!cliPresent) return { ...base, status: 'CLI_MISSING' }
  if (!confirmAuth || !credentialPresent) {
    states.accountAuth = 'BLOCKED_AUTH'
    return { ...base, status: 'BLOCKED_AUTH' }
  }
  const before = workspaceSnapshot()
  const beforeIds = readTaskIds()
  const prompt = `ArmorBreak strict L0 read-only validation. Run ID ${runId}. Use only armorbreak_health, then armorbreak_analyze with capability forensics.hash on README.md, then armorbreak_report with the returned taskId. Do not use shell, read/write/edit, network, L1/L2/L3, or any other tool. Reply with the taskId.`
  const result = spawnSync(spec.binary, hostArgs(key, prompt, root), {
    cwd: root, env: { ...process.env, ARMORBREAK_WORKSPACE: root, ARMORBREAK_RUN_ID: runId }, encoding: 'utf8', timeout: 300_000, shell: process.platform === 'win32',
  })
  const endedAt = new Date().toISOString()
  const after = workspaceSnapshot()
  const audit = auditHandshake(key, startedAt, { runId, operator: OPERATOR[key], workspace: root })
  states.mcpHandshake = audit.pass ? 'PASS' : 'FAIL'
  states.modelExecution = result.status === 0 && String(result.stdout ?? '').trim().length > 0 ? 'PASS' : 'FAIL'
  const taskId = /task_[a-z0-9_]+/.exec(String(result.stdout ?? ''))?.[0] ?? null
  const checked = taskId ? validateTask({ taskId, beforeIds, startedAt, operator: OPERATOR[key], workspace: root, root }) : { pass: false, reason: 'no task id in output' }
  states.taskCompleted = checked.pass ? 'PASS' : 'FAIL'
  states.accountAuth = checked.pass && states.modelExecution === 'PASS' ? 'PASS' : 'FAIL'
  const workspaceClean = before.status === after.status && before.readmeSha256 === after.readmeSha256
  const status = hostVerdict(states, workspaceClean)
  const evidence = {
    ...base, endedAt, status, at: endedAt,
    taskId,
    task: checked.pass ? { state: checked.task.state, operator: checked.task.operator, targetPath: checked.task.targetPath, reportSha: checked.reportSha, evidenceLines: checked.evidenceLines } : null,
    audit: { pass: audit.pass, runId: audit.runId, initialize: audit.initialize, toolsList: audit.toolsList, toolCalls: audit.toolCalls, tools: audit.tools, pid: audit.pid, principal: audit.principal, workspace: audit.workspace, clientInfo: audit.clientInfo, reason: audit.reason ?? null },
    workspace: { clean: workspaceClean, statusBefore: before.status, statusAfter: after.status, readmeUnchanged: before.readmeSha256 === after.readmeSha256 },
    details: { exitCode: result.status, reason: checked.reason ?? audit.reason ?? null, output: sanitize(`${result.stdout ?? ''}\n${result.stderr ?? ''}`, secrets) },
  }
  if (status === 'PASS') updateHostMatrix(HOST_LABEL[key], evidence)
  return evidence
}

const PROVIDER_SPECS = [
  { id: 'openai-chat', label: 'OpenAI Chat', kind: 'openai-compatible', baseUrl: 'https://api.openai.com/v1', baseUrlEnv: 'OPENAI_BASE_URL', model: process.env.OPENAI_CHAT_MODEL || 'gpt-4.1', keyEnv: 'OPENAI_API_KEY' },
  { id: 'openai-responses', label: 'OpenAI Responses', kind: 'openai-responses', baseUrl: 'https://api.openai.com/v1', baseUrlEnv: 'OPENAI_BASE_URL', model: process.env.OPENAI_RESPONSES_MODEL || 'gpt-5', keyEnv: 'OPENAI_API_KEY' },
  { id: 'anthropic', label: 'Anthropic Messages', kind: 'anthropic', baseUrl: 'https://api.anthropic.com', baseUrlEnv: 'ANTHROPIC_BASE_URL', model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5', keyEnv: 'ANTHROPIC_API_KEY' },
  { id: 'gemini', label: 'Gemini Native', kind: 'gemini', baseUrl: 'https://generativelanguage.googleapis.com/v1beta', baseUrlEnv: 'GEMINI_BASE_URL', model: process.env.GEMINI_PROVIDER_MODEL || 'gemini-2.5-pro', keyEnv: 'GEMINI_API_KEY' },
]
const TOOL = {
  name: 'armorbreak_health',
  description: 'Return ArmorBreak Core health. Read-only L0.',
  parameters: { type: 'object', properties: {}, additionalProperties: false },
}

function safeMessage(error, secrets) {
  return { code: error?.code ?? null, message: redact(String(error?.message ?? error), secrets) }
}

export async function runProvider(spec, { run = false } = {}) {
  const runId = newRunId(`provider-${spec.id}`)
  const startedAt = new Date().toISOString()
  const key = process.env[spec.keyEnv]
  const secrets = [key, process.env.OPENAI_API_KEY, process.env.ANTHROPIC_API_KEY, process.env.GEMINI_API_KEY]
  const base = { schemaVersion: 'armorbreak.real-retest/v2', kind: 'provider', provider: spec.label, providerId: spec.id, runId, startedAt, model: spec.model, stages: {}, evidencePath: `docs/v2/acceptance/retest/provider-${spec.id}.json` }
  if (!run) return { ...base, status: 'PREPARED', details: { credentialPresent: Boolean(key), credentialEnv: spec.keyEnv } }
  if (!key) return { ...base, status: 'BLOCKED_AUTH', details: { credentialEnv: spec.keyEnv } }
  const router = createProviderRouter({ providers: [{ id: spec.id, kind: spec.kind, baseUrl: process.env[spec.baseUrlEnv] || spec.baseUrl, models: [spec.model], apiKeyEnv: spec.keyEnv, supportsTools: true, timeoutMs: 60_000 }] })
  const client = createProviderClient({ router })
  const stateRoot = mkdtempSync(join(tmpdir(), 'abm-retest-provider-'))
  const principal = { id: 'provider-retest', kind: 'local-user', workspaces: [ROOT] }
  const core = await createEngine({ stateRoot, principals: [principal] })
  const coreCtx = { principal, workspaceId: ROOT, requestId: runId, traceId: runId }
  const stages = base.stages
  let requestCount = 0
  const counted = {
    async chat(options) {
      if (requestCount >= 5) throw Object.assign(new Error('request budget exceeded'), { code: 'REQUEST_BUDGET' })
      requestCount += 1
      return client.chat(options)
    },
    async chatStream(options) {
      if (requestCount >= 5) throw Object.assign(new Error('request budget exceeded'), { code: 'REQUEST_BUDGET' })
      requestCount += 1
      return client.chatStream(options)
    },
  }
  const runStage = async (name, fn) => {
    const at = new Date().toISOString()
    try { stages[name] = { status: 'PASS', at, ...(await fn()) } } catch (error) { stages[name] = { status: 'FAIL', at, error: safeMessage(error, secrets) } }
  }
  try {
    await runStage('connectivity', async () => {
      const result = await counted.chat({ model: spec.model, messages: [{ role: 'user', content: 'Reply with exactly PONG.' }], maxTokens: 16 })
      if (!String(result.text ?? '').trim()) throw Object.assign(new Error('empty response'), { code: 'EMPTY_RESPONSE' })
      return { text: sanitize(result.text, secrets), usage: result.usage }
    })
    await runStage('tool_call', async () => {
      const result = await counted.chat({ model: spec.model, messages: [{ role: 'user', content: 'Call armorbreak_health exactly once. Do not answer from memory.' }], tools: [TOOL], maxTokens: 256 })
      if (!result.toolCalls?.some((call) => call.name === 'armorbreak_health')) throw Object.assign(new Error('no armorbreak_health tool call'), { code: 'TOOL_CALL_MISSING' })
      return { toolProtocol: 'TOOL_PROTOCOL_VERIFIED', toolCalls: result.toolCalls.map((call) => ({ name: call.name, id: call.id })), usage: result.usage }
    })
    await runStage('streaming', async () => {
      const result = await counted.chatStream({ model: spec.model, messages: [{ role: 'user', content: 'Reply with a short streamed PONG.' }], maxTokens: 32 })
      if (!Number.isInteger(result.eventCount) || result.eventCount < 1) throw Object.assign(new Error('no stream events'), { code: 'STREAM_EMPTY' })
      return { text: sanitize(result.text, secrets), eventCount: result.eventCount, usage: result.usage }
    })
    await runStage('error_handling_local', async () => {
      try { await client.chat({ model: spec.model, messages: [{ role: 'user', content: 'x' }], maxTokens: 0 }) } catch (error) {
        if (error?.code !== 'REQUEST_INVALID') throw error
        return { localValidation: true, code: error.code }
      }
      throw Object.assign(new Error('local validation did not reject maxTokens=0'), { code: 'VALIDATION_NOT_REJECTED' })
    })
    await runStage('tool_loop', async () => {
      const executions = []
      const loop = await runToolLoop({
        client: counted, model: spec.model, tools: [TOOL], maxTurns: 3, maxRetries: 0, budgetTokens: 2000,
        messages: [{ role: 'user', content: 'Call armorbreak_health and report success.' }],
        executeTool: async (call) => {
          if (call?.name !== 'armorbreak_health') throw Object.assign(new Error('unexpected tool'), { code: 'TOOL_UNEXPECTED' })
          const health = await core.health(coreCtx)
          executions.push({ name: call.name, ok: health?.ok !== false })
          return JSON.stringify({ ok: true, tool: call.name, health: { version: health?.version, capabilities: health?.capabilities?.length ?? health?.capabilities } })
        },
      })
      if (loop.turns < 2) throw Object.assign(new Error('tool loop did not complete a second turn'), { code: 'TOOL_LOOP_INCOMPLETE' })
      if (executions.length === 0) throw Object.assign(new Error('no Core tool execution'), { code: 'CORE_TOOL_NOT_EXECUTED' })
      return { turns: loop.turns, usage: loop.usage, final: sanitize(loop.final, secrets), coreToolExecution: 'CORE_TOOL_EXECUTION_VERIFIED', executions }
    })
  } finally {
    await core.close()
    rmSync(stateRoot, { recursive: true, force: true })
  }
  const passed = Object.values(stages).every((stage) => stage.status === 'PASS')
  const connectivity = stages.connectivity?.status === 'PASS'
  const tool = stages.tool_call?.status === 'PASS'
  const status = passed ? 'PASS' : connectivity ? (tool ? 'PARTIAL' : 'BASIC') : 'FAIL'
  const evidence = { ...base, endedAt: new Date().toISOString(), at: new Date().toISOString(), status, compatibilityGrade: passed ? 'FULL' : status, requestCount, maxRequests: 5, retry429: 0, verification: { toolProtocol: stages.tool_call?.status === 'PASS' ? 'TOOL_PROTOCOL_VERIFIED' : 'FAIL', coreToolExecution: stages.tool_loop?.coreToolExecution === 'CORE_TOOL_EXECUTION_VERIFIED' ? 'CORE_TOOL_EXECUTION_VERIFIED' : 'FAIL' } }
  let live
  try {
    live = JSON.parse(readSafeRepoFile(ROOT, 'docs/v2/acceptance/provider-live.json', { requiredPrefix: 'docs/v2/acceptance/' }).toString('utf8'))
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
    live = { schemaVersion: 'armorbreak.provider-live/v1', providers: {} }
  }
  live.providers[spec.id] = { status, grade: evidence.compatibilityGrade, runId, at: evidence.endedAt, model: spec.model, requestCount, verification: evidence.verification, stages: Object.fromEntries(Object.entries(stages).map(([name, value]) => [name, value.status])) }
  writeSafeRepoFile(ROOT, 'docs/v2/acceptance/provider-live.json', `${JSON.stringify(sanitize(live, secrets), null, 2)}\n`, { requiredPrefix: 'docs/v2/acceptance/' })
  return evidence
}

export async function main(argv = process.argv.slice(2)) {
  const value = (name, fallback) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : fallback }
  const has = (name) => argv.includes(name)
  const run = has('--run')
  const confirmAuth = has('--confirm-auth') || process.env.ARMORBREAK_CONFIRM_AUTH === '1'
  const all = has('--all')
  const hostArg = value('--host', null)
  const providerArg = value('--provider', null)
  if (hostArg && providerArg) { console.error('use either --host or --provider, not both'); return 2 }
  if (!hostArg && !providerArg && !all) {
    console.error('usage: node scripts/v2/retest-real.mjs --host claude|antigravity|zcode|all [--run --confirm-auth] | --provider openai-chat|openai-responses|anthropic|gemini|all [--run]')
    return 2
  }
  const failures = []
  if (hostArg || all) {
    const keys = hostArg === 'all' || !hostArg ? ['claude', 'antigravity', 'zcode'] : [hostArg]
    for (const key of keys) {
      if (!['claude', 'antigravity', 'zcode'].includes(key)) { failures.push(`unknown host ${key}`); continue }
      const evidence = await runHost(key, { run, confirmAuth, root: ROOT })
      writeEvidence(`host-${key}`, evidence, [process.env.OPENAI_API_KEY, process.env.ANTHROPIC_API_KEY, process.env.GEMINI_API_KEY])
      if (run && !['PASS', 'BLOCKED_AUTH'].includes(evidence.status)) failures.push(`host ${key}: ${evidence.status}`)
    }
  }
  if (providerArg || all) {
    const specs = providerArg === 'all' || !providerArg ? PROVIDER_SPECS : PROVIDER_SPECS.filter((spec) => spec.id === providerArg)
    if (specs.length === 0) failures.push(`unknown provider ${providerArg}`)
    for (const spec of specs) {
      const evidence = await runProvider(spec, { run })
      writeEvidence(`provider-${spec.id}`, evidence, [process.env.OPENAI_API_KEY, process.env.ANTHROPIC_API_KEY, process.env.GEMINI_API_KEY])
      if (!['PASS', 'BLOCKED_AUTH', 'PREPARED'].includes(evidence.status)) failures.push(`provider ${spec.id}: ${evidence.status}`)
    }
  }
  if (failures.length) { console.error(JSON.stringify({ result: 'FAIL', failures }, null, 2)); return 1 }
  return 0
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().then((code) => { process.exitCode = code }).catch((error) => { console.error(redact(String(error?.stack ?? error))); process.exitCode = 1 })
}
