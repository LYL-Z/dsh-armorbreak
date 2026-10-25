#!/usr/bin/env node
/** ArmorBreak native CLI (P2 slice): doctor/capabilities/analyze/task/mcp. */
import { requestTrustedHostApproval } from './approvalPrompt.js'
import { createEngine } from '../engine-node/index.js'
import { makeApprovalId } from '../../lib/control/approvalAuthority.js'
import { createMcpServer } from '../mcp-server/index.js'
import { copyFileSync, existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { applyJsonInstall, planJsonInstall, uninstallJsonServer } from '../installer/index.js'
import { applyTomlInstall, planTomlInstall, uninstallTomlServer } from '../installer/toml.js'
import { applyYamlInstall, planYamlInstall, uninstallYamlServer } from '../installer/yaml.js'

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

function config(env = process.env) {
  const stateRoot = env.ARMORBREAK_STATE_ROOT
  const workspaceId = env.ARMORBREAK_WORKSPACE
  const principalId = env.ARMORBREAK_PRINCIPAL_ID ?? 'cli-local-user'
  if (!stateRoot || !workspaceId) throw new Error('ARMORBREAK_STATE_ROOT and ARMORBREAK_WORKSPACE are required')
  const principal = { id: principalId, kind: 'local-user', workspaces: [workspaceId] }
  return { stateRoot, workspaceId, principal, principals: [principal] }
}

export async function runCli(argv = process.argv.slice(2), dependencies = {}) {
  const { command, positional, options } = parse(argv)
  if (command === 'help' || options.help) {
    print('armorbreak doctor|capabilities|analyze|task|workflow|approval|install approve|agent|report|mcp [--json]', false)
    return
  }
  const cfg = config(dependencies.env ?? process.env)
  const engine = await createEngine(cfg)
  try {
    const ctx = { principal: cfg.principal, workspaceId: cfg.workspaceId, requestId: `cli-${Date.now()}`, traceId: `trace-${Date.now()}` }
    if (command === 'doctor') return print(await engine.health(ctx), options.json)
    if (command === 'capabilities') return print(await engine.capabilities(ctx), options.json)
    if (command === 'agent' && positional[0] === 'doctor') {
      const configPath = String(options.config ?? '')
      if (!configPath) throw new Error('agent doctor requires --config <path>')
      if (!existsSync(configPath)) throw new Error('config path does not exist')
      let document
      try { document = JSON.parse(readFileSync(configPath, 'utf8')) } catch { throw new Error('agent doctor config is not valid JSON') }
      const servers = document.mcpServers ?? document.mcp?.servers ?? {}
      const entry = servers.armorbreak ?? null
      const problems = []
      if (!entry) problems.push('armorbreak MCP entry is missing')
      else {
        if (typeof entry.command !== 'string' && typeof entry.url !== 'string') problems.push('entry needs command or url')
        const env = entry.env ?? {}
        for (const key of ['ARMORBREAK_STATE_ROOT', 'ARMORBREAK_WORKSPACE', 'ARMORBREAK_PRINCIPAL_ID']) if (!(key in env)) problems.push(`entry env is missing ${key}`)
      }
      print({ status: problems.length === 0 ? 'OK' : 'FAIL', configPath, transport: entry?.url ? 'http' : 'stdio', serverNames: Object.keys(servers), problems }, options.json)
      if (problems.length > 0) process.exitCode = 1
      return
    }
    if (command === 'agent' && positional[0] === 'install') {
      const target = String(options.target ?? '')
      const configPath = String(options.config ?? '')
      const scope = String(options.scope ?? 'project')
      if (!['claude', 'codex', 'hermes', 'generic'].includes(target)) throw new Error('agent install target must be claude, codex, hermes or generic')
      if (!configPath) throw new Error('agent install requires --config <path>; no host path is guessed')
      if (!['user', 'project'].includes(scope)) throw new Error('agent install --scope must be user or project')
      const uninstall = Boolean(options.uninstall || options.disable)
      const serverEnv = {
        ARMORBREAK_STATE_ROOT: String(options['state-root'] ?? '${ARMORBREAK_STATE_ROOT}'),
        ARMORBREAK_WORKSPACE: String(options.workspace ?? '${ARMORBREAK_WORKSPACE}'),
        ARMORBREAK_PRINCIPAL_ID: String(options.principal ?? 'armorbreak-host'),
      }
      if (options['audit-log']) serverEnv.ARMORBREAK_MCP_AUDIT_LOG = String(options['audit-log'])
      const server = {
        command: 'node',
        args: [fileURLToPath(new URL('../mcp-server/index.js', import.meta.url))],
        env: serverEnv,
      }
      if (uninstall) {
        if (!existsSync(configPath)) throw new Error('config path does not exist')
        const backup = configPath + '.armorbreak.bak'
        copyFileSync(configPath, backup)
        let result
        if (target === 'codex') result = await uninstallTomlServer({ configPath })
        else if (target === 'hermes') result = await uninstallYamlServer({ configPath })
        else result = await uninstallJsonServer({ configPath })
        return print({ status: Boolean(options.disable) ? 'DISABLED' : 'UNINSTALLED', target, scope, configPath, backup, ...result }, options.json)
      }
      let plan
      if (target === 'codex') plan = await planTomlInstall({ configPath, server, force: Boolean(options.force) })
      else if (target === 'hermes') plan = await planYamlInstall({ configPath, server, force: Boolean(options.force) })
      else plan = await planJsonInstall({ configPath, server, force: Boolean(options.force) })
      if (!options.apply) return print({ status: 'DRY_RUN', target, scope, configPath, changed: plan.changed, before: plan.before, after: plan.after, warning: 'No file written. Pass --apply after reviewing the diff.' }, options.json)
      let applied
      if (target === 'codex') applied = await applyTomlInstall(plan)
      else if (target === 'hermes') applied = await applyYamlInstall(plan)
      else applied = await applyJsonInstall(plan)
      return print({ status: 'INSTALLED', target, scope, configPath, ...applied }, options.json)
    }
    if (command === 'approval' && positional[0] === 'issue') {
      const riskLevel = String(options.risk ?? '')
      const taskId = String(options['task-id'] ?? '')
      const target = String(options.target ?? '')
      if (!['L1', 'L2'].includes(riskLevel)) throw new Error('approval risk must be L1 or L2; L3 is always denied')
      if (!taskId || !target) throw new Error('approval issue requires --task-id and --target')
      if (options.confirm !== undefined) throw new Error('approval cannot be confirmed by a predictable command-line flag')
      if (options.operator !== undefined) throw new Error('--operator is a caller-controlled label and cannot establish approval identity')
      await requestTrustedHostApproval(dependencies.approvalProvider, {
        agent: dependencies.agent,
        toolName: 'armorbreak',
        callId: dependencies.callId,
        sessionId: dependencies.sessionId,
        reason: '[ArmorBreak ' + riskLevel + '] approve task ' + taskId + ' for target ' + target,
        signal: dependencies.signal,
      })
      const issued = engine.approvalAuthority.issue({
        id: makeApprovalId(), riskLevel, taskId, target, operator: 'platform-approval',
        sessionId: dependencies.sessionId, ttlMs: 5 * 60 * 1000,
      })
      return print({ status: 'ISSUED', ...issued }, options.json)
    }
    if (command === 'install' && positional[0] === 'approve') {
      const planId = String(options['plan-id'] ?? positional[1] ?? '')
      if (!planId) throw new Error('install approve requires --plan-id')
      const plan = await engine.runtime.installer.get(planId)
      if (plan.status !== 'VERIFIED') throw new Error('installation plan must be VERIFIED; got ' + plan.status)
      if (options.operator !== undefined) throw new Error('--operator is a caller-controlled label and cannot establish approval identity')
      await requestTrustedHostApproval(dependencies.approvalProvider, {
        agent: dependencies.agent,
        toolName: 'armorbreak',
        callId: dependencies.callId,
        sessionId: dependencies.sessionId,
        reason: '[ArmorBreak L2] approve installation plan ' + plan.planId + ' hash ' + plan.planHash + ' artifact SHA-256 ' + plan.artifact.sha256 + ' path ' + plan.artifact.path,
        signal: dependencies.signal,
      })
      const approvalId = 'install:' + plan.planId
      const approvalToken = engine.runtime.approvalAuthority.issue({
        id: approvalId, riskLevel: 'L2', taskId: plan.planId, target: plan.planHash,
        operator: 'platform-approval', sessionId: dependencies.sessionId, ttlMs: 5 * 60 * 1000,
      }).token
      const approved = await engine.runtime.installer.approve(plan, { approvalToken, operator: 'platform-approval' })
      return print({ status: approved.status, planId: approved.planId, planHash: approved.planHash, approvedBy: approved.approvedBy, approvedAt: approved.approvedAt }, options.json)
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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runCli().catch((cause) => {
  process.stderr.write(`${String(cause?.message ?? cause)}\n`)
  process.exitCode = 1
})

