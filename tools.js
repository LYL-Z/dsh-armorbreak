/**
 * Preset-scoped model-facing tools for ArmorBreak.
 *
 * Every tool is a thin, typed wrapper over the process-wide runtime: it resolves
 * the workspace, validates arguments, applies the platform approval bridge when
 * a capability needs one, and returns a bounded Markdown summary plus structured
 * data. Policy enforcement itself lives in lib/core/runner.js and scope.js.
 * @module dsh-armorbreak/tools
 */
import { basename } from 'node:path'
import { getRuntime } from './lib/core/runtime.js'
import { getWorkflow, listWorkflows } from './lib/core/workflows.js'
import { generateTaskReport } from './lib/core/reports.js'
import { listDirectory, readFileBounded, searchFiles, statPath } from './lib/core/files.js'
import { POLICY_TOOL_DOC } from './lib/core/help.js'

export const inject = ['tools']

/** Cordis context of the mounted preset scope (one standing mount per process). */
let pluginCtx = null

/**
 * Deep-copy an arbitrary value into lossless JSON. Tool outputs are validated as
 * lossless JSON by the registry, so functions, symbols, nested `undefined`,
 * cyclic objects and non-finite numbers must never escape a tool. Also used for
 * defensive projection of runtime objects that embed capability implementations.
 * @param {unknown} value
 * @param {number} [depth]
 * @param {WeakSet<object>} [seen]
 * @returns {unknown}
 */
export function toLosslessJson(value, depth = 0, seen = new WeakSet()) {
  if (value === null) return null
  const kind = typeof value
  if (kind === 'string' || kind === 'boolean') return value
  if (kind === 'number') return Number.isFinite(value) ? value : String(value)
  if (kind === 'bigint') return value.toString()
  if (kind === 'undefined' || kind === 'function' || kind === 'symbol') return undefined
  if (kind !== 'object') return String(value)
  if (depth > 12) return '[depth-limit]'
  if (value instanceof Date) return value.toISOString()
  if (ArrayBuffer.isView(value)) return { type: 'bytes', length: value.byteLength }
  if (seen.has(value)) return '[circular]'
  seen.add(value)
  if (Array.isArray(value)) {
    return value.map((item) => {
      const next = toLosslessJson(item, depth + 1, seen)
      return next === undefined ? null : next
    })
  }
  /** @type {Record<string, unknown>} */
  const out = {}
  for (const [key, inner] of Object.entries(value)) {
    const next = toLosslessJson(inner, depth + 1, seen)
    if (next !== undefined) out[key] = next
  }
  return out
}

/**
 * Default `workspace` to the calling session's working directory before a tool
 * body runs, so the model does not have to repeat an absolute path in every
 * call. Falls back to the process workspace when no session service is mounted.
 * @param {any} args
 * @param {any} exec
 */
async function enrichArgs(args, exec) {
  const next = { ...(args && typeof args === 'object' ? args : {}) }
  if (!next.workspace && exec?.agent && pluginCtx) {
    try {
      const workingDirectory = typeof pluginCtx.get === 'function' ? pluginCtx.get('workingDirectory') : undefined
      if (workingDirectory && typeof workingDirectory.ensure === 'function') {
        const dir = await workingDirectory.ensure(exec.agent)
        if (typeof dir === 'string' && dir !== '') next.workspace = dir
      }
    } catch {
      /* no session working directory: keep the process-workspace fallback */
    }
  }
  return next
}

/** Canonical successful tool value schema. */
const OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    text: { type: 'string', description: 'Bounded Markdown summary for the model.' },
    data: { type: 'object', description: 'Structured result for programmatic callers.' },
  },
  required: ['text', 'data'],
  additionalProperties: false,
}

/**
 * Build one registered ToolDefinition from a small declarative shape.
 * @param {{name: string, description: string, parameters: object, run: (args: any, exec: any) => Promise<{text: string, data?: object}>}} spec
 */
function tool(spec) {
  return {
    name: spec.name,
    description: spec.description,
    parameters: spec.parameters,
    timeoutMs: 5 * 60 * 1000,
    output: {
      schema: OUTPUT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: String(/** @type {any} */ (value)?.text ?? '') }],
    },
    async execute(args, exec) {
      const enriched = await enrichArgs(args, exec)
      try {
        const sessionId = exec?.sessionId ?? exec?.agent?.sessionId ?? exec?.agent?.id
        if (sessionId) {
          const runtime = getRuntime()
          runtime.recordSessionWorkspace(String(sessionId), workspaceOf(runtime, enriched))
        }
      } catch {
        /* session binding is best-effort; never fail a tool because of it */
      }
      const result = await spec.run(enriched, exec)
      return { text: limitText(result.text), data: (toLosslessJson(result.data ?? {}) ?? {}) }
    },
  }
}

/** @param {string} text @param {number} [max] */
function limitText(text, max = 12000) {
  const value = String(text ?? '')
  return value.length > max ? `${value.slice(0, max)}\n\n…[summary truncated at ${max} chars; use the structured data or armorbreak_evidence for details]` : value
}

/** @param {string} value */
function md(value) {
  return String(value ?? '').replace(/\r?\n/g, ' ').slice(0, 300)
}

/**
 * Platform approval bridge: returns a closure the runner calls for L1/L2 gates.
 * @param {any} ctx
 * @param {any} exec
 */
function approvalBridge(ctx, exec) {
  return async ({ riskLevel, target, reason }) => {
    let approval
    try {
      approval = typeof ctx.get === 'function' ? ctx.get('approval') : undefined
    } catch {
      approval = undefined
    }
    if (!approval || typeof approval.request !== 'function' || !exec?.agent) return 'unavailable'
    try {
      return await approval.request({
        agent: exec.agent,
        toolName: 'armorbreak',
        callId: exec.callId,
        reason: `[ArmorBreak ${riskLevel}] ${reason}\nTarget: ${target}`,
        signal: exec.signal,
      })
    } catch {
      return 'unavailable'
    }
  }
}

/**
 * Activation helper: activation of a pending authorization request requires the
 * platform approval service to answer allowed-once. Unavailable service means
 * fail-closed: no active authorization is created.
 * @param {any} ctx
 * @param {any} exec
 * @param {{requestId: string, target: string, purpose: string}} input
 */
async function activateWithPlatformApproval(ctx, exec, input) {
  const bridge = approvalBridge(ctx, exec)
  const outcome = await bridge({
    riskLevel: 'L2',
    target: input.target,
    reason: `authorization request ${input.requestId}: ${input.purpose}`,
  })
  if (outcome !== 'allowed-once') {
    throw new Error(`平台审批未通过（${outcome}）；授权申请保持 pending，未创建有效授权。`)
  }
  const runtime = getRuntime()
  const activationId = `authz:${input.requestId}`
  const token = runtime.approvalAuthority?.issue({
    id: activationId,
    riskLevel: 'L2',
    taskId: input.requestId,
    target: 'authorization-request',
    operator: 'platform-approval',
  }).token ?? null
  return { approvalSource: 'platform-approval', approvedBy: 'platform-approval', approvalId: activationId, approvalToken: token, operator: 'platform-approval', outcome }
}

/** @param {any} task */
function taskLine(task) {  return `任务 \`${task.id}\`「${md(task.title)}」状态 **${task.state}**${task.workflowId ? ` · 工作流 ${task.workflowId}` : ''} · 证据 ${task.stats?.evidence ?? 0} / 发现 ${task.stats?.findings ?? 0}`
}

/** @param {any} task @param {{max?: number}} [opts] */
function taskStepsTable(task, opts = {}) {
  const steps = (task.steps ?? []).slice(0, opts.max ?? 50)
  if (steps.length === 0) return '（无步骤）'
  const lines = ['| 步骤 | 能力 | 状态 | 耗时 | 结果 |', '|---|---|---|---|---|']
  for (const step of steps) {
    lines.push(`| ${step.id} | ${step.capabilityId} | ${step.status} | ${step.durationMs ? `${step.durationMs} ms` : '-'} | ${md(step.error ?? step.summary ?? '')} |`)
  }
  return lines.join('\n')
}

/** @param {Array<any>} findings */
function findingsText(findings) {
  if (findings.length === 0) return '没有记录到带证据的发现（这不等于目标安全）。'
  const lines = ['| 严重程度 | 标题 | 验证状态 | CWE | 位置 |', '|---|---|---|---|---|']
  for (const finding of findings.slice(0, 30)) {
    lines.push(`| ${finding.severity} | ${md(finding.title)} | ${finding.verification} | ${finding.cwe ?? '-'} | ${md(finding.target ?? '-')} |`)
  }
  if (findings.length > 30) lines.push(`\n…另有 ${findings.length - 30} 条，使用 armorbreak_evidence 查看。`)
  return lines.join('\n')
}

/** @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime @param {any} args */
function workspaceOf(runtime, args) {
  return runtime.resolveWorkspace(args.workspace ?? undefined)
}

/**
 * @param {import('./lib/core/runtime.js').ArmorBreakRuntime} runtime
 * @param {any} args
 */
async function loadTask(runtime, args) {
  if (!args.taskId) throw new Error('taskId is required; call armorbreak_task action=list to find it')
  const workspace = workspaceOf(runtime, args)
  const ctx = runtime.workspace(workspace)
  return { task: await ctx.taskStore.get(String(args.taskId)), ctx, workspace }
}

/**
 * Register every ArmorBreak tool on the preset's scoped tool registry.
 * @param {any} ctx Cordis preset-scope context
 */
export function apply(ctx) {
  pluginCtx = ctx
  const runtime = getRuntime()
  void runtime.init().catch(() => {})

  ctx.tools.register(
    tool({
      name: 'armorbreak_health',
      description:
        'Inspect the ArmorBreak environment before analysis: platform, DSH/profile facts, isolation provider, authorization state, and which external security tools are actually installed. Call this first when a task depends on a capability or tool you have not verified. Does not run any analysis and never touches the target.',
      parameters: {
        type: 'object',
        properties: {
          workspace: { type: 'string', description: 'Absolute workspace directory whose task store and policy to inspect. Defaults to the session working directory.' },
          probeVersions: { type: 'boolean', description: 'When true, run bounded `--version` probes for installed external tools (slower). Default false.' },
        },
        additionalProperties: false,
      },
      async run(args) {
        await runtime.init()
        const workspace = workspaceOf(runtime, args)
        const state = await runtime.stateSummary(workspace)
        const tools = args.probeVersions === true ? await runtime.health.toolMatrix() : null
        const found = tools ? tools.filter((item) => item.found) : []
        const missing = tools ? tools.filter((item) => !item.found) : []
        const lines = [
          '# ArmorBreak 环境健康',
          '',
          `- 运行时：DSH ${state.environment.dshVersion} · ${state.environment.platform}/${state.environment.arch} · Node ${state.environment.node}`,
          `- Profile：${state.environment.profile ?? 'n/a'} · 工作区：\`${state.workspace}\``,
          `- 隔离提供者：${state.isolation.available ? `可用（${state.isolation.provider}）` : `不可用 — ${state.isolation.reason}`}`,
          `- 能力：${state.registry.capabilities} 个（域：${state.registry.domains.join(', ') || '无'}）`,
          `- 授权记录：${state.policy.authorizations.filter((item) => item.active).length} 个有效 / ${state.policy.authorizations.length} 个总计；审批记录：${state.policy.approvals.filter((item) => item.active).length} 个有效`,
          `- 任务：${state.tasks.length} 个（最近：${state.tasks.slice(0, 3).map((task) => `${task.id} ${task.state}`).join('；') || '无'}）`,
        ]
        if (state.registry.diagnostics.length > 0) {
          lines.push('', '**能力诊断**：')
          for (const diagnostic of state.registry.diagnostics.slice(0, 10)) lines.push(`- ${diagnostic.domain}: ${diagnostic.message}`)
        }
        if (tools) {
          lines.push('', `**外部工具**：已安装 ${found.length} / ${tools.length}`)
          for (const item of found) lines.push(`- ✅ ${item.name}${item.version ? ` — ${item.version}` : ''} — \`${item.path}\``)
          if (missing.length > 0) lines.push(`- 未安装：${missing.map((item) => item.name).join('、')}（内置纯 JS 能力仍可用）`)
        } else {
          lines.push('', '外部工具探测：未执行（probeVersions=false）。需要版本信息时传 probeVersions=true。')
        }
        lines.push('', '策略：L0 离线只读分析默认允许（工作区内）；L1 动态分析需要隔离提供者 + 平台审批；L2 主动测试需要授权目标 + 平台审批；L3 始终拒绝。')
        return { text: lines.join('\n'), data: state }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_capabilities',
      description:
        'Discover the real analysis capabilities this mode can execute: ids, domain, risk level, required external tools and their install status. Call before armorbreak_analyze or armorbreak_workflow to avoid claiming a capability that is not registered here. With no arguments returns the grouped catalog.',
      parameters: {
        type: 'object',
        properties: {
          domain: { type: 'string', description: 'Filter by domain: binary, forensics, android, network, web, sast, ctf, live.' },
          capability: { type: 'string', description: 'Exact capability id (for example binary.identify) to describe in detail.' },
          probeDependencies: { type: 'boolean', description: 'Probe declared external tools for version/path status. Default false.' },
        },
        additionalProperties: false,
      },
      async run(args) {
        await runtime.init()
        if (args.capability) {
          const capability = runtime.registry.get(String(args.capability))
          if (!capability) throw new Error(`unknown capability "${args.capability}"; available: ${runtime.registry.list().map((item) => item.id).join(', ')}`)
          const descriptor = await runtime.registry.describe(capability, { probe: args.probeDependencies === true })
          const lines = [
            `## ${descriptor.id} — ${descriptor.title}`,
            '',
            descriptor.description,
            '',
            `- 域：${descriptor.domain}`,
            `- 风险级别：${descriptor.riskLevel}（${riskHelp(descriptor.riskLevel)}）`,
            `- 目标类型：${descriptor.targetKind}`,
          ]
          if (descriptor.externalTools.length > 0) {
            lines.push('', '**外部工具（可选）**：')
            for (const external of descriptor.externalTools) {
              lines.push(`- ${external.found ? `✅ ${external.name}${external.version ? ` ${external.version}` : ''}` : `❌ ${external.name} 未安装 — ${external.install?.[process.platform === 'win32' ? 'windows' : 'unix'] ?? ''}（替代：${external.alternative ?? '无'}）`}`)
            }
          }
          lines.push('', '参数 schema：```json\n' + JSON.stringify(descriptor.params, null, 2) + '\n```')
          return { text: lines.join('\n'), data: descriptor }
        }
        const capabilities = runtime.registry.list(args.domain ? { domain: String(args.domain) } : {})
        if (capabilities.length === 0) {
          return { text: `没有匹配的能力。已加载域：${runtime.registry.domainsList().join(', ') || '无'}。若为空，检查 \`armorbreak_health\` 的能力诊断。`, data: runtime.registry.diagnosticsReport() }
        }
        const lines = ['# ArmorBreak 能力目录', '']
        const byDomain = new Map()
        for (const capability of capabilities) {
          const list = byDomain.get(capability.domain) ?? []
          list.push(capability)
          byDomain.set(capability.domain, list)
        }
        for (const [domain, list] of [...byDomain.entries()].sort()) {
          lines.push(`## ${domain}`)
          for (const capability of list) {
            lines.push(`- \`${capability.id}\` [${capability.riskLevel}] ${capability.title} — ${capability.description}`)
          }
          lines.push('')
        }
        if (runtime.registry.diagnostics.length > 0) {
          lines.push('**加载诊断**：')
          for (const diagnostic of runtime.registry.diagnostics.slice(0, 10)) lines.push(`- ${diagnostic.domain}: ${diagnostic.message}`)
        }
        lines.push(`共 ${capabilities.length} 个能力。执行入口：\`armorbreak_analyze\`（单能力）或 \`armorbreak_workflow\`（多步骤）。`)
        return { text: lines.join('\n'), data: { capabilities: capabilities.map((capability) => ({ id: capability.id, domain: capability.domain, title: capability.title, riskLevel: capability.riskLevel, externalTools: capability.externalTools ?? [] })) } }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_scope',
      description:
        'Manage scope in two separated steps. (1) action=request records what you propose to study: purpose, operator, paths and/or network targets. It grants nothing. (2) action=activate activates a pending request ONLY after the platform asks the human and gets an allowed-once grant; the approval identity is stored in the authorization. Use action=list to inspect, action=revoke to revoke. Never claim that chat text or a request is a human authorization. Offline analysis inside the task workspace needs no scope record; outside paths, L1 execution and L2 probes always need an activated authorization.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'request', 'activate', 'revoke'], description: 'list scope/requests; request a new authorization (not active); activate a pending request via platform approval; revoke an authorization or request by id.' },
          purpose: { type: 'string', description: 'request: what is being researched and why (>= 4 chars). Required with operator.' },
          operator: { type: 'string', description: 'request: the human/team requesting authorization (>= 2 chars).' },
          paths: { type: 'array', items: { type: 'string' }, description: 'request: absolute file/directory paths or prefixes allowed outside the task workspace.' },
          networkTargets: { type: 'array', items: { type: 'string' }, description: 'request: exact hosts, *.domain wildcards, IPs or CIDRs (optionally host:port) allowed for L2 active testing.' },
          riskCeiling: { type: 'string', enum: ['L0', 'L1', 'L2'], description: 'request: highest risk level this record permits. Default L2.' },
          ttlHours: { type: 'number', description: 'request: validity window in hours. Default 24.' },
          requestId: { type: 'string', description: 'activate/revoke: authorization request id from action=list.' },
          authorizationId: { type: 'string', description: 'revoke: exact authorization id from action=list.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      async run(args, exec) {
        const runtime = getRuntime()
        await runtime.init()
        const workspace = workspaceOf(runtime, args)
        const scope = runtime.workspace(workspace).scope
        if (args.action === 'authorize') {
          throw new Error('action=authorize 已移除：模型不能自行创建有效授权。请用 action=request 提交申请，再由平台向用户确认后 action=activate。')
        }
        if (args.action === 'request') {
          const request = await scope.requestAuthorization({
            purpose: String(args.purpose ?? ''),
            operator: String(args.operator ?? ''),
            paths: Array.isArray(args.paths) ? args.paths : [],
            networkTargets: Array.isArray(args.networkTargets) ? args.networkTargets : [],
            riskCeiling: args.riskCeiling ?? 'L2',
            ttlMs: Math.max(1, Math.min(Number(args.ttlHours ?? 24), 24 * 30)) * 60 * 60 * 1000,
          })
          const text = [
            '## 授权申请已登记（未生效）',
            '',
            `- 申请 ID：\`${request.id}\`（状态：${request.status}）`,
            `- 用途：${request.item.purpose}`,
            `- 申请人：${request.item.operator}`,
            `- 路径：${request.item.paths.join(', ') || '（无）'}`,
            `- 网络目标：${request.item.networkTargets.map((target) => target.host).join(', ') || '（无）'}`,
            `- 风险上限：${request.item.riskCeiling} · 申请有效期至 ${request.item.expiresAt}`,
            '',
            '该记录**不授予任何权限**。下一步：调用 action=activate 并传 requestId；平台会向用户展示范围并请求明确批准，只有 allowed-once 才会生成有效授权。',
          ].join('\n')
          return { text, data: request }
        }
        if (args.action === 'activate') {
          const requestId = String(args.requestId ?? '').trim()
          if (!requestId) throw new Error('activate needs requestId (from action=list or action=request)')
          const requests = await scope.listRequests()
          const request = requests.find((item) => item.id === requestId)
          if (!request) throw new Error(`authorization request not found: ${requestId}`)
          if (request.status !== 'pending') throw new Error(`authorization request ${requestId} is not pending (${request.status})`)
          const target = request.item.paths.join(', ') || request.item.networkTargets.map((item) => item.host).join(', ')
          const approval = await activateWithPlatformApproval(ctx, exec, { requestId, target, purpose: request.item.purpose })
          const record = await scope.activateAuthorization(requestId, approval)
          const text = [
            '## 授权已激活（平台审批记录在案）',
            '',
            `- 授权 ID：\`${record.id}\` · 来源申请：\`${requestId}\``,
            `- 操作者：${record.operator} · 审批来源：${record.approvalSource}`,
            `- 路径：${record.paths.join(', ') || '（无）'}`,
            `- 网络目标：${record.networkTargets.map((item) => item.host).join(', ') || '（无）'}`,
            `- 风险上限：${record.riskCeiling} · 至 ${record.expiresAt}`,
            '',
            '授权只授予范围；L1/L2 执行时仍会单独请求平台审批。',
          ].join('\n')
          return { text, data: record }
        }
        if (args.action === 'revoke') {
          if (args.requestId) {
            const request = await scope.revokeRequest(String(args.requestId))
            return { text: `已撤销授权申请 \`${request.id}\`。`, data: request }
          }
          const result = await scope.revoke(String(args.authorizationId ?? ''))
          return { text: `已撤销授权 \`${result.revoked}\`。`, data: result }
        }
        const snapshot = await scope.snapshot()
        const requests = await scope.listRequests()
        const lines = ['# 授权与审批状态', '']
        lines.push('**待处理申请**：')
        if (requests.length === 0) lines.push('- 无')
        for (const item of requests) lines.push(`- \`${item.id}\` ${item.status === 'pending' ? '🕓 待审批' : item.status} · ${item.item.purpose} · 路径 ${(item.item.paths ?? []).join(', ') || '-'} · 网络 ${(item.item.networkTargets ?? []).map((target) => target.host).join(', ') || '-'}`)
        lines.push('', '**有效授权**：')
        if (snapshot.authorizations.length === 0) lines.push('- 无')
        for (const item of snapshot.authorizations) {
          lines.push(`- \`${item.id}\` ${item.active ? '✅ 有效' : '⛔ 过期'} · ${item.purpose} · 操作者 ${item.operator} · 审批 ${item.approvalSource ?? 'legacy/internal'} · 上限 ${item.riskCeiling} · 路径 ${(item.paths ?? []).join(', ') || '-'} · 网络 ${(item.networkTargets ?? []).map((target) => target.host).join(', ') || '-'} · 至 ${item.expiresAt}`)
        }
        lines.push('', '**审批记录**：')
        if (snapshot.approvals.length === 0) lines.push('- 无（L1/L2 执行时会请求平台审批）')
        for (const item of snapshot.approvals) {
          lines.push(`- \`${item.id}\` ${item.active ? '✅ 有效' : '⛔ 失效'} · ${item.riskLevel} · 任务 ${item.taskId} · 目标 ${item.target} · 至 ${item.expiresAt}`)
        }
        return { text: lines.join('\n'), data: { ...snapshot, requests } }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_files',
      description:
        'Bounded, policy-gated read access to the current workspace or an activated authorized path. This is the only file-reading tool in strict ArmorBreak mode (generic fs/shell/web tools are not mounted), so use it to read reports, evidence, logs and source files. Actions: list a directory, read a bounded file, stat a path, or search text inside the workspace. Writes are not supported. Paths outside the workspace need an activated authorization and are denied by the same ScopePolicy as analysis.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'read', 'stat', 'search'], description: 'list: directory entries; read: bounded file content + hashes; stat: metadata; search: bounded regex search over text files.' },
          workspace: { type: 'string', description: 'Absolute workspace directory. Defaults to the session working directory.' },
          path: { type: 'string', description: 'Absolute file or directory path. Defaults to the workspace root for list/search.' },
          pattern: { type: 'string', description: 'search: JavaScript regular expression (case-insensitive), max 200 chars.' },
          maxBytes: { type: 'number', description: 'read: at most this many bytes (default 262144, max 262144).' },
          maxResults: { type: 'number', description: 'search: at most this many matches (default 50, max 50).' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      async run(args) {
        const runtime = getRuntime()
        await runtime.init()
        const workspace = workspaceOf(runtime, args)
        const scope = runtime.workspace(workspace).scope
        if (args.action === 'list') {
          const result = await listDirectory(scope, { workspaceRoot: workspace, path: args.path })
          if (!result.allowed) throw new Error(`${result.code}: ${result.reason}`)
          const lines = [`# 目录 \`${result.resolved}\``, '', `条目：${result.data.entries.length}${result.data.truncated ? '（已截断）' : ''}`]
          for (const entry of result.data.entries.slice(0, 80)) lines.push(`- ${entry.kind === 'directory' ? '📁' : entry.kind === 'symlink' ? '🔗' : '📄'} \`${entry.name}\``)
          return { text: lines.join('\n'), data: result }
        }
        if (args.action === 'read') {
          if (!args.path) throw new Error('read needs an absolute path')
          const result = await readFileBounded(scope, { workspaceRoot: workspace, path: args.path, maxBytes: args.maxBytes })
          if (!result.allowed) throw new Error(`${result.code}: ${result.reason}`)
          const excerpt = result.data.text === null ? null : limitText(result.data.text, 12000)
          const lines = [
            `# 文件 \`${result.data.path}\``,
            '',
            `- 大小：${result.data.totalBytes} 字节 · 已读：${result.data.analyzedBytes} 字节${result.data.truncated ? '（截断）' : ''}`,
            `- 哈希范围：${result.data.hashScope} · SHA-256：\`${result.data.analyzedRangeSha256}\``,
            `- 二进制：${result.data.binary ? '是' : '否'}`,
          ]
          if (excerpt !== null) lines.push('', '```', excerpt, '```')
          if (result.data.truncated) lines.push('', '内容已截断；需要其余部分时在分析工具中使用 offset/range 能力，或读取生成后的报告。')
          return { text: lines.join('\n'), data: { ...result.data, text: excerpt, fullTextSha256: result.data.analyzedRangeSha256 } }
        }
        if (args.action === 'stat') {
          if (!args.path) throw new Error('stat needs an absolute path')
          const result = await statPath(scope, { workspaceRoot: workspace, path: args.path })
          if (!result.allowed) throw new Error(`${result.code}: ${result.reason}`)
          return { text: `\`${result.data.path}\` · ${result.data.kind} · ${result.data.size} 字节 · mtime ${result.data.mtime}`, data: result.data }
        }
        const pattern = String(args.pattern ?? '').slice(0, 200)
        if (!pattern) throw new Error('search needs a pattern')
        const result = await searchFiles(scope, { workspaceRoot: workspace, path: args.path, pattern, maxResults: args.maxResults })
        if (!result.allowed) throw new Error(`${result.code}: ${result.reason}`)
        const lines = [`# 搜索 \`${result.data.pattern}\` in \`${result.data.root}\``, '', `匹配：${result.data.matches.length}（扫描 ${result.data.scannedFiles} 个文本文件${result.data.truncated ? '，已截断' : ''}）`]
        for (const match of result.data.matches.slice(0, 40)) lines.push(`- \`${match.file}:${match.line}\` — ${limitText(match.text, 240)}`)
        return { text: lines.join('\n'), data: result.data }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_task',
      description:
        'Create and manage durable analysis tasks. A task records the objective, target, authorization, workflow plan, step results, evidence and findings under <workspace>/.armorbreak/tasks/. Use it to keep one task per objective, inspect state, add notes, or finalize. Task ids are required by armorbreak_evidence and armorbreak_report.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['create', 'list', 'get', 'cancel', 'note', 'finalize'], description: 'Operation to perform.' },
          workspace: { type: 'string', description: 'Absolute workspace directory. Defaults to the session working directory; pass it explicitly when analyzing another directory.' },
          taskId: { type: 'string', description: 'Exact task id for get/cancel/note/finalize.' },
          title: { type: 'string', description: 'create: short human title for the objective.' },
          objective: { type: 'string', description: 'create: what question the task must answer and the expected output.' },
          targetPath: { type: 'string', description: 'create: absolute path of the artifact/directory to analyze.' },
          workflow: { type: 'string', description: 'create: optional workflow id (see armorbreak_workflow action=list). When set, the task plan is created from it.' },
          note: { type: 'string', description: 'note: durable note to append (assumptions, decisions, blockers).' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      async run(args) {
        const runtime = getRuntime()
        await runtime.init()
        const workspace = workspaceOf(runtime, args)
        const ctxRuntime = runtime.workspace(workspace)
        const store = ctxRuntime.taskStore
        if (args.action === 'create') {
          const workflow = args.workflow ? getWorkflow(String(args.workflow)) : null
          const targetPath = args.targetPath ? String(args.targetPath) : null
          const task = await store.create({
            title: String(args.title ?? (workflow ? workflow.title : 'Analysis task')),
            objective: String(args.objective ?? ''),
            workflowId: workflow?.id ?? null,
            targetPath,
            targetKind: workflow?.targetKind ?? (targetPath ? 'file' : 'none'),
            steps: workflow?.steps ?? [],
          })
          let scopeNote = ''
          if (targetPath) {
            const check = await ctxRuntime.scope.checkFile({ taskId: task.id, targetPath, workspaceRoot: workspace })
            scopeNote = check.allowed ? `范围检查：通过（${check.code}）` : `范围检查：**未通过**（${check.code}）— ${check.reason}`
          }
          const text = [
            '## 任务已创建',
            '',
            taskLine(task),
            `- 目标：\`${targetPath ?? '(待指定)'}\``,
            `- 计划步骤：${task.steps.length} 个${workflow ? `（工作流 ${workflow.id}）` : ''}`,
            scopeNote ? `- ${scopeNote}` : '- 范围检查：无文件目标，跳过',
            '',
            '下一步：`armorbreak_workflow action=run taskId=…` 或逐能力 `armorbreak_analyze taskId=…`。',
          ].join('\n')
          return { text, data: store.summary(task, { includeSteps: true }) }
        }
        if (args.action === 'list') {
          const tasks = await store.list(20)
          const lines = ['# 任务列表', '', `工作区：\`${workspace}\``, '']
          if (tasks.length === 0) lines.push('（无任务）')
          for (const task of tasks) lines.push(`- \`${task.id}\` **${task.state}** · ${md(task.title)} · 证据 ${task.stats.evidence} / 发现 ${task.stats.findings} · 更新 ${task.updatedAt}`)
          return { text: lines.join('\n'), data: { workspace, tasks: tasks.map((task) => store.summary(task)) } }
        }
        const { task } = await loadTask(runtime, args)
        if (args.action === 'get') {
          const findings = (await store.evidenceStore(task.id).readFindings()).findings
          const text = [
            '## ' + taskLine(task),
            '',
            `- 目标：\`${task.targetPath ?? '(none)'}\` · 工作区 \`${task.workspace}\``,
            `- 风险上限：${task.riskMax} · 创建 ${task.createdAt}`,
            task.objective ? `- 目标说明：${md(task.objective)}` : '',
            task.report ? `- 报告：\`${task.report.path}\`（${task.report.format}）` : '- 报告：未生成',
            '',
            '**步骤**',
            taskStepsTable(task),
            '',
            '**发现**',
            findingsText(findings),
          ].filter(Boolean).join('\n')
          return { text, data: { ...store.summary(task, { includeSteps: true }), findings } }
        }
        if (args.action === 'cancel') {
          await store.cancel(task, 'cancelled via armorbreak_task')
          return { text: `任务 \`${task.id}\` 已取消（证据与报告保留）。`, data: store.summary(task) }
        }
        if (args.action === 'note') {
          await store.addNote(task, String(args.note ?? ''))
          return { text: `已向任务 \`${task.id}\` 追加备注。`, data: store.summary(task) }
        }
        if (args.action === 'finalize') {
          const finalized = await runtime.runner.finalizeTask(task, { generateReport: true })
          return {
            text: `任务 \`${finalized.id}\` 已收尾：**${finalized.state}**。${finalized.report ? `报告：\`${finalized.report.path}\`` : '（未生成报告）'}`,
            data: store.summary(finalized, { includeSteps: true }),
          }
        }
        throw new Error(`unsupported action "${args.action}"`)
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_analyze',
      description:
        'Run one real analysis capability against one target and persist its evidence, findings and audit record. Capabilities are listed by armorbreak_capabilities; each has a risk level. L0 runs offline and automatically inside the task workspace; L1 (dynamic execution) and L2 (active network testing) additionally require an authorization plus the platform approval prompt — a denial is final and must not be retried through another tool. Analysis never executes the target sample.',
      parameters: {
        type: 'object',
        properties: {
          capability: { type: 'string', description: 'Exact capability id from armorbreak_capabilities (for example binary.identify, android.manifest, network.flows, sast.scan).' },
          target: { type: 'string', description: 'Absolute path of the file or directory to analyze. Required for file/directory capabilities; omit for network capabilities and pass options.url instead.' },
          workspace: { type: 'string', description: 'Absolute workspace directory for task/evidence storage. Defaults to the session working directory.' },
          options: { type: 'object', description: 'Capability-specific options. See the capability schema from armorbreak_capabilities.' },
          taskId: { type: 'string', description: 'Existing task to attach this execution to. Omit to create a new ad-hoc task automatically.' },
        },
        required: ['capability'],
        additionalProperties: false,
      },
      async run(args, exec) {
        const runtime = getRuntime()
        await runtime.init()
        const capabilityId = String(args.capability ?? '')
        const capability = runtime.registry.get(capabilityId)
        if (!capability) throw new Error(`unknown capability "${capabilityId}"; call armorbreak_capabilities for available ids`)
        let task
        let workspace
        if (args.taskId) {
          const loaded = await loadTask(runtime, args)
          task = loaded.task
          workspace = loaded.workspace
        } else {
          workspace = workspaceOf(runtime, args)
          const store = runtime.workspace(workspace).taskStore
          const targetKind = capability.targetKind ?? 'file'
          const targetPath = args.target ? String(args.target) : targetKind === 'file' || targetKind === 'directory' ? null : null
          task = await store.create({
            title: `${capability.title} — ${targetPath ? basename(targetPath) : capability.domain}`,
            objective: `Run ${capabilityId}${targetPath ? ` on ${targetPath}` : ''}`,
            workflowId: null,
            targetPath,
            targetKind,
            steps: [{ id: 'analyze', title: capability.title, capabilityId, options: args.options ?? {} }],
          })
        }
        const result = await runtime.runner.runCapability({
          task,
          capabilityId,
          targetPath: args.target ? String(args.target) : task.targetPath,
          options: args.options && typeof args.options === 'object' ? args.options : {},
          stepId: task.steps.find((step) => step.status === 'PENDING')?.id ?? null,
          requestApproval: approvalBridge(ctx, exec),
          signal: exec.signal,
        })
        let finalized = task
        if (!task.steps.some((step) => step.status === 'PENDING' || step.status === 'RUNNING')) {
          finalized = await runtime.runner.finalizeTask(task, { generateReport: true })
        }
        const lines = [
          `# ${capability.title}（\`${capability.id}\`）`,
          '',
          `- 任务：\`${task.id}\` → **${finalized.state}**${finalized.report ? ` · 报告 \`${finalized.report.path}\`` : ''}`,
          `- 目标：\`${result.target ?? '(none)'}\`${result.targetSha256 ? ` · SHA-256 \`${result.targetSha256.slice(0, 16)}…\`` : ''}`,
          `- 风险级别：${result.riskLevel} · 耗时 ${result.durationMs} ms · 证据 ${result.evidenceIds.length} 条`,
          '',
          result.summary,
        ]
        if (result.findings.length > 0) {
          lines.push('', '**发现**', findingsText(await runtime.workspace(workspace).taskStore.evidenceStore(task.id).readFindings().then((state) => state.findings)))
        }
        if (result.artifacts.length > 0) {
          lines.push('', '**产物**')
          for (const artifact of result.artifacts) lines.push(`- \`${artifact.path}\`（${artifact.contentType}）`)
        }
        return {
          text: lines.join('\n'),
          data: { ...result, task: runtime.workspace(workspace).taskStore.summary(finalized) },
        }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_workflow',
      description:
        'Start, run (sync or background), inspect, resume or cancel a reusable multi-step analysis workflow (BinaryStaticAnalysis, AndroidAPKReview, WebCodeSecurityReview, PCAPInvestigation, DependencyAudit, CTFArtifactAnalysis, ForensicFileReview, WebAPIReview, SecurityReportGeneration). Steps form a DAG: independent steps may run concurrently, dependents are skipped when a dependency fails, and retry/timeout/failure policy can be declared per step. Use action=run_async for long workflows so one model call does not block until completion, then action=status to poll. A failed step is preserved; evidence and a default report are kept.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'start', 'run', 'run_async', 'status', 'cancel', 'resume', 'retry'], description: 'list workflows; start creates a task; run executes synchronously; run_async executes in the background; status includes queue state; cancel aborts; resume recovers an interrupted task; retry resets failed/skipped steps and runs in the background.' },
          workflow: { type: 'string', description: 'start: workflow id from action=list (exact case).' },
          target: { type: 'string', description: 'start: absolute path of the file or directory to analyze (required unless the workflow needs no target).' },
          workspace: { type: 'string', description: 'Absolute workspace directory for task/evidence storage.' },
          taskId: { type: 'string', description: 'run/run_async/status/cancel/resume/retry: exact task id.' },
          title: { type: 'string', description: 'start: optional human title for the task.' },
          maxSteps: { type: 'number', description: 'run/run_async: maximum steps per execution window (1-50, default 50).' },
          concurrency: { type: 'number', description: 'run/run_async/retry: maximum independent steps (or none) executed concurrently, 1-4. Default 1 for synchronous run, 2 for background.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      async run(args, exec) {
        const runtime = getRuntime()
        await runtime.init()
        if (args.action === 'list') {
          const workflows = listWorkflows()
          const lines = ['# ArmorBreak 工作流', '']
          for (const workflow of workflows) lines.push(`- \`${workflow.id}\` — ${workflow.title}（${workflow.steps} 步，目标 ${workflow.targetKind}）：${workflow.description}`)
          return { text: lines.join('\n'), data: { workflows } }
        }
        if (args.action === 'start') {
          const workflow = getWorkflow(String(args.workflow ?? ''))
          const workspace = workspaceOf(runtime, args)
          const store = runtime.workspace(workspace).taskStore
          const target = args.target ? String(args.target) : null
          if (workflow.targetKind !== 'none' && !target) throw new Error(`workflow ${workflow.id} needs an absolute target path`)
          const task = await store.create({
            title: String(args.title ?? `${workflow.title} — ${target ? basename(target) : 'report'}`),
            objective: workflow.description,
            workflowId: workflow.id,
            targetPath: target,
            targetKind: workflow.targetKind,
            steps: workflow.steps,
          })
          await runtime.runner.prepareTask(task, { requestApproval: approvalBridge(ctx, exec), approvalTarget: target, signal: exec.signal })
          const text = [
            '## 工作流已启动',
            '',
            taskLine(task),
            `- 目标：\`${target ?? '(none)'}\` · 风险上限 ${task.riskMax}`,
            '- 计划：',
            ...task.steps.map((step, index) => `  ${index + 1}. \`${step.capabilityId}\` — ${step.title}`),
            '',
            '下一步：',
            `- 同步执行：\`armorbreak_workflow action=run taskId=${task.id}\`（受单次工具超时约束）`,
            `- 后台执行：\`armorbreak_workflow action=run_async taskId=${task.id}\`，随后用 action=status 轮询。`,
          ].join('\n')
          return { text, data: store.summary(task, { includeSteps: true }) }
        }
        const { task, workspace } = await loadTask(runtime, args)
        const store = runtime.workspace(workspace).taskStore
        if (args.action === 'cancel') {
          const result = await runtime.queue.cancel(task.id, { reason: 'cancelled via armorbreak_workflow' })
          return { text: `工作流任务 \`${task.id}\` 已取消（queue: ${result.queueState ?? 'n/a'}）。`, data: { ...store.summary(await store.get(task.id).catch(() => task)), queue: runtime.queue.status(task.id) } }
        }
        if (args.action === 'run_async') {
          const concurrency = Math.max(1, Math.min(Number(args.concurrency ?? 2), 4))
          if (!['EXECUTING', 'COLLECTING_EVIDENCE'].includes(task.state)) {
            await runtime.runner.prepareTask(task, { requestApproval: approvalBridge(ctx, exec), approvalTarget: task.targetPath, signal: exec.signal })
          }
          await runtime.queue.start(task, {
            requestApproval: approvalBridge(ctx, exec),
            maxSteps: Math.max(1, Math.min(Number(args.maxSteps ?? 50), 50)),
            concurrency,
            signal: exec.signal,
          })
          const text = [
            `## 工作流已在后台启动：${taskLine(task)}`,
            '',
            '后台队列使用进程内租约；L0 工作流可安全异步执行。L1/L2 步骤若在后台执行时无法获得当前会话的平台审批，会 fail-closed 记录失败，请在审批窗口内用同步 run。',
            '',
            `下一步：\`armorbreak_workflow action=status taskId=${task.id}\` 轮询；\`action=cancel\` 取消。`,
          ].join('\n')
          return { text, data: { summary: store.summary(task, { includeSteps: true }), queue: runtime.queue.status(task.id) } }
        }
        if (args.action === 'resume') {
          await runtime.queue.recover(workspace)
          const latest = await store.get(task.id)
          await runtime.queue.resume(latest, {
            requestApproval: approvalBridge(ctx, exec),
            maxSteps: Math.max(1, Math.min(Number(args.maxSteps ?? 50), 50)),
            concurrency: Math.max(1, Math.min(Number(args.concurrency ?? 2), 4)),
          })
          return { text: `已恢复任务 \`${task.id}\`（后台执行，状态 ${(await store.get(task.id)).state}）。`, data: runtime.queue.status(task.id) }
        }
        if (args.action === 'retry') {
          const latest = await store.get(task.id)
          await store.resetFailedSteps(latest)
          await runtime.queue.start(latest, {
            requestApproval: approvalBridge(ctx, exec),
            maxSteps: Math.max(1, Math.min(Number(args.maxSteps ?? 50), 50)),
            concurrency: Math.max(1, Math.min(Number(args.concurrency ?? 2), 4)),
          })
          return { text: `已重置失败/跳过步骤并提交后台重试：任务 \`${task.id}\`。`, data: runtime.queue.status(task.id) }
        }
        if (args.action === 'status') {
          return {
            text: [`## ${taskLine(task)}`, '', taskStepsTable(task), '', `后台队列：${runtime.queue.status(task.id) ? JSON.stringify(runtime.queue.status(task.id)) : '无活动/历史条目（进程重启后需 action=resume）'}`].join('\n'),
            data: { summary: store.summary(task, { includeSteps: true }), queue: runtime.queue.status(task.id) },
          }
        }
        if (args.action === 'run') {
          const maxSteps = Math.max(1, Math.min(Number(args.maxSteps ?? 50), 50))
          const updated = await runtime.runner.runWorkflow(task, {
            maxSteps,
            requestApproval: approvalBridge(ctx, exec),
            signal: exec.signal,
            generateReport: true,
            concurrency: Math.max(1, Math.min(Number(args.concurrency ?? 1), 4)),
          })
          const report = updated.report ? `报告：\`${updated.report.path}\`` : '报告：待全部步骤完成后生成'
          const text = [
            `## 工作流执行：${taskLine(updated)}`,
            '',
            taskStepsTable(updated),
            '',
            report,
          ].join('\n')
          return { text, data: store.summary(updated, { includeSteps: true }) }
        }
        throw new Error(`unsupported action "${args.action}"`)
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_evidence',
      description:
        'Read the evidence and findings of a task, verify a finding\'s verification status after corroboration, and check evidence/audit hash chains. Evidence excerpts are already redacted; cite evidence ids and target SHA-256 in conclusions. Findings are never auto-confirmed: change verification only when you have corroborating evidence.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['list', 'get', 'verify', 'chain'], description: 'list evidence and findings; get one finding or evidence record; verify sets a finding status; chain validates the evidence and audit hash chains.' },
          workspace: { type: 'string', description: 'Absolute workspace directory. Defaults to the session working directory.' },
          taskId: { type: 'string', description: 'Exact task id.' },
          limit: { type: 'number', description: 'list: maximum findings/evidence to print (default 30).' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], description: 'list: filter findings by severity.' },
          findingId: { type: 'string', description: 'get/verify: exact finding id.' },
          evidenceId: { type: 'string', description: 'get: exact evidence id.' },
          verification: { type: 'string', enum: ['observed', 'corroborated', 'hypothesis', 'unverified'], description: 'verify: new verification level, justified by the evidence you cite in note.' },
          note: { type: 'string', description: 'verify: why the status changed and what evidence supports it.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      async run(args) {
        const runtime = getRuntime()
        await runtime.init()
        const { task, ctx: workspaceCtx } = await loadTask(runtime, args)
        const evidenceStore = workspaceCtx.taskStore.evidenceStore(task.id)
        if (args.action === 'chain') {
          const [evidenceChain, auditChain] = await Promise.all([evidenceStore.verifyChain(), workspaceCtx.audit.verify()])
          const text = [
            `## 证据链（任务 ${task.id}）`,
            '',
            `- 证据链：${evidenceChain.valid ? '✅ 通过' : `❌ 损坏（第 ${evidenceChain.brokenAt} 条）`} · ${evidenceChain.records} 条记录`,
            `- 审计链：${auditChain.valid ? '✅ 通过' : `❌ 损坏（第 ${auditChain.brokenAt} 条）`} · ${auditChain.records} 条记录`,
          ].join('\n')
          return { text, data: { evidence: evidenceChain, audit: auditChain } }
        }
        if (args.action === 'get') {
          if (args.findingId) {
            const { findings } = await evidenceStore.readFindings()
            const finding = findings.find((item) => item.id === args.findingId)
            if (!finding) throw new Error(`finding not found: ${args.findingId}`)
            return { text: `## ${finding.title}\n\n\`\`\`json\n${JSON.stringify(finding, null, 2).slice(0, 6000)}\n\`\`\``, data: finding }
          }
          if (args.evidenceId) {
            const evidence = await evidenceStore.readEvidence(10000)
            const record = evidence.find((item) => item.id === args.evidenceId)
            if (!record) throw new Error(`evidence not found: ${args.evidenceId}`)
            return { text: `## ${record.title}\n\n- 类型：${record.kind} · 目标哈希：${record.targetSha256 ?? '-'} · 时间：${record.at}\n\n\`\`\`\n${record.excerpt}\n\`\`\``, data: record }
          }
          throw new Error('get needs findingId or evidenceId')
        }
        if (args.action === 'verify') {
          if (!args.findingId) throw new Error('verify needs findingId')
          const updated = await evidenceStore.verifyFinding(String(args.findingId), {
            verification: args.verification,
            severity: args.severity,
            note: args.note,
          })
          return { text: `发现 \`${updated.id}\` 验证状态更新为 **${updated.verification}**。`, data: updated }
        }
        const [evidence, findingsState] = await Promise.all([evidenceStore.readEvidence(500), evidenceStore.readFindings()])
        let findings = findingsState.findings
        if (args.severity) findings = findings.filter((item) => item.severity === String(args.severity))
        const limit = Math.max(1, Math.min(Number(args.limit ?? 30), 100))
        const lines = [`# 任务证据与发现 \`${task.id}\``, '', taskLine(task), '', '**发现**', findingsText(findings.slice(0, limit)), '', '**证据**']
        if (evidence.length === 0) lines.push('（无）')
        for (const record of evidence.slice(-limit)) {
          lines.push(`- \`${record.id}\` [${record.kind}] ${md(record.title)} — ${md(record.excerpt).slice(0, 160)}${record.targetSha256 ? ` · sha256 ${record.targetSha256.slice(0, 12)}…` : ''}`)
        }
        lines.push('', '使用 `armorbreak_evidence action=chain` 校验哈希链；`action=get findingId=…` 查看完整发现。')
        return { text: limitText(lines.join('\n')), data: { findings, evidence, task: workspaceCtx.taskStore.summary(task) } }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_report',
      description:
        'Generate a security report from a task\'s durable evidence, findings and audit chain: markdown (default), html, json, sarif, or pdf (pdf requires LibreOffice and fails with install guidance when absent). The report contains findings with verification status, evidence ids, target SHA-256, authorization/approval records, reproducibility conditions and residual uncertainty. Existing reports are never overwritten in place; each call writes a new timestamped file.',
      parameters: {
        type: 'object',
        properties: {
          taskId: { type: 'string', description: 'Exact task id to report on.' },
          format: { type: 'string', enum: ['markdown', 'html', 'json', 'sarif', 'pdf'], description: 'Report format. Default markdown.' },
          workspace: { type: 'string', description: 'Absolute workspace directory. Defaults to the session working directory.' },
        },
        required: ['taskId'],
        additionalProperties: false,
      },
      async run(args) {
        const runtime = getRuntime()
        await runtime.init()
        const { task, ctx: workspaceCtx } = await loadTask(runtime, args)
        const format = String(args.format ?? 'markdown')
        const report = await generateTaskReport(runtime, task, { format: format === 'md' ? 'markdown' : format })
        if (!['COMPLETED', 'PARTIAL_SUCCESS', 'FAILED', 'REJECTED', 'CANCELLED', 'TIMED_OUT'].includes(task.state)) {
          if (task.state === 'VERIFYING') {
            await workspaceCtx.taskStore.transition(task, 'REPORTING', 'report requested')
          }
        }
        task.report = { format: report.format, path: report.path, sha256: report.sha256, at: report.generatedAt }
        await workspaceCtx.taskStore.save(task)
        await workspaceCtx.taskStore.addNote(task, `report generated: ${report.path}`)
        const lines = [
          '## 报告已生成',
          '',
          `- 格式：**${report.format}** · ${report.bytes} 字节`,
          `- 路径：\`${report.path}\``,
          `- SHA-256：\`${report.sha256}\``,
          `- 任务：\`${task.id}\`（${task.state}）`,
          '',
          '报告包含：摘要、授权/审批记录、任务状态轨迹、带验证状态的发现、证据附录（含哈希）、审计记录（脱敏）、复现条件与限制。',
        ]
        if (format === 'pdf') lines.push('PDF 由 LibreOffice 转换；如失败请改用 html。')
        return { text: lines.join('\n'), data: report }
      },
    }),
  )

  ctx.tools.register(
    tool({
      name: 'armorbreak_environment',
      description:
        'Diagnose isolated-execution providers (Docker, Podman, WSL2) without enabling or installing them: CLI presence, daemon usability, self-test status, recommended provider and installation guidance. Detection is not isolation: only a successful self-test yields IsolationVerified, and WSL2 is not treated as a security sandbox. Use this instead of assuming a container runtime is usable.',
      parameters: {
        type: 'object',
        properties: {
          action: { type: 'string', enum: ['diagnose', 'providers', 'verify', 'installation_guide'], description: 'diagnose: all providers with recommended/L1 status; providers: same provider matrix; verify: run the injected self-test for one provider; installation_guide: official install links.' },
          provider: { type: 'string', enum: ['docker', 'podman', 'wsl2'], description: 'verify/installation_guide: provider id.' },
          fresh: { type: 'boolean', description: 'diagnose: bypass the in-process probe cache. Default false.' },
        },
        required: ['action'],
        additionalProperties: false,
      },
      async run(args) {
        const runtime = getRuntime()
        await runtime.init()
        const manager = runtime.isolationProviders
        if (args.action === 'installation_guide') {
          const guides = manager.installationGuide(args.provider)
          return {
            text: ['# 隔离提供者安装指引', '', ...guides.map((guide) => `- **${guide.title}**（${guide.isolation}）：${guide.installUrl}${guide.note ? ` — ${guide.note}` : ''}`), '', '安装后仍需 daemon 可用 + 自检通过，才可能获得 L1 执行许可；WSL2 默认不作为安全沙箱。'].join('\n'),
            data: { guides },
          }
        }
        if (args.action === 'verify') {
          if (!args.provider) throw new Error('verify needs provider (docker/podman/wsl2)')
          const result = await manager.selfTest(String(args.provider))
          return {
            text: `隔离自检（${result.provider}）：${result.verified ? '✅ 通过' : '⛔ 未通过'} — ${result.reason}`,
            data: result,
          }
        }
        const diagnosis = await manager.diagnose({ fresh: args.fresh === true })
        const lines = ['# 隔离提供者诊断', '']
        for (const provider of diagnosis.providers) {
          lines.push(`- **${provider.title}**：${provider.state} — ${provider.reason}${provider.version ? `（${provider.version}）` : ''}`)
        }
        lines.push('', `建议提供者：${diagnosis.recommended ?? '无'}`, `L1 状态：${diagnosis.l1.available ? '可用（已自检）' : `未就绪（${diagnosis.l1.state}）`} — ${diagnosis.l1.reason}`, '', diagnosis.wsl2Note)
        return { text: lines.join('\n'), data: diagnosis }
      },
    }),
  )
}
function riskHelp(level) {
  if (level === 'L0') return '离线只读分析，工作区内默认允许'
  if (level === 'L1') return '本地动态分析：需要隔离提供者 + 平台审批'
  if (level === 'L2') return '授权目标主动测试：需要授权 + 平台审批 + 速率限制'
  return '破坏/泄露/持久化操作：始终拒绝'
}

export { POLICY_TOOL_DOC }

export default { inject, apply }
