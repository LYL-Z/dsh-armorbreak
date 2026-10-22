/**
 * @armorbreak/sdk-ts (JS implementation with .d.ts contract).
 * Supports direct TrustedEngine and MCP HTTP transports. Credentials are
 * supplied by the host; the model is never an authorization principal.
 */
export class ArmorBreakClient {
  /**
   * @param {{engine?: object, baseUrl?: string, token?: string, fetchImpl?: Function, principal?: object, workspaceId?: string}} options
   */
  constructor(options = {}) {
    if (!options.engine && !options.baseUrl) throw new Error('engine or baseUrl is required')
    if (options.engine && options.baseUrl) throw new Error('choose one transport: engine or baseUrl')
    this.engine = options.engine ?? null
    this.baseUrl = options.baseUrl ? String(options.baseUrl).replace(/\/$/, '') : null
    this.token = options.token ?? null
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch
    this.principal = options.principal ?? { id: 'sdk-local', kind: 'local-user' }
    this.workspaceId = options.workspaceId ?? process.cwd()
    this.initialized = false
    this.nextId = 1
  }

  context() {
    const id = this.nextId++
    return { principal: this.principal, workspaceId: this.workspaceId, requestId: `sdk-${id}`, traceId: `trace-${id}` }
  }

  async request(method, params = {}) {
    if (this.engine) {
      const ctx = this.context()
      if (method === 'health') return this.engine.health(ctx)
      if (method === 'capabilities') return this.engine.capabilities(ctx)
      if (method === 'analyze') return this.engine.analyze(ctx, params)
      if (method === 'task.get') return this.engine.getTask(ctx, params.taskId)
      if (method === 'task.list') return this.engine.listTasks(ctx)
      if (method === 'evidence') return this.engine.getEvidence(ctx, params.taskId)
      if (method === 'report') return this.engine.getReport(ctx, params.taskId)
      throw new Error(`unknown SDK method: ${method}`)
    }
    return this.httpRequest(method, params)
  }

  async httpRequest(method, params) {
    const tool = {
      health: 'armorbreak_health',
      capabilities: 'armorbreak_capabilities',
      analyze: 'armorbreak_analyze',
      'task.get': 'armorbreak_task_get',
      'task.list': 'armorbreak_task_list',
      evidence: 'armorbreak_evidence',
      report: 'armorbreak_report',
    }[method]
    if (!tool) throw new Error(`unknown SDK method: ${method}`)
    await this.ensureInitialized()
    const response = await this.rpc('tools/call', { name: tool, arguments: params })
    if (response.result?.isError) throw new Error(response.result.content?.[0]?.text ?? 'SDK tool call failed')
    const text = response.result?.content?.[0]?.text
    return text ? JSON.parse(text) : null
  }

  async ensureInitialized() {
    if (this.initialized) return
    await this.rpc('initialize', { protocolVersion: '2025-06-18' })
    this.initialized = true
  }

  async rpc(method, params) {
    const endpoint = this.baseUrl.endsWith('/mcp') ? this.baseUrl : `${this.baseUrl}/mcp`
    const response = await this.fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(this.token ? { authorization: `Bearer ${this.token}` } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id: this.nextId++, method, params }),
    })
    if (!response.ok) throw new Error(`MCP HTTP ${response.status}`)
    const body = await response.json()
    if (body.error) throw new Error(`${body.error.code}: ${body.error.message}`)
    return body
  }

  health() { return this.request('health') }
  capabilities() { return this.request('capabilities') }
  analyze(input) { return this.request('analyze', input) }
  task(taskId) { return this.request('task.get', { taskId }) }
  async tasks() { const result = await this.request('task.list'); return Array.isArray(result) ? result : (result?.tasks ?? []) }
  evidence(taskId) { return this.request('evidence', { taskId }) }
  report(taskId) { return this.request('report', { taskId }) }
}
