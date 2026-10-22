/** Provider HTTP client (P3 slice). Tests use local mock servers; no paid API calls. */
function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function messageText(messages) {
  if (!Array.isArray(messages) || messages.length === 0) throw fail('REQUEST_INVALID', 'messages are required')
  return messages.map((message) => {
    if (!message || typeof message.role !== 'string' || typeof message.content !== 'string') throw fail('REQUEST_INVALID', 'each message needs role/content strings')
    return { role: message.role, content: message.content }
  })
}

function normalizedUsage(raw) {
  if (!raw || typeof raw !== 'object') return null
  const inputTokens = Number(raw.inputTokens ?? raw.prompt_tokens ?? raw.input_tokens ?? 0)
  const outputTokens = Number(raw.outputTokens ?? raw.completion_tokens ?? raw.output_tokens ?? 0)
  const totalTokens = Number(raw.totalTokens ?? raw.total_tokens ?? inputTokens + outputTokens)
  return { inputTokens, outputTokens, totalTokens }
}

export class ProviderClient {
  constructor({ router, env = process.env, fetchImpl = globalThis.fetch } = {}) {
    if (!router) throw fail('CLIENT_INVALID', 'router is required')
    if (typeof fetchImpl !== 'function') throw fail('CLIENT_INVALID', 'fetch is unavailable')
    this.router = router
    this.env = env
    this.fetchImpl = fetchImpl
  }

  async chat({ model, messages, tools = [], maxTokens = 1024, signal } = {}) {
    const route = this.router.resolve({ model, requireTools: tools.length > 0 })
    const msgs = messageText(messages)
    if (!Number.isInteger(maxTokens) || maxTokens < 1 || maxTokens > 32768) throw fail('REQUEST_INVALID', 'maxTokens must be 1..32768')
    const key = route.credentialEnv ? this.env[route.credentialEnv] : null
    if (route.credentialEnv && !key) throw fail('KEY_MISSING', `credential env ${route.credentialEnv} is missing`)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), route.timeoutMs)
    if (signal) {
      if (signal.aborted) controller.abort()
      else signal.addEventListener('abort', () => controller.abort(), { once: true })
    }
    try {
      const request = this.buildRequest(route, { messages: msgs, tools, maxTokens, key })
      const response = await this.fetchImpl(request.url, { method: 'POST', headers: request.headers, body: JSON.stringify(request.body), signal: controller.signal })
      if (!response.ok) throw fail(`PROVIDER_HTTP_${response.status}`, `provider ${route.providerId} returned HTTP ${response.status}`)
      const payload = await response.json()
      return { providerId: route.providerId, model: route.model, ...this.parseResponse(route, payload) }
    } catch (cause) {
      if (cause?.name === 'AbortError') throw fail('PROVIDER_TIMEOUT', `provider ${route.providerId} timed out`)
      throw cause
    } finally {
      clearTimeout(timer)
    }
  }

  buildRequest(route, { messages, tools, maxTokens, key }) {
    if (route.kind === 'anthropic') {
      const system = messages.filter((message) => message.role === 'system').map((message) => message.content).join('\n')
      const rest = messages.filter((message) => message.role !== 'system')
      return {
        url: `${route.baseUrl}/v1/messages`,
        headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
        body: {
          model: route.model, max_tokens: maxTokens, messages: rest,
          ...(system ? { system } : {}),
          ...(tools.length ? { tools: tools.map((tool) => ({ name: tool.name, description: tool.description, input_schema: tool.parameters ?? tool.inputSchema ?? {} })) } : {}),
        },
      }
    }
    return {
      url: `${route.baseUrl}/chat/completions`,
      headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
      body: { model: route.model, messages, max_tokens: maxTokens, ...(tools.length ? { tools } : {}) },
    }
  }

  parseResponse(route, payload) {
    if (route.kind === 'anthropic') {
      const text = (payload.content ?? []).filter((block) => block.type === 'text').map((block) => block.text).join('')
      const toolCalls = (payload.content ?? []).filter((block) => block.type === 'tool_use').map((block) => ({ id: block.id, name: block.name, arguments: block.input }))
      return { text, toolCalls, usage: normalizedUsage(payload.usage) }
    }
    const message = payload.choices?.[0]?.message ?? {}
    return {
      text: typeof message.content === 'string' ? message.content : '',
      toolCalls: (message.tool_calls ?? []).map((call) => ({ id: call.id, name: call.function?.name, arguments: call.function?.arguments })),
      usage: normalizedUsage(payload.usage),
    }
  }
}

export function createProviderClient(options) {
  return new ProviderClient(options)
}
