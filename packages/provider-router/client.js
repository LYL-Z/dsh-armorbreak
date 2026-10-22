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

  async chatStream({ model, messages, tools = [], maxTokens = 1024, signal } = {}) {
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
      request.body.stream = true
      if (route.kind !== 'anthropic') request.body.stream_options = { include_usage: true }
      const response = await this.fetchImpl(request.url, { method: 'POST', headers: request.headers, body: JSON.stringify(request.body), signal: controller.signal })
      if (!response.ok) throw fail(`PROVIDER_HTTP_${response.status}`, `provider ${route.providerId} returned HTTP ${response.status}`)
      if (!response.body || typeof response.body.getReader !== 'function') throw fail('STREAM_UNAVAILABLE', 'provider response has no readable body')
      return { providerId: route.providerId, model: route.model, ...(await this.parseStream(route, response.body)) }
    } catch (cause) {
      if (cause?.name === 'AbortError') throw fail('PROVIDER_TIMEOUT', `provider ${route.providerId} timed out`)
      throw cause
    } finally {
      clearTimeout(timer)
    }
  }

  async parseStream(route, body) {
    if (route.kind === 'anthropic') throw fail('STREAM_UNSUPPORTED', 'Anthropic streaming is not implemented in this slice')
    const reader = body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let text = ''
    let finishReason = null
    let usage = null
    let eventCount = 0
    const toolMap = new Map()
    const consume = (line) => {
      const trimmed = line.trim()
      if (!trimmed.startsWith('data:')) return
      const data = trimmed.slice(5).trim()
      if (!data || data === '[DONE]') return
      let event
      try { event = JSON.parse(data) } catch { return }
      eventCount += 1
      const choice = event.choices?.[0]
      if (choice?.delta?.content) text += choice.delta.content
      if (choice?.finish_reason) finishReason = choice.finish_reason
      for (const delta of choice?.delta?.tool_calls ?? []) {
        const index = delta.index ?? delta.id ?? toolMap.size
        const current = toolMap.get(index) ?? { id: '', name: '', arguments: '' }
        if (delta.id) current.id = delta.id
        if (delta.function?.name) current.name += delta.function.name
        if (delta.function?.arguments) current.arguments += delta.function.arguments
        toolMap.set(index, current)
      }
      if (event.usage) usage = normalizedUsage(event.usage)
    }
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let newline
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline).replace(/\r$/, '')
        buffer = buffer.slice(newline + 1)
        consume(line)
      }
    }
    buffer += decoder.decode()
    if (buffer.trim()) consume(buffer)
    const toolCalls = [...toolMap.values()].filter((call) => call.name).map((call) => {
      let parsed = call.arguments
      try { parsed = JSON.parse(call.arguments) } catch { /* keep string for local provider compatibility */ }
      return { id: call.id || `stream-${call.name}`, name: call.name, arguments: parsed }
    })
    return { text, toolCalls, usage, finishReason, eventCount }
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
