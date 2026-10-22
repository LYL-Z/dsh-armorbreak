/** Provider HTTP client: OpenAI Chat/Responses, Anthropic, Gemini native, Ollama/local. */
function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function messageText(messages) {
  if (!Array.isArray(messages) || messages.length === 0) throw fail('REQUEST_INVALID', 'messages are required')
  return messages.map((message) => {
    if (!message || typeof message.role !== 'string' || typeof message.content !== 'string') throw fail('REQUEST_INVALID', 'each message needs role/content strings')
    const next = { role: message.role, content: message.content }
    if (message.toolCallId !== undefined) next.toolCallId = message.toolCallId
    if (message.name !== undefined) next.name = message.name
    if (message.isError !== undefined) next.isError = Boolean(message.isError)
    if (Array.isArray(message.toolCalls)) next.toolCalls = message.toolCalls
    return next
  })
}

function normalizedUsage(raw) {
  if (!raw || typeof raw !== 'object') return null
  const inputTokens = Number(raw.inputTokens ?? raw.prompt_tokens ?? raw.input_tokens ?? raw.promptTokenCount ?? 0)
  const outputTokens = Number(raw.outputTokens ?? raw.completion_tokens ?? raw.output_tokens ?? raw.candidatesTokenCount ?? 0)
  const totalTokens = Number(raw.totalTokens ?? raw.total_tokens ?? raw.totalTokenCount ?? inputTokens + outputTokens)
  return { inputTokens, outputTokens, totalTokens }
}

function parseArguments(value) {
  if (typeof value !== 'string') return value ?? {}
  try { return JSON.parse(value) } catch { return value }
}

function openAIMessages(messages) {
  return messages.map((message) => {
    if (message.role === 'tool') return { role: 'tool', content: message.content, tool_call_id: message.toolCallId, name: message.name }
    if (message.role === 'assistant' && message.toolCalls?.length) {
      return {
        role: 'assistant',
        content: message.content,
        tool_calls: message.toolCalls.map((call) => ({ id: call.id, type: 'function', function: { name: call.name, arguments: typeof call.arguments === 'string' ? call.arguments : JSON.stringify(call.arguments ?? {}) } })),
      }
    }
    return { role: message.role, content: message.content }
  })
}

function anthropicMessages(messages) {
  const out = []
  for (const message of messages) {
    if (message.role === 'tool') {
      out.push({ role: 'user', content: [{ type: 'tool_result', tool_use_id: message.toolCallId, content: message.content, ...(message.isError ? { is_error: true } : {}) }] })
      continue
    }
    if (message.role === 'assistant' && message.toolCalls?.length) {
      out.push({ role: 'assistant', content: [{ type: 'text', text: message.content || '' }, ...message.toolCalls.map((call) => ({ type: 'tool_use', id: call.id, name: call.name, input: call.arguments ?? {} }))] })
      continue
    }
    out.push({ role: message.role, content: message.content })
  }
  return out
}

function responsesInput(messages) {
  const out = []
  for (const message of messages) {
    if (message.role === 'tool') { out.push({ type: 'function_call_output', call_id: message.toolCallId, output: message.content }); continue }
    if (message.role === 'assistant' && message.toolCalls?.length) {
      if (message.content) out.push({ role: 'assistant', content: [{ type: 'output_text', text: message.content }] })
      for (const call of message.toolCalls) out.push({ type: 'function_call', call_id: call.id, name: call.name, arguments: typeof call.arguments === 'string' ? call.arguments : JSON.stringify(call.arguments ?? {}) })
      continue
    }
    out.push({ role: message.role === 'system' ? 'system' : message.role, content: [{ type: message.role === 'assistant' ? 'output_text' : 'input_text', text: message.content }] })
  }
  return out
}

function geminiContents(messages) {
  const contents = []
  for (const message of messages) {
    if (message.role === 'system') continue
    if (message.role === 'tool') {
      contents.push({ role: 'user', parts: [{ functionResponse: { name: message.name, response: { content: message.content } } }] })
      continue
    }
    if (message.role === 'assistant' && message.toolCalls?.length) {
      contents.push({ role: 'model', parts: [...(message.content ? [{ text: message.content }] : []), ...message.toolCalls.map((call) => ({ functionCall: { name: call.name, args: call.arguments ?? {} } }))] })
      continue
    }
    contents.push({ role: message.role === 'assistant' ? 'model' : 'user', parts: [{ text: message.content }] })
  }
  return contents
}

function mapAnthropicStop(value) {
  if (value === 'tool_use') return 'tool_calls'
  if (value === 'max_tokens') return 'length'
  if (value === 'end_turn' || value === 'stop_sequence') return 'stop'
  return value ?? null
}

function mapGeminiFinish(value) {
  if (value === 'MAX_TOKENS') return 'length'
  if (value === 'SAFETY' || value === 'RECITATION') return 'content_filter'
  if (value === 'STOP') return 'stop'
  return value ?? null
}

async function readSse(body, onData) {
  const reader = body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let eventCount = 0
  const consume = (line) => {
    const trimmed = line.trim()
    if (!trimmed.startsWith('data:')) return
    const data = trimmed.slice(5).trim()
    if (!data || data === '[DONE]') return
    let event
    try { event = JSON.parse(data) } catch { return }
    eventCount += 1
    onData(event)
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
  return eventCount
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
      const request = this.buildRequest(route, { messages: msgs, tools, maxTokens, key, stream: false })
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
      const request = this.buildRequest(route, { messages: msgs, tools, maxTokens, key, stream: true })
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
    if (route.kind === 'anthropic') return this.parseAnthropicStream(body)
    if (route.kind === 'openai-responses') return this.parseResponsesStream(body)
    if (route.kind === 'gemini') return this.parseGeminiStream(body)
    return this.parseOpenAIStream(body)
  }

  async parseOpenAIStream(body) {
    let text = ''
    let finishReason = null
    let usage = null
    const toolMap = new Map()
    const eventCount = await readSse(body, (event) => {
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
    })
    const toolCalls = [...toolMap.values()].filter((call) => call.name).map((call) => ({ id: call.id || `stream-${call.name}`, name: call.name, arguments: parseArguments(call.arguments) }))
    return { text, toolCalls, usage, finishReason, eventCount }
  }

  async parseAnthropicStream(body) {
    let text = ''
    let finishReason = null
    let usage = null
    let inputTokens = 0
    let outputTokens = 0
    const blocks = new Map()
    const eventCount = await readSse(body, (event) => {
      if (event.type === 'message_start') inputTokens = Number(event.message?.usage?.input_tokens ?? 0)
      if (event.type === 'content_block_start' && event.content_block?.type === 'tool_use') {
        blocks.set(event.index, { id: event.content_block.id, name: event.content_block.name, arguments: '' })
      }
      if (event.type === 'content_block_delta') {
        if (event.delta?.type === 'text_delta') text += event.delta.text ?? ''
        if (event.delta?.type === 'input_json_delta') {
          const current = blocks.get(event.index)
          if (current) current.arguments += event.delta.partial_json ?? ''
        }
      }
      if (event.type === 'message_delta') {
        finishReason = mapAnthropicStop(event.delta?.stop_reason)
        outputTokens = Number(event.usage?.output_tokens ?? outputTokens)
      }
      if (event.usage) {
        inputTokens = Number(event.usage.input_tokens ?? inputTokens)
        outputTokens = Number(event.usage.output_tokens ?? outputTokens)
      }
    })
    usage = inputTokens || outputTokens ? { inputTokens, outputTokens, totalTokens: inputTokens + outputTokens } : null
    const toolCalls = [...blocks.values()].map((call) => ({ id: call.id, name: call.name, arguments: parseArguments(call.arguments) }))
    return { text, toolCalls, usage, finishReason, eventCount }
  }

  async parseResponsesStream(body) {
    let text = ''
    let finishReason = null
    let usage = null
    const items = new Map()
    const eventCount = await readSse(body, (event) => {
      if (event.type === 'response.output_text.delta') text += event.delta ?? ''
      if (event.type === 'response.output_item.added' && event.item?.type === 'function_call') {
        items.set(event.item.id ?? event.item.call_id, { id: event.item.call_id ?? event.item.id, name: event.item.name, arguments: '' })
      }
      if (event.type === 'response.function_call_arguments.delta') {
        const item = items.get(event.item_id) ?? items.get(event.call_id)
        if (item) item.arguments += event.delta ?? ''
      }
      if (event.type === 'response.output_item.done' && event.item?.type === 'function_call') {
        const item = items.get(event.item.id ?? event.item.call_id) ?? { id: event.item.call_id ?? event.item.id, name: event.item.name, arguments: '' }
        item.arguments = event.item.arguments ?? item.arguments
        item.name = event.item.name ?? item.name
        items.set(event.item.id ?? event.item.call_id, item)
      }
      if (event.type === 'response.completed') {
        usage = normalizedUsage(event.response?.usage)
        finishReason = 'stop'
      }
      if (event.type === 'response.failed' || event.type === 'error') throw fail('PROVIDER_STREAM_ERROR', event.response?.error?.message ?? event.message ?? 'provider stream failed')
    })
    const toolCalls = [...items.values()].filter((item) => item.name).map((item) => ({ id: item.id, name: item.name, arguments: parseArguments(item.arguments) }))
    return { text, toolCalls, usage, finishReason, eventCount }
  }

  async parseGeminiStream(body) {
    let text = ''
    let finishReason = null
    let usage = null
    const calls = []
    const eventCount = await readSse(body, (event) => {
      const candidate = event.candidates?.[0]
      for (const part of candidate?.content?.parts ?? []) {
        if (part.text) text += part.text
        if (part.functionCall) calls.push({ id: `gemini-${calls.length + 1}`, name: part.functionCall.name, arguments: part.functionCall.args ?? {} })
      }
      if (candidate?.finishReason) finishReason = mapGeminiFinish(candidate.finishReason)
      if (event.usageMetadata) usage = normalizedUsage(event.usageMetadata)
    })
    return { text, toolCalls: calls, usage, finishReason, eventCount }
  }

  buildRequest(route, { messages, tools, maxTokens, key, stream = false }) {
    if (route.kind === 'anthropic') {
      const system = messages.filter((message) => message.role === 'system').map((message) => message.content).join('\n')
      const rest = anthropicMessages(messages.filter((message) => message.role !== 'system'))
      return {
        url: `${route.baseUrl}/v1/messages`,
        headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
        body: {
          model: route.model, max_tokens: maxTokens, messages: rest,
          ...(system ? { system } : {}),
          ...(stream ? { stream: true } : {}),
          ...(tools.length ? { tools: tools.map((tool) => ({ name: tool.name, description: tool.description, input_schema: tool.parameters ?? tool.inputSchema ?? {} })) } : {}),
        },
      }
    }
    if (route.kind === 'openai-responses') {
      return {
        url: `${route.baseUrl}/responses`,
        headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
        body: {
          model: route.model, input: responsesInput(messages), max_output_tokens: maxTokens,
          ...(stream ? { stream: true } : {}),
          ...(tools.length ? { tools: tools.map((tool) => ({ type: 'function', name: tool.name, description: tool.description, parameters: tool.parameters ?? tool.inputSchema ?? {} })) } : {}),
        },
      }
    }
    if (route.kind === 'gemini') {
      const system = messages.filter((message) => message.role === 'system').map((message) => message.content).join('\n')
      return {
        url: `${route.baseUrl}/models/${encodeURIComponent(route.model)}:${stream ? 'streamGenerateContent?alt=sse' : 'generateContent'}`,
        headers: { 'content-type': 'application/json', 'x-goog-api-key': key },
        body: {
          contents: geminiContents(messages),
          ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
          ...(tools.length ? { tools: [{ functionDeclarations: tools.map((tool) => ({ name: tool.name, description: tool.description, parameters: tool.parameters ?? tool.inputSchema ?? {} })) }] } : {}),
          generationConfig: { maxOutputTokens: maxTokens },
        },
      }
    }
    return {
      url: `${route.baseUrl}/chat/completions`,
      headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
      body: {
        model: route.model, messages: openAIMessages(messages), max_tokens: maxTokens,
        ...(stream ? { stream: true, stream_options: { include_usage: true } } : {}),
        ...(tools.length ? { tools } : {}),
      },
    }
  }

  parseResponse(route, payload) {
    if (route.kind === 'anthropic') {
      const text = (payload.content ?? []).filter((block) => block.type === 'text').map((block) => block.text).join('')
      const toolCalls = (payload.content ?? []).filter((block) => block.type === 'tool_use').map((block) => ({ id: block.id, name: block.name, arguments: block.input }))
      return { text, toolCalls, usage: normalizedUsage(payload.usage), finishReason: mapAnthropicStop(payload.stop_reason) }
    }
    if (route.kind === 'openai-responses') {
      let text = ''
      const toolCalls = []
      for (const item of payload.output ?? []) {
        if (item.type === 'message') for (const part of item.content ?? []) if (part.type === 'output_text') text += part.text ?? ''
        if (item.type === 'function_call') toolCalls.push({ id: item.call_id ?? item.id, name: item.name, arguments: parseArguments(item.arguments) })
      }
      return { text, toolCalls, usage: normalizedUsage(payload.usage), finishReason: payload.status === 'incomplete' ? 'length' : 'stop' }
    }
    if (route.kind === 'gemini') {
      const candidate = payload.candidates?.[0]
      let text = ''
      const toolCalls = []
      for (const part of candidate?.content?.parts ?? []) {
        if (part.text) text += part.text
        if (part.functionCall) toolCalls.push({ id: `gemini-${toolCalls.length + 1}`, name: part.functionCall.name, arguments: part.functionCall.args ?? {} })
      }
      return { text, toolCalls, usage: normalizedUsage(payload.usageMetadata), finishReason: mapGeminiFinish(candidate?.finishReason) }
    }
    const message = payload.choices?.[0]?.message ?? {}
    return {
      text: typeof message.content === 'string' ? message.content : '',
      toolCalls: (message.tool_calls ?? []).map((call) => ({ id: call.id, name: call.function?.name, arguments: parseArguments(call.function?.arguments) })),
      usage: normalizedUsage(payload.usage),
      finishReason: payload.choices?.[0]?.finish_reason ?? null,
    }
  }
}

export function createProviderClient(options) {
  return new ProviderClient(options)
}
