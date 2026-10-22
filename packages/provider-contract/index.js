/** Normalized provider message/tool/stream contracts (ABU-310). */
const ROLES = new Set(['system', 'user', 'assistant', 'tool'])
const FINISH = new Set(['stop', 'length', 'tool_calls', 'content_filter', 'error'])
const STREAM_TYPES = new Set(['message_start', 'content_delta', 'tool_call_delta', 'message_stop', 'error'])

function fail(message) { throw new Error(`provider contract: ${message}`) }
function nonEmpty(value, name) { if (typeof value !== 'string' || !value) fail(`${name} must be a non-empty string`); return value }

export function normalizeMessage(input) {
  if (!input || typeof input !== 'object') fail('message must be an object')
  if (!ROLES.has(input.role)) fail(`invalid role: ${input.role}`)
  if (typeof input.content !== 'string') fail('message.content must be a string')
  const message = { role: input.role, content: input.content }
  if (input.toolCallId !== undefined) message.toolCallId = nonEmpty(input.toolCallId, 'toolCallId')
  if (input.name !== undefined) message.name = nonEmpty(input.name, 'name')
  return message
}

export function normalizeToolCall(input) {
  if (!input || typeof input !== 'object') fail('tool call must be an object')
  return { id: nonEmpty(input.id, 'tool call id'), name: nonEmpty(input.name, 'tool name'), arguments: input.arguments ?? {} }
}

export function normalizeToolResult(input) {
  if (!input || typeof input !== 'object') fail('tool result must be an object')
  return { toolCallId: nonEmpty(input.toolCallId, 'toolCallId'), content: String(input.content ?? ''), isError: Boolean(input.isError) }
}

export function normalizeUsage(input = {}) {
  const value = { inputTokens: Number(input.inputTokens ?? 0), outputTokens: Number(input.outputTokens ?? 0) }
  if (!Number.isInteger(value.inputTokens) || value.inputTokens < 0) fail('inputTokens must be a non-negative integer')
  if (!Number.isInteger(value.outputTokens) || value.outputTokens < 0) fail('outputTokens must be a non-negative integer')
  value.totalTokens = Number(input.totalTokens ?? value.inputTokens + value.outputTokens)
  if (!Number.isInteger(value.totalTokens) || value.totalTokens < 0) fail('totalTokens must be a non-negative integer')
  return value
}

export function normalizeFinishReason(value) {
  if (!FINISH.has(value)) fail(`invalid finish reason: ${value}`)
  return value
}

export function normalizeStreamEvent(input) {
  if (!input || typeof input !== 'object') fail('stream event must be an object')
  if (!STREAM_TYPES.has(input.type)) fail(`invalid stream event: ${input.type}`)
  const event = { type: input.type }
  if (input.index !== undefined) {
    if (!Number.isInteger(input.index) || input.index < 0) fail('index must be a non-negative integer')
    event.index = input.index
  }
  if (input.delta !== undefined) event.delta = String(input.delta)
  if (input.toolCallId !== undefined) event.toolCallId = nonEmpty(input.toolCallId, 'toolCallId')
  if (input.finishReason !== undefined) event.finishReason = normalizeFinishReason(input.finishReason)
  return event
}

export function normalizeError(input) {
  if (!input || typeof input !== 'object') fail('error must be an object')
  return { code: nonEmpty(input.code, 'error code'), message: String(input.message ?? ''), retryable: Boolean(input.retryable) }
}
