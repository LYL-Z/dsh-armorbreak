/** Bounded provider tool loop (ABU-316 slice). */
import { normalizeUsage } from '../provider-contract/index.js'

function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function isRetryable(error) {
  if (error?.retryable === true) return true
  const status = Number(error?.status ?? 0)
  return status === 429 || status >= 500
}

export async function runToolLoop({
  client, model, messages, tools = [], executeTool,
  maxTurns = 4, maxRetries = 2, budgetTokens = null, deadline = null,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  if (!client || typeof client.chat !== 'function') throw fail('LOOP_INVALID', 'client.chat is required')
  if (!Array.isArray(messages) || messages.length === 0) throw fail('LOOP_INVALID', 'messages are required')
  if (typeof executeTool !== 'function') throw fail('LOOP_INVALID', 'executeTool is required')
  if (!Number.isInteger(maxTurns) || maxTurns < 1 || maxTurns > 32) throw fail('LOOP_INVALID', 'maxTurns must be 1..32')
  if (budgetTokens !== null && (!Number.isInteger(budgetTokens) || budgetTokens < 1)) throw fail('LOOP_INVALID', 'budgetTokens must be a positive integer')
  const working = messages.map((message) => ({ ...message }))
  const usage = normalizeUsage({})
  let turns = 0
  while (turns < maxTurns) {
    if (deadline !== null && Date.now() > Date.parse(deadline)) throw fail('DEADLINE', 'tool loop deadline exceeded')
    turns += 1
    let response
    for (let attempt = 0; ; attempt += 1) {
      try {
        response = await client.chat({ model, messages: working, tools })
        break
      } catch (error) {
        if (attempt >= maxRetries || !isRetryable(error)) throw error
        await sleep(25 * 2 ** attempt)
      }
    }
    if (response.usage) {
      const next = normalizeUsage({
        inputTokens: usage.inputTokens + Number(response.usage.inputTokens ?? 0),
        outputTokens: usage.outputTokens + Number(response.usage.outputTokens ?? 0),
      })
      usage.inputTokens = next.inputTokens
      usage.outputTokens = next.outputTokens
      usage.totalTokens = next.totalTokens
      if (budgetTokens !== null && usage.totalTokens > budgetTokens) throw fail('BUDGET_EXCEEDED', `tool loop exceeded ${budgetTokens} tokens`)
    }
    const toolCalls = Array.isArray(response.toolCalls) ? response.toolCalls : []
    if (toolCalls.length === 0) return { messages: working, final: response.text ?? '', turns, usage, toolCalls: [] }
    working.push({ role: 'assistant', content: response.text ?? '' })
    for (const call of toolCalls) {
      if (!call?.id || !call?.name) throw fail('TOOL_CALL_INVALID', 'tool call requires id/name')
      let content
      let isError = false
      try { content = String(await executeTool(call)) } catch (error) { content = String(error?.message ?? error); isError = true }
      working.push({ role: 'tool', content, toolCallId: call.id, name: call.name, isError })
    }
  }
  throw fail('TOOL_LOOP_LIMIT', `tool loop exceeded ${maxTurns} turns`)
}
