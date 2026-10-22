export type Role = 'system' | 'user' | 'assistant' | 'tool'
export type FinishReason = 'stop' | 'length' | 'tool_calls' | 'content_filter' | 'error'
export interface NormalizedMessage { role: Role; content: string; toolCallId?: string; name?: string }
export interface NormalizedToolCall { id: string; name: string; arguments: unknown }
export interface NormalizedToolResult { toolCallId: string; content: string; isError: boolean }
export interface NormalizedUsage { inputTokens: number; outputTokens: number; totalTokens: number }
export interface NormalizedStreamEvent { type: 'message_start' | 'content_delta' | 'tool_call_delta' | 'message_stop' | 'error'; index?: number; delta?: string; toolCallId?: string; finishReason?: FinishReason }
export interface NormalizedError { code: string; message: string; retryable: boolean }
export function normalizeMessage(input: unknown): NormalizedMessage
export function normalizeToolCall(input: unknown): NormalizedToolCall
export function normalizeToolResult(input: unknown): NormalizedToolResult
export function normalizeUsage(input?: unknown): NormalizedUsage
export function normalizeFinishReason(value: unknown): FinishReason
export function normalizeStreamEvent(input: unknown): NormalizedStreamEvent
export function normalizeError(input: unknown): NormalizedError
