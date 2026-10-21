/**
 * Provider router (P3 slice). It resolves a model to a provider descriptor, but
 * never treats the model as an authorization principal and never stores or
 * returns plaintext API keys. Callers read credentials only from the declared
 * environment variable in their own adapter.
 */
const KINDS = new Set(['openai-compatible', 'anthropic', 'ollama', 'local'])
const SECRET_FIELD = /api[_-]?key|token|secret|authorization|password/i

function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function validateProvider(input) {
  if (!input || typeof input !== 'object') throw fail('PROVIDER_INVALID', 'provider must be an object')
  if (!input.id || typeof input.id !== 'string') throw fail('PROVIDER_INVALID', 'provider.id is required')
  if (!KINDS.has(input.kind)) throw fail('PROVIDER_INVALID', `unsupported provider kind: ${String(input.kind)}`)
  if (!input.baseUrl || !/^https?:\/\//.test(input.baseUrl)) throw fail('PROVIDER_INVALID', `provider ${input.id} needs http(s) baseUrl`)
  if (!Array.isArray(input.models) || input.models.length === 0) throw fail('PROVIDER_INVALID', `provider ${input.id} needs models`)
  if (input.apiKey !== undefined) throw fail('PROVIDER_INVALID', 'plaintext apiKey is forbidden; use apiKeyEnv')
  if (input.apiKeyEnv !== undefined && !/^[A-Z][A-Z0-9_]+$/.test(input.apiKeyEnv)) throw fail('PROVIDER_INVALID', 'apiKeyEnv must be an env var name')
  for (const key of Object.keys(input)) if (SECRET_FIELD.test(key) && key !== 'apiKeyEnv') throw fail('PROVIDER_INVALID', `provider ${input.id} contains secret-like field ${key}`)
  if (input.timeoutMs !== undefined && (!Number.isInteger(input.timeoutMs) || input.timeoutMs < 100 || input.timeoutMs > 600_000)) throw fail('PROVIDER_INVALID', 'timeoutMs must be 100..600000')
  return {
    id: input.id,
    kind: input.kind,
    baseUrl: input.baseUrl.replace(/\/$/, ''),
    models: [...input.models],
    apiKeyEnv: input.apiKeyEnv ?? null,
    supportsTools: Boolean(input.supportsTools),
    timeoutMs: input.timeoutMs ?? 60_000,
  }
}

export class ProviderRouter {
  constructor({ providers, env = process.env } = {}) {
    if (!Array.isArray(providers) || providers.length === 0) throw fail('PROVIDER_INVALID', 'at least one provider is required')
    this.providers = providers.map(validateProvider)
    this.env = env
    this.modelIsAuthority = false
    this.authorization = 'external host approval; model is never an approver'
  }

  list() {
    return this.providers.map((provider) => ({
      id: provider.id, kind: provider.kind, baseUrl: provider.baseUrl, models: [...provider.models],
      supportsTools: provider.supportsTools, timeoutMs: provider.timeoutMs,
      credentialEnv: provider.apiKeyEnv, credentialPresent: Boolean(provider.apiKeyEnv && this.env[provider.apiKeyEnv]),
    }))
  }

  resolve({ model, requireTools = false } = {}) {
    const wanted = String(model ?? '').trim()
    if (!wanted) throw fail('MODEL_REQUIRED', 'model is required')
    const candidates = this.providers.filter((provider) => provider.models.includes(wanted))
    if (candidates.length === 0) throw fail('MODEL_NOT_FOUND', `no provider advertises model ${wanted}`)
    const selected = candidates.find((provider) => !requireTools || provider.supportsTools)
    if (!selected) throw fail('MODEL_UNSUPPORTED', `model ${wanted} has no tool-capable provider`)
    if (selected.apiKeyEnv && !this.env[selected.apiKeyEnv]) throw fail('KEY_MISSING', `credential env ${selected.apiKeyEnv} is missing for provider ${selected.id}`)
    return {
      providerId: selected.id,
      kind: selected.kind,
      baseUrl: selected.baseUrl,
      model: wanted,
      supportsTools: selected.supportsTools,
      timeoutMs: selected.timeoutMs,
      credentialEnv: selected.apiKeyEnv,
      modelIsAuthority: false,
    }
  }
}

export function createProviderRouter(options) {
  return new ProviderRouter(options)
}
