const SECRET_FIELD = /api[_-]?key|token|secret|password|credential|private[_-]?key/i
const ENV_PLACEHOLDER = /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/
const LITERAL_SECRET_VALUE = /^(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i

function invalid() {
  const error = new Error('plaintext secret fields are forbidden; use ${ENV_NAME} placeholders in env')
  error.code = 'CONFIG_INVALID'
  return error
}

/** Reject nested secret fields and literal credential-shaped values. */
export function validateNoPlaintextSecrets(server) {
  const active = new WeakSet()
  let visited = 0

  function visit(value, insideEnv, depth) {
    if (depth > 32 || ++visited > 10000) throw invalid()
    if (typeof value === 'string') {
      if (LITERAL_SECRET_VALUE.test(value) && !(insideEnv && ENV_PLACEHOLDER.test(value))) throw invalid()
      return
    }
    if (value === null || typeof value !== 'object') return
    if (active.has(value)) throw invalid()
    active.add(value)
    try {
      if (Array.isArray(value)) {
        for (const item of value) visit(item, insideEnv, depth + 1)
        return
      }
      for (const [key, child] of Object.entries(value)) {
        const childIsEnv = insideEnv || key.toLowerCase() === 'env'
        if (SECRET_FIELD.test(key) && !(childIsEnv && typeof child === 'string' && ENV_PLACEHOLDER.test(child))) throw invalid()
        visit(child, childIsEnv, depth + 1)
      }
    } finally {
      active.delete(value)
    }
  }

  visit(server, false, 0)
  return server
}
