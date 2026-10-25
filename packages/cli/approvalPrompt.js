function approvalError(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

/**
 * Request approval from a trusted host surface. A terminal and its input stream
 * may be controlled by the same caller requesting approval, so they are not an
 * authority and cannot be used to mint an approval token.
 */
export async function requestTrustedHostApproval(provider, request = {}) {
  if (!provider || typeof provider.request !== 'function') {
    throw approvalError('TRUSTED_APPROVAL_PROVIDER_REQUIRED', 'approval requires a trusted host approval provider; terminal input is not an approval authority')
  }
  if (typeof request.agent !== 'string' || !request.agent || typeof request.callId !== 'string' || !request.callId || typeof request.sessionId !== 'string' || !request.sessionId) {
    throw approvalError('TRUSTED_APPROVAL_CONTEXT_REQUIRED', 'trusted host approval requires host-provided agent, call, and session identifiers')
  }
  let outcome
  try {
    outcome = await provider.request({ ...request, toolName: 'armorbreak' })
  } catch {
    outcome = 'unavailable'
  }
  if (outcome !== 'allowed-once') {
    throw approvalError('TRUSTED_APPROVAL_DENIED', 'trusted host approval was not granted; no approval token was issued')
  }
  return outcome
}

/** Terminal text is deliberately never accepted as proof of human approval. */
export async function confirmInteractiveApproval() {
  throw approvalError('TRUSTED_APPROVAL_PROVIDER_REQUIRED', 'terminal input is not a trusted approval authority')
}
