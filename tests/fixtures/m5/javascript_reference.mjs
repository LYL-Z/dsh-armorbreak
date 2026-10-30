export function formatAccount({ value }) {
  if (!Number.isSafeInteger(value) || value < 0) return { error: 'invalid' }
  return { value: `ACCT-${String(value).padStart(4, '0')}` }
}

export function evaluateArithmetic({ operation, left, right }) {
  if (!Number.isFinite(left) || !Number.isFinite(right)) return { error: 'invalid' }
  if (operation === 'add') return { value: left + right }
  if (operation === 'multiply') return { value: left * right }
  return { error: 'unsupported-operation' }
}

export function transitionState({ state, command, enabled }) {
  if (command === 'start' && enabled === true && state === 'idle') return { state: 'active' }
  if (command === 'stop' && state === 'active') return { state: 'idle' }
  return { state }
}
