import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'

/** Require a live terminal confirmation; command-line flags are not consent. */
export async function confirmInteractiveApproval({ action, details = [], expected, input = stdin, output = stdout } = {}) {
  if (!input?.isTTY || !output?.isTTY) {
    const error = new Error('approval requires an interactive terminal')
    error.code = 'INTERACTIVE_APPROVAL_REQUIRED'
    throw error
  }
  if (typeof expected !== 'string' || !expected) throw new Error('approval confirmation phrase is required')

  output.write(`\n${String(action ?? 'APPROVAL').toUpperCase()}\n`)
  for (const detail of details) output.write(`  ${String(detail)}\n`)
  const terminal = createInterface({ input, output })
  try {
    const answer = await terminal.question(`Type exactly: ${expected}\n> `)
    if (answer !== expected) {
      const error = new Error('interactive approval phrase did not match')
      error.code = 'APPROVAL_CONFIRMATION_MISMATCH'
      throw error
    }
  } finally {
    terminal.close()
  }
}
