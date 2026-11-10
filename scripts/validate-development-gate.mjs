import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

export const requiredJobs = ['common-matrix', 'common-l0', 'common-l1']
export function evaluateGate(needs, expectedSha, actualSha) {
  const errors = []
  if (!/^[0-9a-f]{40}$/.test(expectedSha ?? '') || expectedSha !== actualSha) errors.push('candidate SHA mismatch')
  if (!needs || typeof needs !== 'object' || Array.isArray(needs)) return [...errors, 'invalid dependency object']
  for (const id of requiredJobs) {
    if (!Object.hasOwn(needs, id)) errors.push(`${id}: missing`)
    else if (needs[id]?.result !== 'success') errors.push(`${id}: ${needs[id]?.result ?? 'invalid result'}`)
  }
  for (const id of Object.keys(needs)) if (!requiredJobs.includes(id)) errors.push(`${id}: unexpected dependency`)
  return errors
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const actualSha = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
    const errors = evaluateGate(JSON.parse(process.env.NEEDS_JSON ?? 'null'), process.env.EXPECTED_SHA, actualSha)
    if (errors.length) throw new Error(errors.join('; '))
    console.log(`All common validations succeeded for ${actualSha}`)
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
