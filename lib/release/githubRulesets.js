/** Load a ruleset's full detail after finding it in GitHub's summary list. */
export function loadNamedRuleset(name, { listRulesets, getRuleset }) {
  if (typeof name !== 'string' || !name || typeof listRulesets !== 'function' || typeof getRuleset !== 'function') {
    throw new TypeError('ruleset name and GitHub readers are required')
  }
  const summaries = listRulesets()
  if (!Array.isArray(summaries)) throw new TypeError('GitHub ruleset list response must be an array')
  const matches = summaries.filter((item) => item?.name === name)
  if (matches.length > 1) throw new Error(`multiple GitHub rulesets have the required name: ${name}`)
  if (matches.length === 0) return null

  const id = Number(matches[0].id)
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error(`GitHub ruleset has an invalid id: ${name}`)
  const details = getRuleset(id)
  if (!details || Number(details.id) !== id || details.name !== name) {
    throw new Error(`GitHub ruleset detail response does not match the selected ruleset: ${name}`)
  }
  return details
}
