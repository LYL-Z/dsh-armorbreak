/** Minimal deterministic skill trigger router for explicit, testable activation. */
export function selectSkill(prompt, skills) {
  const text = String(prompt ?? '').toLowerCase()
  if (!text.trim()) return null
  const scored = skills.map((skill) => {
    const score = skill.keywords.reduce((count, keyword) => count + (text.includes(String(keyword).toLowerCase()) ? 1 : 0), 0)
    return { name: skill.name, score }
  }).sort((a, b) => b.score - a.score || a.name.localeCompare(b.name))
  const best = scored[0]
  return best && best.score >= 2 ? best : null
}
