import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { selectSkill } from '../packages/skill-router/index.js'

test('every skill has positive and negative trigger cases that route correctly', async () => {
  const triggers = JSON.parse(await readFile('skills/triggers.json', 'utf8'))
  assert.equal(triggers.skills.length, 7)
  assert.equal(new Set(triggers.skills.map((skill) => skill.name)).size, 7)
  for (const skill of triggers.skills) {
    const positive = selectSkill(skill.positive, triggers.skills)
    assert.equal(positive?.name, skill.name, `${skill.name} positive trigger failed`)
    assert.equal(selectSkill(skill.negative, triggers.skills), null, `${skill.name} negative trigger matched`)
  }
})
