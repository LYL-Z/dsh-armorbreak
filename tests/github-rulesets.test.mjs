import assert from 'node:assert/strict'
import test from 'node:test'
import { loadNamedRuleset } from '../lib/release/githubRulesets.js'

const name = 'ArmorBreak V2.2 Stable release tag protection'

test('ruleset loader fetches complete details instead of trusting list summaries', () => {
  const summary = { id: 25816149, name, target: 'tag', enforcement: 'active' }
  let fetchedId
  const details = {
    ...summary,
    conditions: { ref_name: { include: ['refs/tags/v2.2.0'], exclude: [] } },
    rules: [{ type: 'creation' }, { type: 'update' }, { type: 'deletion' }],
    bypass_actors: [{ actor_type: 'User', actor_id: 250811935, bypass_mode: 'always' }],
  }
  const result = loadNamedRuleset(name, {
    listRulesets: () => [summary],
    getRuleset(id) { fetchedId = id; return details },
  })
  assert.equal(fetchedId, 25816149)
  assert.deepEqual(result, details)
  assert.deepEqual(result.conditions.ref_name.include, ['refs/tags/v2.2.0'])
  assert.deepEqual(result.rules.map((rule) => rule.type), ['creation', 'update', 'deletion'])
  assert.equal(result.bypass_actors[0].actor_id, 250811935)
})

test('ruleset loader fails closed when the named ruleset is absent or ambiguous', () => {
  assert.equal(loadNamedRuleset(name, { listRulesets: () => [], getRuleset() { assert.fail('must not fetch') } }), null)
  assert.throws(() => loadNamedRuleset(name, {
    listRulesets: () => [{ id: 1, name }, { id: 2, name }],
    getRuleset() { assert.fail('must not fetch ambiguous summary') },
  }), /multiple GitHub rulesets/)
})

test('ruleset loader rejects invalid or mismatched detail responses', () => {
  assert.throws(() => loadNamedRuleset(name, {
    listRulesets: () => [{ id: 'not-an-id', name }], getRuleset() { assert.fail('must not fetch') },
  }), /invalid id/)
  assert.throws(() => loadNamedRuleset(name, {
    listRulesets: () => [{ id: 5, name }], getRuleset() { return { id: 6, name } },
  }), /does not match/)
})
