import test from 'node:test'
import assert from 'node:assert/strict'
import { POST_SOURCE_FILES, findForbiddenPostSourcePaths, isFullCommitSha } from '../scripts/v2/v23-provenance.mjs'

test('post-source allowlist is exact and limited to current evidence documentation', () => {
  assert.deepEqual([...POST_SOURCE_FILES].sort(), [
    'docs/v2.3/acceptance-report.md',
    'docs/v2.3/compatibility-matrix.json',
    'docs/v2.3/evidence/p0-h/acceptance-manifest.json',
    'docs/v2.3/migration-and-rollback.md',
    'docs/v2.3/threat-model.md',
  ])
  assert.deepEqual(findForbiddenPostSourcePaths([
    'docs/v2.3/evidence/p0-h/security-review.json',
    'docs/v2.3/acceptance-report.md',
  ]), [])
})

test('post-source code changes are rejected, including provenance, workflow and security-gate tampering', () => {
  const forbidden = findForbiddenPostSourcePaths([
    'scripts/v2/validate-v23-acceptance.mjs',
    'scripts/v2/v23-provenance.mjs',
    'scripts/v2/release-gates.mjs',
    '.github/workflows/ci.yml',
    '.github/workflows/v2.3-validation.yml',
    'docs/v2.3/evidence/p0-h/security-review.json',
  ])
  assert.deepEqual(forbidden, [
    'scripts/v2/validate-v23-acceptance.mjs',
    'scripts/v2/v23-provenance.mjs',
    'scripts/v2/release-gates.mjs',
    '.github/workflows/ci.yml',
    '.github/workflows/v2.3-validation.yml',
  ])
})

test('post-source source changes reject reuse of an older manifest SHA', () => {
  const oldSourceSha = '0795c4dd270f59cb60a006c756035da111e1d970'
  assert.equal(isFullCommitSha(oldSourceSha), true)
  assert.deepEqual(findForbiddenPostSourcePaths([
    // A changed source or gate after this older SHA is never an evidence-only append.
    'scripts/v2/validate-v23-acceptance.mjs',
  ]), ['scripts/v2/validate-v23-acceptance.mjs'])
})

test('abbreviated or malformed source identifiers cannot satisfy the manifest binding', () => {
  assert.equal(isFullCommitSha('0795c4dd270f59cb60a006c756035da111e1d970'), true)
  assert.equal(isFullCommitSha('0795c4d'), false)
  assert.equal(isFullCommitSha(''), false)
  assert.equal(isFullCommitSha(null), false)
})
