import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign, verify } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
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

test('temporary source/evidence commits and detached authorization bind without a Git SHA self-reference', (t) => {
  const repo = mkdtempSync(join(tmpdir(), 'armorbreak-v23-provenance-'))
  t.after(() => rmSync(repo, { recursive: true, force: true }))
  const git = (...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '--quiet')
  git('config', 'user.name', 'Protocol Test')
  git('config', 'user.email', 'protocol-test@example.invalid')
  writeFileSync(join(repo, 'README.md'), 'temporary source/evidence/tag provenance test\n')
  git('add', 'README.md')
  git('commit', '-m', 'base')
  const baseCommit = git('rev-parse', 'HEAD')
  git('checkout', '-b', 'candidate')
  writeFileSync(join(repo, 'source.js'), 'export const candidate = true\n')
  git('add', 'source.js')
  git('commit', '-m', 'source S')
  const sourceCommit = git('rev-parse', 'HEAD')
  mkdirSync(join(repo, 'docs'))
  writeFileSync(join(repo, 'docs', 'review.json'), '{"testRecord":true}\n')
  git('add', 'docs/review.json')
  git('commit', '-m', 'evidence E')
  const evidenceCommit = git('rev-parse', 'HEAD')
  assert.equal(git('merge-base', '--is-ancestor', sourceCommit, evidenceCommit) || '', '')
  assert.equal(git('diff', '--name-only', `${sourceCommit}..${evidenceCommit}`), 'docs/review.json')
  git('checkout', '-b', 'main', baseCommit)
  git('merge', '--no-ff', 'candidate', '-m', 'temporary main merge M')
  const tagCommit = git('rev-parse', 'HEAD')
  git('tag', '-a', 'test-v2.3.0', '-m', 'harmless local test tag')
  assert.equal(git('rev-parse', 'test-v2.3.0^{commit}'), tagCommit)
  assert.equal(git('merge-base', '--is-ancestor', evidenceCommit, tagCommit) || '', '')
  assert.equal(git('rev-parse', `${evidenceCommit}^{tree}`), git('rev-parse', `${tagCommit}^{tree}`))

  const claims = { schemaVersion: 'armorbreak.v2.3-external-release-authorization/v1', sourceCommit, evidenceCommit, tagCommit, tag: 'test-v2.3.0' }
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const canonical = JSON.stringify(Object.fromEntries(Object.entries(claims).sort(([a], [b]) => a.localeCompare(b))))
  const signature = sign(null, Buffer.from(canonical), privateKey)
  assert.equal(verify(null, Buffer.from(canonical), publicKey, signature), true)
  const staleClaims = { ...claims, evidenceCommit: baseCommit }
  const staleCanonical = JSON.stringify(Object.fromEntries(Object.entries(staleClaims).sort(([a], [b]) => a.localeCompare(b))))
  assert.equal(verify(null, Buffer.from(staleCanonical), publicKey, signature), false)
})
