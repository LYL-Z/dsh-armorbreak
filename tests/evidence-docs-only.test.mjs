import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

import { classifyDocsBaseline, classifyDocsOnly, validateEvidence } from '../lib/release/evidenceValidator.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')
const TEST_TAP = 'TAP version 13\nok 1 - policy and approval are checked\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n'

function testReport(commit) {
  return JSON.stringify({
    schemaVersion: 'armorbreak.test-report/v1',
    commit,
    exitCode: 0,
    command: 'node --test --test-reporter=tap --test-concurrency=1',
    processError: null,
    signal: null,
    counts: { tests: 1, pass: 1, fail: 0, skipped: 0, cancelled: 0, todo: 0 },
    tapPath: 'docs/v2/acceptance/test-report.tap',
    tapSha256: hash(TEST_TAP),
  })
}

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim()
}

function write(root, path, content) {
  mkdirSync(dirname(join(root, path)), { recursive: true })
  writeFileSync(join(root, path), content)
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'abm-docs-only-'))
  git(root, 'init')
  git(root, 'config', 'user.email', 'qa@example.test')
  git(root, 'config', 'user.name', 'QA')
  write(root, 'README.md', '# README\n')
  write(root, 'docs/usage.md', '# Usage\n')
  write(root, 'SECURITY.md', '# Security\n')
  write(root, 'lib/source.js', 'export const value = 1\n')
  write(root, 'scripts/v2/release-gates.mjs', 'export const gate = true\n')
  write(root, '.github/workflows/ci.yml', 'name: CI\n')
  write(root, 'docs/v2/acceptance/test-report.tap', TEST_TAP)
  git(root, 'add', '-A')
  git(root, 'commit', '-m', 'base')
  const base = git(root, 'rev-parse', 'HEAD')
  return { root, base }
}

function commitChange(root, path, content, message = 'change') {
  write(root, path, content)
  git(root, 'add', '-A')
  git(root, 'commit', '-m', message)
  return git(root, 'rev-parse', 'HEAD')
}

test('docs-only accepts only real documentation diffs, not commit messages', () => {
  const { root, base } = fixture()
  try {
    commitChange(root, 'README.md', '# README changed\n', 'chore: not a docs message')
    commitChange(root, 'docs/usage.md', '# Usage changed\n')
    const head = git(root, 'rev-parse', 'HEAD')
    const result = classifyDocsOnly({ repoRoot: root, base, head })
    assert.equal(result.ok, true)
    assert.deepEqual(result.changed.sort(), ['README.md', 'docs/usage.md'])
    assert.equal(result.issues.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('docs-only rejects security, source, release-gate, evidence and build-config changes', () => {
  const { root, base } = fixture()
  const cases = [
    ['SECURITY.md', '# Security changed\n', 'security policy'],
    ['lib/source.js', 'export const value = 2\n', 'source code'],
    ['scripts/v2/release-gates.mjs', 'export const gate = false\n', 'release gate'],
    ['docs/v2/acceptance/test-report.tap', 'tampered', 'evidence'],
    ['.github/workflows/ci.yml', 'name: CI changed\n', 'build/CI config'],
    ['docs/v2/generated/host-matrix.md', '# generated changed\n', 'generated acceptance metadata'],
    ['docs/v2/provider-security.md', '# Provider security changed\n', 'provider security guidance'],
    ['docs/acceptance.md', '# Acceptance changed\n', 'acceptance evidence'],
    ['docs/audit/environment-audit.md', '# Audit changed\n', 'audit evidence'],
  ]
  try {
    for (const [path, content, label] of cases) {
      git(root, 'reset', '--hard', base)
      const head = commitChange(root, path, content, 'docs: only markdown')
      const result = classifyDocsOnly({ repoRoot: root, base, head })
      assert.equal(result.ok, false, label)
      assert.ok(result.issues.some((issue) => issue.includes(path)), `${label}: ${result.issues.join('; ')}`)
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('docs-only rejects git replace refs', () => {
  const { root, base } = fixture()
  try {
    const head = commitChange(root, 'README.md', '# README changed\n')
    git(root, 'replace', head, base)
    const result = classifyDocsOnly({ repoRoot: root, base, head })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /replace refs/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('evidence-only accepts a real evidence append after the source baseline', () => {
  const { root, base } = fixture()
  try {
    const report = testReport(base)
    write(root, 'docs/v2/acceptance/test-report.json', report)
    write(root, 'docs/v2/acceptance/evidence-manifest.json', JSON.stringify({
      schemaVersion: 'armorbreak.evidence-manifest/v1',
      commit: base,
      files: {
        'docs/v2/acceptance/test-report.json': { sha256: hash(report), size: Buffer.byteLength(report) },
        'docs/v2/acceptance/test-report.tap': { sha256: hash(TEST_TAP), size: Buffer.byteLength(TEST_TAP) },
      },
    }))
    git(root, 'add', 'docs/v2/acceptance')
    git(root, 'commit', '-m', 'evidence: bind baseline tests')
    const evidenceHead = git(root, 'rev-parse', 'HEAD')
    const accepted = validateEvidence({ repoRoot: root, commit: evidenceHead, allowEvidenceAncestor: true })
    assert.equal(accepted.ok, true, accepted.issues.join('; '))
    assert.equal(accepted.mode, 'evidence-only')
    const tagStyleExactCommit = validateEvidence({ repoRoot: root, commit: evidenceHead, allowEvidenceAncestor: false })
    assert.equal(tagStyleExactCommit.ok, false, 'tag validation must require evidence bound to the tagged commit')
    assert.ok(tagStyleExactCommit.issues.some((issue) => /does not match/.test(issue)))

    write(root, 'docs/v2/release/readiness.json', JSON.stringify({
      schemaVersion: 'armorbreak.release-readiness/v1',
      commit: base,
      evaluatedAtCommit: base,
      evidence: {
        manifestCommit: base,
        testReportCommit: base,
        testCounts: { tests: 1, pass: 1, fail: 0, skipped: 0, cancelled: 0, todo: 0 },
        current: true,
        checks: { manifestValid: true, evidenceLineage: true, testsPassed: true, gatesValid: true },
      },
      ready: false,
      incomplete: [],
      sbom: false,
    }) + '\n')
    git(root, 'add', 'docs/v2/release/readiness.json')
    git(root, 'commit', '-m', 'readiness: bind status to tested evidence')
    const readinessHead = git(root, 'rev-parse', 'HEAD')
    const readinessRejected = validateEvidence({ repoRoot: root, commit: readinessHead, allowEvidenceAncestor: true })
    assert.equal(readinessRejected.ok, false)
    assert.ok(readinessRejected.issues.some((issue) => /readiness\.json/.test(issue)))
    const readinessAccepted = validateEvidence({ repoRoot: root, commit: readinessHead, allowEvidenceAncestor: true, allowReadiness: true })
    assert.equal(readinessAccepted.ok, true, readinessAccepted.issues.join('; '))

    write(root, 'docs/v2/release/readiness.json', '{"gaReady":true}\n')
    git(root, 'add', 'docs/v2/release/readiness.json')
    git(root, 'commit', '-m', 'readiness: reject unbound metadata')
    const forgedReadinessHead = git(root, 'rev-parse', 'HEAD')
    const forgedReadiness = validateEvidence({ repoRoot: root, commit: forgedReadinessHead, allowEvidenceAncestor: true, allowReadiness: true })
    assert.equal(forgedReadiness.ok, false)
    assert.ok(forgedReadiness.issues.some((issue) => /readiness metadata|readiness schema/.test(issue)))

    write(root, 'lib/source.js', 'export const value = 2\n')
    git(root, 'add', 'lib/source.js')
    git(root, 'commit', '-m', 'source: change without evidence')
    const sourceHead = git(root, 'rev-parse', 'HEAD')
    const rejected = validateEvidence({ repoRoot: root, commit: sourceHead, allowEvidenceAncestor: true })
    assert.equal(rejected.ok, false)
    assert.ok(rejected.issues.some((issue) => /non-evidence change/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('validator accepts a path-verified docs-only baseline and still rejects a protected diff', () => {
  const { root, base } = fixture()
  try {
    const docsHead = commitChange(root, 'README.md', '# README changed\n')
    const report = testReport(base)
    write(root, 'docs/v2/acceptance/test-report.json', report)
    write(root, 'docs/v2/acceptance/evidence-manifest.json', JSON.stringify({
      schemaVersion: 'armorbreak.evidence-manifest/v1',
      commit: base,
      files: {
        'docs/v2/acceptance/test-report.json': { sha256: hash(report), size: Buffer.byteLength(report) },
        'docs/v2/acceptance/test-report.tap': { sha256: hash(TEST_TAP), size: Buffer.byteLength(TEST_TAP) },
      },
    }))
    const accepted = validateEvidence({ repoRoot: root, commit: docsHead, base, allowDocsOnly: true })
    assert.equal(accepted.ok, true, accepted.issues.join('; '))
    assert.equal(accepted.mode, 'docs-only')

    const protectedHead = commitChange(root, 'SECURITY.md', '# Security changed\n')
    const rejected = validateEvidence({ repoRoot: root, commit: protectedHead, base, allowDocsOnly: true })
    assert.equal(rejected.ok, false)
    assert.ok(rejected.issues.some((issue) => /non-doc change/.test(issue)))

    const noBase = validateEvidence({ repoRoot: root, commit: docsHead, allowDocsOnly: true })
    assert.equal(noBase.ok, false)
    assert.ok(noBase.issues.some((issue) => /target branch base is required/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('docs baseline accepts prior evidence and prior docs-only merges', () => {
  const { root, base } = fixture()
  try {
    write(root, 'docs/v2/acceptance/prior.json', '{}\n')
    git(root, 'add', 'docs/v2/acceptance/prior.json')
    git(root, 'commit', '-m', 'evidence: prior')
    const evidenceBase = git(root, 'rev-parse', 'HEAD')
    git(root, 'add', 'docs/usage.md')
    write(root, 'docs/usage.md', '# Usage changed\n')
    git(root, 'add', 'docs/usage.md')
    git(root, 'commit', '-m', 'docs: prior docs-only')
    const priorDocsBase = git(root, 'rev-parse', 'HEAD')
    const baseline = classifyDocsBaseline({ repoRoot: root, base, head: priorDocsBase })
    assert.equal(baseline.ok, true, baseline.issues.join('; '))
    assert.ok(baseline.changed.includes('docs/v2/acceptance/prior.json'))
    assert.ok(baseline.changed.includes('docs/usage.md'))
    assert.equal(classifyDocsBaseline({ repoRoot: root, base, head: evidenceBase }).ok, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('docs baseline rejects CI, build and security changes in target base', () => {
  const { root, base } = fixture()
  try {
    for (const [path, content] of [
      ['.github/workflows/ci.yml', 'name: changed\n'],
      ['SECURITY.md', '# changed\n'],
      ['docs/v2/provider-security.md', '# changed\n'],
    ]) {
      git(root, 'reset', '--hard', base)
      const head = commitChange(root, path, content, 'docs: misleading')
      const baseline = classifyDocsBaseline({ repoRoot: root, base, head })
      assert.equal(baseline.ok, false, path)
      assert.ok(baseline.issues.some((issue) => issue.includes(path)))
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('docs-only rejects a target base with unbound source changes after evidence', () => {
  const { root, base } = fixture()
  try {
    const report = testReport(base)
    write(root, 'docs/v2/acceptance/test-report.json', report)
    write(root, 'docs/v2/acceptance/evidence-manifest.json', JSON.stringify({
      schemaVersion: 'armorbreak.evidence-manifest/v1',
      commit: base,
      files: {
        'docs/v2/acceptance/test-report.json': { sha256: hash(report), size: Buffer.byteLength(report) },
        'docs/v2/acceptance/test-report.tap': { sha256: hash(TEST_TAP), size: Buffer.byteLength(TEST_TAP) },
      },
    }))
    git(root, 'add', 'docs/v2/acceptance')
    git(root, 'commit', '-m', 'evidence: baseline')
    const staleSourceBase = commitChange(root, 'lib/source.js', 'export const value = 2\n')
    const docsHead = commitChange(root, 'README.md', '# README changed\n')
    const result = validateEvidence({ repoRoot: root, commit: docsHead, base: staleSourceBase, allowDocsOnly: true, allowEvidenceAncestor: true })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /docs-only base is not evidence-backed/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('docs-only rejects a gitlink disguised as a markdown document', () => {
  const { root, base } = fixture()
  try {
    git(root, 'update-index', '--add', '--cacheinfo', `160000,${base},docs/gitlink.md`)
    git(root, 'commit', '-m', 'docs: add gitlink')
    const head = git(root, 'rev-parse', 'HEAD')
    const result = classifyDocsOnly({ repoRoot: root, base, head })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /non-regular document/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('validator requireClean rejects a dirty working tree before trusting evidence', () => {
  const { root, base } = fixture()
  try {
    write(root, 'README.md', '# uncommitted change\n')
    const result = validateEvidence({ repoRoot: root, commit: base, requireClean: true })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /working tree is dirty/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
