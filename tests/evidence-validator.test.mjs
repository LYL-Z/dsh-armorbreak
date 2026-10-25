import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'

import { validateEvidence } from '../lib/release/evidenceValidator.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'abm-evidence-'))
  const dir = join(root, 'docs/v2/acceptance')
  mkdirSync(dir, { recursive: true })
  const commit = 'a'.repeat(40)
  const tap = 'TAP version 13\nok 1 - policy and approval gates\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n'
  const files = {
    'docs/v2/acceptance/test-report.json': JSON.stringify({
      schemaVersion: 'armorbreak.test-report/v1', commit, exitCode: 0,
      command: 'node --test --test-reporter=tap --test-concurrency=1', processError: null, signal: null,
      counts: { tests: 1, pass: 1, fail: 0, skipped: 0, cancelled: 0, todo: 0 },
      tapPath: 'docs/v2/acceptance/test-report.tap', tapSha256: hash(tap),
    }),
    'docs/v2/acceptance/test-report.tap': tap,
    'docs/v2/acceptance/desktop-e2e.json': JSON.stringify({ screenshots: [], l0Task: {} }),
  }
  for (const [name, content] of Object.entries(files)) writeFileSync(join(root, name), content)
  const manifest = {
    schemaVersion: 'armorbreak.evidence-manifest/v1', commit, generatedAt: new Date().toISOString(),
    files: Object.fromEntries(Object.entries(files).map(([name, content]) => [name, { sha256: hash(content), size: Buffer.byteLength(content) }])),
  }
  writeFileSync(join(root, 'docs/v2/acceptance/evidence-manifest.json'), JSON.stringify(manifest))
  return root
}

function addPinnedFiles(root, additions) {
  const manifestPath = join(root, 'docs/v2/acceptance/evidence-manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  for (const [path, content] of Object.entries(additions)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), content)
    manifest.files[path] = { sha256: hash(content), size: Buffer.byteLength(content) }
  }
  writeFileSync(manifestPath, JSON.stringify(manifest))
}

test('evidence validator accepts pinned files and rejects tamper/missing', () => {
  const root = fixture()
  assert.equal(validateEvidence({ repoRoot: root, commit: 'a'.repeat(40) }).ok, true)
  writeFileSync(join(root, 'docs/v2/acceptance/test-report.tap'), 'tampered')
  const tampered = validateEvidence({ repoRoot: root, commit: 'a'.repeat(40) })
  assert.equal(tampered.ok, false)
  assert.ok(tampered.issues.some((issue) => /hash mismatch/.test(issue)))
  rmSync(root, { recursive: true, force: true })
})

test('evidence validator rejects dangling embedded acceptance references', () => {
  const root = fixture()
  addPinnedFiles(root, {
    'docs/v2/acceptance/host-e2e.json': JSON.stringify({
      evidence: ['docs/v2/acceptance/host-model/pi/l0.json'],
    }),
  })
  try {
    const result = validateEvidence({ repoRoot: root, commit: 'a'.repeat(40) })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /referenced evidence path is missing or unsafe.*host-model\/pi\/l0\.json/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('evidence validator rejects stale embedded hashes for nested relative evidence', () => {
  const root = fixture()
  const evidence = 'current nested evidence\n'
  addPinnedFiles(root, {
    'docs/v2/acceptance/host-audit/sample.jsonl': evidence,
    'docs/v2/acceptance/host-e2e.json': JSON.stringify({
      files: {
        'host-audit/sample.jsonl': { sha256: hash('stale evidence\n'), size: Buffer.byteLength('stale evidence\n') },
      },
    }),
  })
  try {
    const result = validateEvidence({ repoRoot: root, commit: 'a'.repeat(40) })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /embedded SHA-256 mismatch.*host-audit\/sample\.jsonl/.test(issue)))
    assert.ok(result.issues.some((issue) => /embedded byte size mismatch.*host-audit\/sample\.jsonl/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('evidence validator resolves references relative to their nested JSON document', () => {
  const root = fixture()
  const log = 'synthetic Pi install/uninstall evidence\n'
  addPinnedFiles(root, {
    'docs/v2/acceptance/host-model/pi/install-uninstall.log': log,
    'docs/v2/acceptance/host-model/pi/pi-package-install.json': JSON.stringify({
      headlessWithoutExtensionFlag: {
        evidence: {
          path: 'install-uninstall.log',
          sha256: hash(log),
          size: Buffer.byteLength(log),
        },
      },
    }),
  })
  try {
    const result = validateEvidence({ repoRoot: root, commit: 'a'.repeat(40) })
    assert.equal(result.ok, true, result.issues.join('\n'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('evidence validator checks source hashes against the pinned Git blob across line endings', () => {
  const root = mkdtempSync(join(tmpdir(), 'abm-evidence-source-'))
  const git = (...args) => execFileSync('git', args, { cwd: root, stdio: 'ignore' })
  const source = 'src/release.js'
  const sourceBytes = Buffer.from('export const release = true\n')
  const acceptance = 'docs/v2/acceptance'
  const tapPath = `${acceptance}/test-report.tap`
  const reportPath = `${acceptance}/test-report.json`
  const manifestPath = `${acceptance}/evidence-manifest.json`
  const releasePath = `${acceptance}/release-build.json`
  const tap = Buffer.from('TAP version 13\nok 1 - pinned source evidence\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n')
  try {
    git('init')
    git('config', 'user.email', 'qa@example.test')
    git('config', 'user.name', 'QA')
    git('config', 'core.autocrlf', 'true')
    writeFileSync(join(root, '.gitattributes'), '*.js text eol=lf\n')
    mkdirSync(dirname(join(root, source)), { recursive: true })
    mkdirSync(join(root, acceptance), { recursive: true })
    writeFileSync(join(root, source), sourceBytes)
    const report = {
      schemaVersion: 'armorbreak.test-report/v1', commit: '', exitCode: 0,
      command: 'node --test --test-reporter=tap --test-concurrency=1', processError: null, signal: null,
      counts: { tests: 1, pass: 1, fail: 0, skipped: 0, cancelled: 0, todo: 0 },
      tapPath, tapSha256: hash(tap),
    }
    writeFileSync(join(root, tapPath), tap)
    writeFileSync(join(root, releasePath), JSON.stringify({ contentManifest: [{ path: source, size: sourceBytes.length, sha256: hash(sourceBytes) }] }))
    writeFileSync(join(root, reportPath), JSON.stringify(report))
    git('add', '-A')
    git('commit', '-m', 'pin release evidence')
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
    report.commit = commit
    writeFileSync(join(root, reportPath), JSON.stringify(report))
    const sourceHash = execFileSync('git', ['hash-object', source], { cwd: root, encoding: 'utf8' }).trim()
    const rawBlob = execFileSync('git', ['cat-file', 'blob', sourceHash], { cwd: root })
    const release = { contentManifest: [{ path: source, size: rawBlob.length, sha256: hash(rawBlob) }] }
    writeFileSync(join(root, releasePath), JSON.stringify(release))
    const records = Object.fromEntries([tapPath, reportPath, releasePath].map((path) => {
      const bytes = readFileSync(join(root, path))
      return [path, { size: bytes.length, sha256: hash(bytes) }]
    }))
    writeFileSync(join(root, manifestPath), JSON.stringify({ schemaVersion: 'armorbreak.evidence-manifest/v1', commit, files: records }))
    git('add', '-A')
    git('commit', '-m', 'bind release evidence')
    const evidenceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()

    writeFileSync(join(root, source), Buffer.from(sourceBytes.toString('utf8').replaceAll('\n', '\r\n')))
    const accepted = validateEvidence({ repoRoot: root, commit: evidenceCommit, allowEvidenceAncestor: true })
    assert.equal(accepted.ok, true, accepted.issues.join('\n'))

    writeFileSync(join(root, source), 'export const release = false\r\n')
    const changed = validateEvidence({ repoRoot: root, commit: evidenceCommit, allowEvidenceAncestor: true })
    assert.equal(changed.ok, false)
    assert.ok(changed.issues.some((issue) => /referenced evidence path is missing or unsafe.*differs from its pinned commit/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('evidence validator refuses a parent junction to acceptance data outside the repository', (t) => {
  const root = fixture()
  const acceptance = join(root, 'docs/v2/acceptance')
  const external = join(root, 'external-acceptance')
  mkdirSync(external, { recursive: true })
  for (const name of ['evidence-manifest.json', 'test-report.json', 'test-report.tap']) {
    writeFileSync(join(external, name), 'synthetic external evidence')
  }
  rmSync(acceptance, { recursive: true, force: true })
  try {
    symlinkSync(external, acceptance, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    rmSync(root, { recursive: true, force: true })
    t.skip(`could not create isolated directory link: ${String(error?.code ?? error)}`)
    return
  }
  try {
    const result = validateEvidence({ repoRoot: root, commit: 'a'.repeat(40) })
    assert.equal(result.ok, false)
    assert.ok(result.issues.some((issue) => /symlink or junction|outside its declared location/.test(issue)))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
