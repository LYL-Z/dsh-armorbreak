import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { copyFileSync, linkSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { makeTestTempDirectorySync } from './helpers/temporary.js'

const repoRoot = fileURLToPath(new URL('..', import.meta.url))
const sourceManifestBuilder = join(repoRoot, 'scripts/v2/build-evidence-manifest.mjs')
const sourceSafeFile = join(repoRoot, 'lib/release/safeEvidenceFile.js')
const sourceSafeWindowsWriter = join(repoRoot, 'lib/release/safe-evidence-write-windows.ps1')
const sha256 = (value) => createHash('sha256').update(value).digest('hex')

function fixture(t) {
  const root = makeTestTempDirectorySync('abm-manifest-builder-')
  t.after(() => rmSync(root, { recursive: true, force: true }))
  mkdirSync(join(root, 'scripts/v2'), { recursive: true })
  mkdirSync(join(root, 'lib/release'), { recursive: true })
  mkdirSync(join(root, 'docs/v2/acceptance'), { recursive: true })
  copyFileSync(sourceManifestBuilder, join(root, 'scripts/v2/build-evidence-manifest.mjs'))
  copyFileSync(sourceSafeFile, join(root, 'lib/release/safeEvidenceFile.js'))
  copyFileSync(sourceSafeWindowsWriter, join(root, 'lib/release/safe-evidence-write-windows.ps1'))
  writeFileSync(join(root, 'package.json'), '{"type":"module"}\n')
  writeFileSync(join(root, 'README.md'), '# baseline\n')
  writeFileSync(join(root, 'docs/v2/acceptance/test-report.tap'), 'TAP version 13\n# tests 1\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n')
  writeFileSync(join(root, 'docs/v2/acceptance/test-report.json'), '{"commit":"pending"}\n')
  for (const args of [['init', '-q'], ['config', 'user.name', 'Test'], ['config', 'user.email', 'test@example.invalid'], ['add', '.'], ['commit', '-qm', 'baseline']]) {
    const result = spawnSync('git', args, { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr)
  }
  return root
}

function runBuilder(root) {
  return spawnSync(process.execPath, [join(root, 'scripts/v2/build-evidence-manifest.mjs')], { cwd: root, encoding: 'utf8' })
}

test('manifest builder hashes regular files but rejects hard-linked evidence', (t) => {
  const root = fixture(t)
  const initial = runBuilder(root)
  assert.equal(initial.status, 0, initial.stderr)
  const manifestPath = join(root, 'docs/v2/acceptance/evidence-manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  assert.equal(manifest.commit.length, 40)
  assert.equal(manifest.files['docs/v2/acceptance/test-report.tap'].size > 0, true)

  linkSync(join(root, 'README.md'), join(root, 'docs/v2/acceptance/aliased-readme.md'))
  const rejected = runBuilder(root)
  assert.notEqual(rejected.status, 0)
  assert.match(`${rejected.stdout}\n${rejected.stderr}`, /multiple hard links/)
})

test('manifest builder refuses to bind uncommitted source changes', (t) => {
  const root = fixture(t)
  const initial = runBuilder(root)
  assert.equal(initial.status, 0, initial.stderr)
  const manifestPath = join(root, 'docs/v2/acceptance/evidence-manifest.json')
  const prior = readFileSync(manifestPath, 'utf8')
  writeFileSync(join(root, 'README.md'), '# dirty source\n')
  const rejected = runBuilder(root)
  assert.notEqual(rejected.status, 0)
  assert.match(`${rejected.stdout}\n${rejected.stderr}`, /committed source; dirty paths: README\.md/)
  assert.equal(readFileSync(manifestPath, 'utf8'), prior)
})

test('manifest builder includes the referenced Pi install log but keeps unrelated logs excluded', (t) => {
  const root = fixture(t)
  const piLog = join(root, 'docs/v2/acceptance/host-model/pi/install-uninstall.log')
  const otherLog = join(root, 'docs/v2/acceptance/host-model/pi/noise.log')
  mkdirSync(join(root, 'docs/v2/acceptance/host-model/pi'), { recursive: true })
  writeFileSync(piLog, 'referenced install evidence\n')
  writeFileSync(otherLog, 'unreferenced log\n')

  const result = runBuilder(root)
  assert.equal(result.status, 0, result.stderr)
  const manifest = JSON.parse(readFileSync(join(root, 'docs/v2/acceptance/evidence-manifest.json'), 'utf8'))
  assert.equal(manifest.files['docs/v2/acceptance/host-model/pi/install-uninstall.log'].sha256, sha256('referenced install evidence\n'))
  assert.equal(manifest.files['docs/v2/acceptance/host-model/pi/noise.log'], undefined)
})
