import assert from 'node:assert/strict'
import fs, { linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { readSafeRepoFile, writeSafeRepoFile } from '../lib/release/safeEvidenceFile.js'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'abm-safe-evidence-'))
  mkdirSync(join(root, 'docs/v2/acceptance'), { recursive: true })
  return root
}

test('safe evidence reads stable regular files and atomically replaces regular outputs', () => {
  const root = fixture()
  try {
    const path = 'docs/v2/acceptance/result.json'
    writeFileSync(join(root, path), '{"before":true}')
    writeSafeRepoFile(root, path, '{"after":true}', { requiredPrefix: 'docs/v2/acceptance/' })
    assert.equal(readSafeRepoFile(root, path, { requiredPrefix: 'docs/v2/acceptance/' }).toString(), '{"after":true}')
    assert.equal(readFileSync(join(root, path), 'utf8'), '{"after":true}')
    assert.equal(lstatSync(join(root, path)).nlink, 1)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('safe evidence rejects hard links and symlink or junction output paths', (t) => {
  const root = fixture()
  try {
    const shared = join(root, 'shared.json')
    writeFileSync(shared, '{"shared":true}')
    linkSync(shared, join(root, 'docs/v2/acceptance/hardlinked.json'))
    assert.throws(() => readSafeRepoFile(root, 'docs/v2/acceptance/hardlinked.json'), /multiple hard links/)

    const outside = join(root, 'outside')
    mkdirSync(outside)
    writeFileSync(join(outside, 'result.json'), 'outside')
    rmSync(join(root, 'docs/v2/acceptance'), { recursive: true, force: true })
    try { symlinkSync(outside, join(root, 'docs/v2/acceptance'), process.platform === 'win32' ? 'junction' : 'dir') } catch (error) {
      t.skip(`isolated directory-link creation is unavailable: ${String(error?.code ?? error)}`)
      return
    }
    assert.throws(() => readSafeRepoFile(root, 'docs/v2/acceptance/result.json'), /symlink or junction/)
    assert.throws(() => writeSafeRepoFile(root, 'docs/v2/acceptance/result.json', 'blocked'), /real directory/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('safe evidence writes no bytes when a parent junction changes during temporary-file open', () => {
  const root = fixture()
  const acceptance = join(root, 'docs/v2/acceptance')
  const held = join(root, 'docs/v2/acceptance-held')
  const outside = join(root, 'outside')
  mkdirSync(outside)

  let swapped = false
  let writeCalls = 0
  const originalOpen = fs.openSync
  const originalWrite = fs.writeSync
  fs.openSync = (file, ...args) => {
    if (!swapped && String(file).endsWith('.tmp')) {
      renameSync(acceptance, held)
      symlinkSync(outside, acceptance, process.platform === 'win32' ? 'junction' : 'dir')
      swapped = true
    }
    return originalOpen(file, ...args)
  }
  fs.writeSync = (...args) => {
    writeCalls += 1
    return originalWrite(...args)
  }
  syncBuiltinESMExports()

  try {
    assert.throws(
      () => writeSafeRepoFile(root, 'docs/v2/acceptance/release-gates.json', 'SYNTHETIC-OUTSIDE-CAPTURE'),
      (error) => error.code === 'EVIDENCE_PATH_UNSAFE',
    )
    assert.equal(swapped, true)
    assert.equal(writeCalls, 0, 'the helper must reject before writing bytes through a swapped parent')
    assert.deepEqual(readdirSync(outside), [], 'no temporary or final evidence file should remain outside the repository')
  } finally {
    fs.openSync = originalOpen
    fs.writeSync = originalWrite
    syncBuiltinESMExports()
    rmSync(root, { recursive: true, force: true })
  }
})
