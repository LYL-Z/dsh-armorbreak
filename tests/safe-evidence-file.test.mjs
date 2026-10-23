import assert from 'node:assert/strict'
import { linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
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
