import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { validateEvidence } from '../lib/release/evidenceValidator.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'abm-evidence-'))
  const dir = join(root, 'docs/v2/acceptance')
  mkdirSync(dir, { recursive: true })
  const files = {
    'docs/v2/acceptance/test-report.json': JSON.stringify({ commit: 'abc', tapSha256: hash('tap') }),
    'docs/v2/acceptance/test-report.tap': 'tap',
    'docs/v2/acceptance/desktop-e2e.json': JSON.stringify({ screenshots: [], l0Task: {} }),
  }
  for (const [name, content] of Object.entries(files)) writeFileSync(join(root, name), content)
  const manifest = {
    schemaVersion: 'armorbreak.evidence-manifest/v1', commit: 'abc', generatedAt: new Date().toISOString(),
    files: Object.fromEntries(Object.entries(files).map(([name, content]) => [name, { sha256: hash(content), size: Buffer.byteLength(content) }])),
  }
  writeFileSync(join(root, 'docs/v2/acceptance/evidence-manifest.json'), JSON.stringify(manifest))
  return root
}

test('evidence validator accepts pinned files and rejects tamper/missing', () => {
  const root = fixture()
  assert.equal(validateEvidence({ repoRoot: root, commit: 'abc' }).ok, true)
  writeFileSync(join(root, 'docs/v2/acceptance/test-report.tap'), 'tampered')
  const tampered = validateEvidence({ repoRoot: root, commit: 'abc' })
  assert.equal(tampered.ok, false)
  assert.ok(tampered.issues.some((issue) => /hash mismatch/.test(issue)))
  rmSync(root, { recursive: true, force: true })
})
