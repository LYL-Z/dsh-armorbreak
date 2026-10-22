import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { checkDocs } from '../lib/release/docsConsistency.js'

test('docs consistency catches stale BLOCKED/NOT READY/test-count text', () => {
  const root = mkdtempSync(join(tmpdir(), 'abm-docs-'))
  const files = {
    'package.json': '{"version":"2.0.0"}',
    'docs/v2/release/readiness.json': '{"package":{"version":"2.0.0"}}',
    'docs/v2/release/platform-matrix.md': '| Windows DSH Desktop real GUI + model | — | **BLOCKED** |\n',
    'docs/v2/release/license-audit.md': 'currently **NOT READY**\n',
    'docs/v2/acceptance/test-matrix.md': '| Unit | `node --test` 269 tests |\n',
  }
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(root, name, '..'), { recursive: true })
    writeFileSync(join(root, name), content)
  }
  const issues = checkDocs(root)
  assert.ok(issues.length >= 3)
  assert.ok(issues.some((issue) => /platform-matrix|BLOCKED/.test(issue)))
  assert.ok(issues.some((issue) => /NOT READY/.test(issue)))
  assert.ok(issues.some((issue) => /test matrix|stale/.test(issue)))
  rmSync(root, { recursive: true, force: true })
})
