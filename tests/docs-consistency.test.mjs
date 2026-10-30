import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

test('V2.3 candidate package version does not rewrite the historical V2.2 Stable contract', () => {
  const root = mkdtempSync(join(tmpdir(), 'abm-v23-docs-'))
  const files = {
    'package.json': '{"version":"2.3.0"}',
    'docs/v2/release/readiness.json': '{"package":{"version":"2.2.0"}}',
    'docs/v2/release/v2.2-stable-scope-v1.json': JSON.stringify({
      schemaVersion: 'armorbreak.v2.2-stable-scope/v1', packageVersion: '2.2.0', tag: 'v2.2.0',
      legacyFullGa: { legacyReleaseSnapshot: { status: 'HISTORICAL_RC_EVIDENCE', file: 'docs/v2/release/readiness.json', packageVersion: '2.2.0', preserveOriginalEvidence: true } },
    }),
    'docs/v2.3/compatibility-matrix.json': JSON.stringify({ schemaVersion: 'armorbreak.v2.3.compatibility-matrix/v1', baselineSha: '66ec0017af4b9d636f09e45f7cf55eed060512ac', milestones: [{ id: 'P0-H', status: 'IN_PROGRESS' }] }),
    'docs/v2.3/evidence/p0-h/acceptance-manifest.json': JSON.stringify({ baselineSha: '66ec0017af4b9d636f09e45f7cf55eed060512ac' }),
    'docs/v2.3/acceptance-report.md': '## 8. RELEASE READINESS\n\n- **NOT_READY**\n',
  }
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(root, name, '..'), { recursive: true })
    writeFileSync(join(root, name), content)
  }
  assert.deepEqual(checkDocs(root), [])
  const policyPath = join(root, 'docs/v2/release/v2.2-stable-scope-v1.json')
  const policy = JSON.parse(readFileSync(policyPath, 'utf8'))
  policy.tag = 'v2.3.0'
  writeFileSync(policyPath, JSON.stringify(policy))
  assert.ok(checkDocs(root).some((issue) => /historical V2\.2 Stable policy/.test(issue)))
  rmSync(root, { recursive: true, force: true })
})
