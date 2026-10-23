#!/usr/bin/env node
/** ABU-006: evidence validator; exits non-zero on any missing/tampered reference. */
import { execFileSync } from 'node:child_process'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'

const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const arg = (name) => {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] && !process.argv[index + 1].startsWith('--') ? process.argv[index + 1] : undefined
}
const allowDocsOnly = process.argv.includes('--allow-docs-only')
const base = arg('--base') ?? process.env.EVIDENCE_BASE_SHA
const result = validateEvidence({ repoRoot: process.cwd(), commit, base, allowEvidenceAncestor: true, allowDocsOnly })
console.log(JSON.stringify(result, null, 2))
if (!result.ok) process.exitCode = 1
