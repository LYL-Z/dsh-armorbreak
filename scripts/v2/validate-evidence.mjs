#!/usr/bin/env node
/** ABU-006: evidence validator; exits non-zero on any missing/tampered reference. */
import { execFileSync } from 'node:child_process'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'

const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const arg = (name) => {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] && !process.argv[index + 1].startsWith('--') ? process.argv[index + 1] : undefined
}
const isTag = process.env.GITHUB_REF_TYPE === 'tag' || String(process.env.GITHUB_REF ?? '').startsWith('refs/tags/')
const allowDocsOnly = process.argv.includes('--allow-docs-only') && !isTag
const allowEvidenceOnly = process.argv.includes('--allow-evidence-only')
const requireClean = process.argv.includes('--require-clean')
const base = arg('--base') ?? process.env.EVIDENCE_BASE_SHA
const result = validateEvidence({ repoRoot: process.cwd(), commit, base, allowEvidenceAncestor: allowEvidenceOnly, allowDocsOnly, requireClean })
if (process.env.GITHUB_SHA && process.env.GITHUB_SHA !== commit) {
  result.ok = false
  result.issues.push(`HEAD ${commit} does not match GITHUB_SHA ${process.env.GITHUB_SHA}`)
}
console.log(JSON.stringify(result, null, 2))
if (!result.ok) process.exitCode = 1
