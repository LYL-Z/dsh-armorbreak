#!/usr/bin/env node
/** ABU-006: evidence validator; exits non-zero on any missing/tampered reference. */
import { execFileSync } from 'node:child_process'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'

const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const result = validateEvidence({ repoRoot: process.cwd(), commit, allowEvidenceAncestor: true })
console.log(JSON.stringify(result, null, 2))
if (!result.ok) process.exitCode = 1
