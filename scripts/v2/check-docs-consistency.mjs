#!/usr/bin/env node
/** ABU-004: fail CI when user-visible release docs contradict current evidence. */
import { checkDocs } from '../../lib/release/docsConsistency.js'

const issues = checkDocs(process.cwd())
if (issues.length > 0) {
  console.error('docs-consistency: FAIL')
  for (const issue of issues) console.error(`- ${issue}`)
  process.exitCode = 1
} else {
  console.log('docs-consistency: PASS')
}
