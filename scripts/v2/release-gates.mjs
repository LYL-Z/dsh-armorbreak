#!/usr/bin/env node
/** ABU-002/003: write the evidence-driven release gate report. */
import { execFileSync } from 'node:child_process'
import { writeFileSync } from 'node:fs'
import { computeReleaseGates } from '../../lib/release/gates.js'

const commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const report = computeReleaseGates({ commit, allowEvidenceAncestor: true })
writeFileSync('docs/v2/acceptance/release-gates.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ commit, releasable: report.releasable, gates: Object.fromEntries(Object.entries(report.gates).map(([name, gate]) => [name, gate.status])), testReport: report.testReport }, null, 2))
if (!report.releasable) process.exitCode = 1
