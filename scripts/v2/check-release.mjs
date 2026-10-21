#!/usr/bin/env node
/** Release readiness check. Never marks the release ready unless every gate passes. */
import { readFile, readdir, writeFile } from 'node:fs/promises'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'

async function readJson(path) { try { return JSON.parse((await readFile(path, 'utf8')).replace(/^\uFEFF/, '')) } catch { return null } }
const pkg = await readJson('package.json')
const gates = await readJson('docs/v2/acceptance/release-gates.json')
const sbom = await readJson('docs/v2/release/sbom.spdx.json')
const manifest = await readJson('docs/v2/acceptance/evidence-manifest.json')
const testReport = await readJson('docs/v2/acceptance/test-report.json')
const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const evidenceOk = Boolean(testReport?.counts?.fail === 0 && testReport?.counts?.tests > 0 && manifest?.files && gates?.evidenceManifest?.valid !== false)
const statuses = {}
try {
  for (const file of await readdir('docs/v2/tasks')) {
    if (!file.startsWith('AB2-M4-')) continue
    const text = await readFile(join('docs/v2/tasks', file), 'utf8')
    statuses[file] = text.match(/^status:\s*(\S+)/m)?.[1] ?? 'UNKNOWN'
  }
} catch { /* no docs */ }
const required = ['AB2-M4-03.md', 'AB2-M4-04.md', 'AB2-M4-06.md', 'AB2-M4-07.md', 'AB2-M4-10.md', 'AB2-M4-11.md', 'AB2-M4-12.md']
const incomplete = required.filter((file) => statuses[file] !== 'DONE')
const ready = Boolean(gates?.releasable === true && incomplete.length === 0 && sbom && evidenceOk)
const result = {
  schemaVersion: 'armorbreak.release-readiness/v1',
  generatedAt: new Date().toISOString(),
  package: { name: pkg?.name, version: pkg?.version },
  sbom: Boolean(sbom),
  commit: head,
  evidence: { manifestCommit: manifest?.commit ?? null, testReportCommit: testReport?.commit ?? null, testCounts: testReport?.counts ?? null, current: evidenceOk },
  gates: gates?.gates ?? null,
  m4: statuses,
  incomplete,
  ready,
  reason: ready ? 'all required gates/tasks/evidence match the current commit' : 'release blocked by incomplete gates/tasks or stale/missing evidence; not a failure of the build',
}
await writeFile('docs/v2/release/readiness.json', `${JSON.stringify(result, null, 2)}\n`)
console.log(JSON.stringify({ ready: result.ready, incomplete, gates: Object.fromEntries(Object.entries(result.gates ?? {}).map(([key, value]) => [key, value.status])) }, null, 2))
