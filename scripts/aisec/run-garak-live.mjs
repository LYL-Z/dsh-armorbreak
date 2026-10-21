#!/usr/bin/env node
/**
 * AB2-M3-03 live Garak probe runner. Only the offline `test` generator and two
 * harmless research probes are allowed; raw payloads are not persisted.
 */
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { mapGarakReport, planGarak } from '../../lib/aisec/garakAdapter.js'
import { createMockTarget } from '../../lib/aisec/evaluator.js'

const python = process.env.ARMORBREAK_GARAK_PYTHON ?? 'D:\\dsh-ABM\\aisec-venv\\Scripts\\python.exe'
const garak = join('D:\\dsh-ABM\\aisec-venv\\Scripts', 'garak.exe')
const reportDir = 'D:\\dsh-ABM\\garak-report'
const plan = planGarak({ target: createMockTarget('garak-local'), probes: ['promptinject', 'encoding'] })
const report = { schemaVersion: 'armorbreak.garak-live/v1', generatedAt: new Date().toISOString(), command: null, status: 'NOT_RUN', results: [], error: null, plan: { traceId: plan.traceId, probes: plan.probes } }
if (!existsSync(garak)) {
  report.error = 'garak executable not installed'
} else {
  await mkdir(reportDir, { recursive: true })
  const args = ['--model_type', 'test', '--probes', 'promptinject,encoding', '--report_prefix', join(reportDir, 'run')]
  report.command = `${garak} ${args.join(' ')}`
  const run = spawnSync(garak, args, { encoding: 'utf8', timeout: 180_000, windowsHide: true })
  report.exitCode = run.status
  report.stdout = (run.stdout ?? '').slice(-2000)
  report.stderr = (run.stderr ?? '').slice(-2000)
  if (run.status !== 0) report.error = 'garak exited non-zero'
  try {
    const files = await readdir(reportDir)
    const jsonl = files.find((file) => file.endsWith('.report.jsonl')) ?? files.find((file) => file.endsWith('.jsonl'))
    if (jsonl) {
      report.results = mapGarakReport({ text: await readFile(join(reportDir, jsonl), 'utf8'), plan, targetId: 'garak-local' })
      report.status = 'PASS'
    } else if (!report.error) report.error = 'no Garak JSONL report found'
  } catch (error) { report.error = String(error?.message ?? error).slice(0, 300) }
}
await writeFile('docs/v2/acceptance/garak-live.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ status: report.status, exitCode: report.exitCode ?? null, results: report.results.length, error: report.error }, null, 2))
if (report.status !== 'PASS') process.exitCode = 1
