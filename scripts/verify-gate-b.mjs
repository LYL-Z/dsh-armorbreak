#!/usr/bin/env node
/**
 * Gate B verification for the Stage B external tool adapters.
 *
 * Runs the REAL Semgrep and Trivy CLIs against the local fixture
 * `fixtures/gate-b-sample` with the local rule set
 * `fixtures/gate-b-rules/armorbreak-local.yml`, in two layers:
 *
 *   1. capability layer: the registered `sast.semgrep` / `sast.trivy`
 *      capabilities are called directly with a bare env (no test seam), so the
 *      raw tool invocation and full normalized findings are captured;
 *   2. runner layer: an L0 directory task executes the same two steps through
 *      ExecutionRunner, proving policy/evidence-chain/audit/report integration.
 *
 * The script is intentionally strict: it fails unless both tools are installed,
 * both steps complete, the evidence chain verifies, and both scanners return
 * findings. Nothing is downloaded except by the operator beforehand
 * (`trivy fs --download-db-only`); Semgrep rules are always local.
 *
 * Usage: node scripts/verify-gate-b.mjs
 * Output artifacts: docs/acceptance/gate-b-{summary,task,findings}.json, gate-b-report.md
 */
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { copyFile, mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ArmorBreakRuntime } from '../lib/core/runtime.js'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const SAMPLE_DIR = join(REPO_ROOT, 'fixtures', 'gate-b-sample')
const RULES_FILE = join(REPO_ROOT, 'fixtures', 'gate-b-rules', 'armorbreak-local.yml')
const OUT_DIR = join(REPO_ROOT, 'docs', 'acceptance')

const SEMGREP_OPTIONS = { config: RULES_FILE, timeoutMs: 180_000 }
const TRIVY_OPTIONS = { scanners: 'vuln,secret', severity: 'HIGH,CRITICAL', timeoutMs: 300_000 }

const EXPECTED_SEMGREP_RULES = [
  'armorbreak.js.eval-dynamic',
  'armorbreak.js.child-process-concat',
  'armorbreak.js.sql-concat',
  'armorbreak.js.weak-hash-md5',
  'armorbreak.secret.aws-access-key',
]
const EXPECTED_TRIVY_KINDS = ['lang-pkgs', 'secret']

/** @param {string} file */
async function sha256File(file) {
  return createHash('sha256').update(await readFile(file)).digest('hex')
}

/** Stable directory manifest: sha256 over sorted relative paths + file bytes. */
async function manifest(root) {
  /** @type {string[]} */
  const files = []
  /** @param {string} dir */
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) await walk(full)
      else if (entry.isFile()) files.push(full)
    }
  }
  await walk(root)
  files.sort()
  const hash = createHash('sha256')
  for (const file of files) {
    hash.update(relative(root, file).split(sep).join('/'))
    hash.update('\0')
    hash.update(await readFile(file))
    hash.update('\0')
  }
  return { sha256: hash.digest('hex'), files: files.map((file) => relative(root, file).split(sep).join('/')) }
}

/** @param {unknown} value */
function rel(value) {
  return typeof value === 'string' ? value.replaceAll('\\', '/') : value
}

/** @param {any[]} findings @param {string} key */
function countBy(findings, key) {
  /** @type {Record<string, number>} */
  const out = {}
  for (const finding of findings) {
    const value = String(finding[key] ?? 'unknown')
    out[value] = (out[value] ?? 0) + 1
  }
  return out
}

async function main() {
  if (!existsSync(SAMPLE_DIR)) throw new Error(`fixture missing: ${SAMPLE_DIR}`)
  if (!existsSync(RULES_FILE)) throw new Error(`local Semgrep rules missing: ${RULES_FILE}`)

  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-gate-b-state-'))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()

  // 1. Detection: real `semgrep --version` / `trivy --version` probes.
  /** @type {Record<string, any>} */
  const tools = {}
  for (const toolId of ['semgrep', 'trivy']) {
    const probe = await runtime.health.probe(toolId, { version: true, refresh: true })
    tools[toolId] = probe
    if (!probe.found) {
      throw new Error(`${toolId} is not installed or not on PATH. ${probe.install?.windows ?? ''} (then re-run this script)`)
    }
    if (!probe.version) {
      throw new Error(`${toolId} was found at ${probe.path} but its version probe failed: ${probe.versionError ?? 'no output'}`)
    }
  }
  for (const capabilityId of ['sast.semgrep', 'sast.trivy']) {
    if (!runtime.registry.get(capabilityId)) throw new Error(`capability ${capabilityId} is not registered; the Stage B manifest failed to load`)
  }

  // 2. Capability layer: real CLIs through the registered capabilities with a
  //    bare env (no `env.execExternal` test seam), capturing full normalization.
  const direct = {
    semgrep: await runtime.registry.get('sast.semgrep').run({ targetPath: SAMPLE_DIR, options: SEMGREP_OPTIONS, env: {} }),
    trivy: await runtime.registry.get('sast.trivy').run({ targetPath: SAMPLE_DIR, options: TRIVY_OPTIONS, env: {} }),
  }

  // 3. Runner layer: the same steps as a user task, for the integrated evidence chain.
  const workspace = REPO_ROOT
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'Gate B - real Semgrep/Trivy CLI through Stage B adapters',
    objective: 'Verify external tool adapters against the real CLIs on a local, intentionally vulnerable fixture.',
    targetPath: SAMPLE_DIR,
    targetKind: 'directory',
    tags: ['gate-b', 'stage-b', 'external-adapters'],
    steps: [
      { id: 'semgrep', title: 'Semgrep scan with local rules', capabilityId: 'sast.semgrep', options: SEMGREP_OPTIONS },
      { id: 'trivy', title: 'Trivy fs scan with local vulnerability DB', capabilityId: 'sast.trivy', options: TRIVY_OPTIONS },
    ],
  })
  console.log(`task ${task.id} created: ${task.targetKind} ${rel(task.targetPath)}`)
  const finished = await runtime.runner.runWorkflow(task, { generateReport: true })
  const evidenceStore = store.evidenceStore(finished.id)
  const { findings: storedFindings } = await evidenceStore.readFindings()
  const chain = await evidenceStore.verifyChain()

  // 4. Fail-closed acceptance checks.
  const semgrepFindings = direct.semgrep.findings
  const trivyFindings = direct.trivy.findings
  const semgrepRules = [...new Set(semgrepFindings.map((finding) => finding.sourceRule))].sort()
  // Semgrep namespaces rules from a local --config file with a config-id prefix
  // (derived from the config path), so compare by suffix rather than equality.
  const missingRules = EXPECTED_SEMGREP_RULES.filter((rule) => !semgrepRules.some((seen) => String(seen) === rule || String(seen).endsWith(`.${rule}`)))
  const trivyKinds = [...direct.trivy.data.kinds].sort()
  const trivyNormalizedKinds = [...new Set(trivyFindings.map((finding) => finding.location?.kind ?? 'unknown'))].sort()
  const missingKinds = EXPECTED_TRIVY_KINDS.filter((kind) => !trivyKinds.includes(kind))
  const directTotal = semgrepFindings.length + trivyFindings.length
  const steps = finished.steps.map((/** @type {any} */ step) => ({
    id: step.id,
    capabilityId: step.capabilityId,
    status: step.status,
    error: step.error ?? null,
    durationMs: step.durationMs ?? null,
    summary: step.summary ?? null,
    evidence: Array.isArray(step.evidenceIds) ? step.evidenceIds.length : 0,
    findings: Array.isArray(step.findingIds) ? step.findingIds.length : 0,
  }))
  const problems = []
  if (finished.state !== 'COMPLETED') problems.push(`task ended ${finished.state}; non-DONE steps: ${steps.filter((step) => step.status !== 'DONE').map((step) => `${step.id}=${step.status}:${step.error ?? ''}`).join('; ') || 'none'}`)
  if (!chain.valid) problems.push(`evidence chain is broken at ${chain.brokenAt} (${chain.records} records)`)
  if (semgrepFindings.length === 0) problems.push('Semgrep returned no normalized findings')
  if (semgrepFindings.some((finding) => finding.verification !== 'hypothesis')) problems.push('Semgrep findings must default to verification=hypothesis')
  if (missingRules.length > 0) problems.push(`Semgrep did not report these local rules: ${missingRules.join(', ')}`)
  if (!direct.semgrep.data.toolVersion) problems.push('Semgrep report did not include a tool version')
  if (trivyFindings.length === 0) problems.push('Trivy returned no normalized findings')
  if (trivyFindings.some((finding) => finding.verification !== 'hypothesis')) problems.push('Trivy findings must default to verification=hypothesis')
  if (missingKinds.length > 0) problems.push(`Trivy did not return these result kinds: ${missingKinds.join(', ')} (got ${trivyKinds.join(', ') || 'none'})`)
  if (direct.trivy.meta.offlineDb !== true) problems.push('Trivy was not invoked with the offline-DB contract (--skip-db-update)')
  if (storedFindings.length !== directTotal) problems.push(`runner evidence store has ${storedFindings.length} findings, capability layer returned ${directTotal}`)

  const generatedAt = new Date().toISOString()
  await mkdir(OUT_DIR, { recursive: true })

  /** @type {Record<string, {sha256: string, bytes: number}>} */
  const artifacts = {}
  const reportSource = finished.report?.path ?? null
  if (reportSource && existsSync(reportSource)) {
    const target = join(OUT_DIR, 'gate-b-report.md')
    await copyFile(reportSource, target)
    artifacts['gate-b-report.md'] = { sha256: await sha256File(target), bytes: (await readFile(target)).length }
  } else {
    problems.push('task report was not generated')
  }

  const summary = {
    gate: 'B',
    version: 'v1.1.0-stage-b',
    generatedAt,
    workspace: rel(workspace),
    fixture: {
      path: rel(SAMPLE_DIR),
      sha256: await manifest(SAMPLE_DIR),
    },
    rules: { path: rel(RULES_FILE), sha256: await sha256File(RULES_FILE) },
    tools: Object.fromEntries(Object.entries(tools).map(([toolId, probe]) => [toolId, {
      found: probe.found,
      path: rel(probe.path),
      version: probe.version,
    }])),
    capabilityLayer: {
      semgrep: {
        summary: direct.semgrep.summary,
        findings: semgrepFindings.length,
        rules: semgrepRules,
        expectedRulesMissing: missingRules,
        bySeverity: countBy(semgrepFindings, 'severity'),
        toolVersion: direct.semgrep.data.toolVersion,
        resultCount: direct.semgrep.data.resultCount,
      },
      trivy: {
        summary: direct.trivy.summary,
        findings: trivyFindings.length,
        resultKinds: trivyKinds,
        normalizedLocationKinds: trivyNormalizedKinds,
        bySeverity: countBy(trivyFindings, 'severity'),
        resultCount: direct.trivy.data.resultCount,
        offlineDb: direct.trivy.meta.offlineDb,
        dbDownloadAllowed: direct.trivy.data.dbDownloadAllowed,
      },
    },
    runnerLayer: {
      taskId: finished.id,
      state: finished.state,
      targetPath: rel(finished.targetPath),
      targetKind: finished.targetKind,
      riskMax: finished.riskMax,
      stats: finished.stats,
      steps,
      stateHistory: finished.stateHistory.map((/** @type {any} */ item) => ({ state: item.state, reason: item.reason })),
      report: finished.report ? { path: rel(finished.report.path), sha256: finished.report.sha256 } : null,
      evidence: { chainValid: chain.valid, records: chain.records, brokenAt: chain.brokenAt ?? null },
    },
    findings: { total: directTotal, storedByRunner: storedFindings.length },
    artifacts,
    problems,
    result: problems.length === 0 ? 'PASS' : 'FAIL',
  }

  await writeFile(join(OUT_DIR, 'gate-b-findings.json'), `${JSON.stringify({ generatedAt, semgrep: direct.semgrep, trivy: direct.trivy }, null, 2)}\n`, 'utf8')
  await writeFile(join(OUT_DIR, 'gate-b-task.json'), `${JSON.stringify(finished, null, 2)}\n`, 'utf8')
  await writeFile(join(OUT_DIR, 'gate-b-summary.json'), `${JSON.stringify(summary, null, 2)}\n`, 'utf8')

  console.log('')
  for (const toolId of ['semgrep', 'trivy']) {
    console.log(`${toolId.padEnd(8)} ${tools[toolId].version}  ${rel(tools[toolId].path)}`)
  }
  console.log(`capability  semgrep: ${semgrepFindings.length} findings (${semgrepRules.length} rules, tool ${direct.semgrep.data.toolVersion})`)
  console.log(`capability  trivy:   ${trivyFindings.length} findings (${trivyKinds.join(', ')}; offlineDb=${direct.trivy.meta.offlineDb})`)
  console.log(`runner      ${finished.state}  id=${finished.id}`)
  for (const step of steps) {
    console.log(`step        ${step.id.padEnd(8)} ${step.status.padEnd(5)} ${step.findings} findings / ${step.evidence} evidence  ${step.durationMs ?? '?'} ms`)
  }
  console.log(`evidence    chain ${chain.valid ? 'verified' : 'BROKEN'} (${chain.records} records); ${storedFindings.length} findings stored by runner`)
  console.log(`artifacts: ${['gate-b-summary.json', 'gate-b-findings.json', 'gate-b-task.json'].concat(Object.keys(artifacts)).join(', ')} in docs/acceptance/`)
  if (problems.length > 0) {
    console.error(`\nGate B FAILED:\n- ${problems.join('\n- ')}`)
    process.exitCode = 1
    return
  }
  console.log('\nGate B PASS')
}

main().catch((error) => {
  console.error(`Gate B verification error: ${/** @type {any} */ (error)?.message ?? error}`)
  process.exitCode = 1
})
