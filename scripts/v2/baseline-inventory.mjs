/**
 * AB2-M1-01 baseline inventory: real runtime registry, manifests, docs and a
 * fresh test/benchmark record. No network calls; no fabricated pass counts.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { ArmorBreakRuntime } from '../../lib/core/runtime.js'
import { listWorkflows } from '../../lib/core/workflows.js'

const root = resolve(import.meta.dirname, '..', '..')
const git = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim()
const testLogRaw = readFileSync(join(root, 'docs/v2/acceptance/unit-tests.log'))
const testLog = (testLogRaw[0] === 0xff && testLogRaw[1] === 0xfe) || testLogRaw.includes(0) ? testLogRaw.toString('utf16le') : testLogRaw.toString('utf8')
const testCounts = Object.fromEntries(['tests', 'pass', 'fail', 'skipped'].map((label) => { const line = testLog.split(/\r?\n/).find((entry) => entry.includes(`ℹ ${label} `)); return [label, line ? Number((line.match(/(\d+)/) ?? [])[1] ?? 0) : 0] }))
const benchResults = JSON.parse(readFileSync(join(root, 'benchmarks/results.json'), 'utf8'))

const runtime = new ArmorBreakRuntime({ stateRoot: join(root, 'docs/v2/.baseline-state') })
await runtime.init()
const capabilities = runtime.registry.list().map((cap) => ({
  id: cap.id,
  domain: cap.domain,
  title: cap.title,
  riskLevel: cap.riskLevel,
  targetKind: cap.targetKind ?? 'file',
  externalTools: cap.externalTools ?? [],
}))
const domains = [...new Set(capabilities.map((cap) => cap.domain))].sort()
const manifestSummary = readdirSync(join(root, 'lib/analyzers'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && existsSync(join(root, 'lib/analyzers', entry.name, 'manifest.js')))
  .map((entry) => {
    const text = readFileSync(join(root, 'lib/analyzers', entry.name, 'manifest.js'), 'utf8')
    const ids = [...text.matchAll(/id:\s*'([^']+)'/g)].map((match) => match[1])
    return { domain: entry.name, file: `lib/analyzers/${entry.name}/manifest.js`, idDeclarations: ids.length }
  })

let history = { available: false, taskCount: null, states: null, error: null }
try {
  const taskStore = runtime.workspace('D:\\dsh-ABM').taskStore
  const tasks = await taskStore.list(1000)
  const states = {}
  for (const task of tasks) states[task.state] = (states[task.state] ?? 0) + 1
  history = { available: true, taskCount: tasks.length, states, error: null }
} catch (error) {
  history = { available: false, taskCount: null, states: null, error: String(error?.message ?? error) }
}

const isolation = await runtime.isolationProviders.diagnose({ fresh: true }).catch((error) => ({ error: String(error?.message ?? error) }))
const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const readme = readFileSync(join(root, 'README.md'), 'utf8')
const architecture = readFileSync(join(root, 'docs/architecture.md'), 'utf8')
const acceptance = readFileSync(join(root, 'docs/acceptance-v1.2.0.md'), 'utf8')
const inconsistencies = []
if (/39 offline capabilities/.test(packageJson.description)) inconsistencies.push('package.json description still says 39 offline capabilities (actual 46)')
if (!/46/.test(readme)) inconsistencies.push('README does not contain the current 46-capability count')
if (/still mounts standard shell\/web tools/i.test(architecture)) inconsistencies.push('docs/architecture.md still contains the pre-v1.2 standard shell/web tools statement')
if (/190 \/ 190|190\/190/.test(acceptance) && testCounts.pass !== testCounts.tests) inconsistencies.push(`docs/acceptance-v1.2.0.md claims 190/190, fresh run is ${testCounts.pass}/${testCounts.tests} pass with ${testCounts.skipped} skipped`)
if (!acceptance.includes('skipped 1')) inconsistencies.push('acceptance doc does not record the fresh skipped test')
if (domains.length !== 8) inconsistencies.push(`expected 8 domains, got ${domains.length}`)
if (capabilities.length !== 46) inconsistencies.push(`expected 46 capabilities, got ${capabilities.length}`)

const baseline = {
  generatedAt: new Date().toISOString(),
  schemaVersion: 'armorbreak.baseline/v1',
  baseSha: git(['rev-parse', 'HEAD']),
  branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
  packageVersion: packageJson.version,
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  dsh: { version: process.env.DSH_CLIENT_VERSION ?? process.env.DSH_VERSION ?? 'unknown', desktopVersion: '0.2.1-rc.2 (documented; not re-probed)' },
  tests: { ...testCounts, source: 'docs/v2/acceptance/unit-tests.log', freshRun: true, skippedExamples: ['sast.semgrep missing external tool guidance'] },
  benchmark: { p50p95: benchResults, source: 'benchmarks/results.json' },
  capabilities: { count: capabilities.length, domains, ids: capabilities.map((cap) => cap.id) },
  manifests: manifestSummary,
  workflows: listWorkflows().map((workflow) => ({ id: workflow.id, name: workflow.name ?? null, steps: Array.isArray(workflow.steps) ? workflow.steps.length : null })),
  diagnostics: runtime.registry.diagnosticsReport(),
  isolation: isolation.providers ?? isolation,
  history,
  docsInconsistencies: inconsistencies,
}
const inventory = { ...baseline, capabilityDetails: capabilities }
const fs = await import('node:fs/promises')
await fs.writeFile(join(root, 'docs/v2/acceptance/baseline.json'), `${JSON.stringify(baseline, null, 2)}\n`)
await fs.writeFile(join(root, 'docs/v2/acceptance/baseline-inventory.json'), `${JSON.stringify(inventory, null, 2)}\n`)
console.log(JSON.stringify({
  baseSha: baseline.baseSha,
  branch: baseline.branch,
  version: baseline.packageVersion,
  tests: baseline.tests,
  capabilities: baseline.capabilities.count,
  domains: baseline.capabilities.domains,
  workflows: baseline.workflows.length,
  diagnostics: baseline.diagnostics.diagnostics?.length ?? null,
  history: baseline.history.taskCount,
  inconsistencies: baseline.docsInconsistencies,
}, null, 2))
