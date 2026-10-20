/**
 * ArmorBreak reproducible micro-benchmarks (zero dependencies).
 *
 * Measures the real hot paths a deployed mode exercises:
 *   - capability-registry cold start (8 domain manifests, contract validation)
 *   - binary.identify / binary.strings on a real PE sample
 *   - forensics.hash on 360 KiB
 *   - network.pcap_overview / network.flows on a synthetic 5,000-packet capture
 *   - sast.scan on a synthetic 200-file JavaScript project
 *   - report generation with 50 findings + 100 evidence records
 *   - end-to-end BinaryStaticAnalysis workflow (7 steps)
 *
 * Usage:
 *   node benchmarks/bench.mjs [--sample <path-to-PE>] [--out benchmarks/results.json]
 *
 * The script prints a table and writes machine-readable JSON. Numbers are for
 * this machine only; see docs/benchmarks.md for the recorded environment.
 */
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { generateTaskReport } from '../lib/core/reports.js'

const args = process.argv.slice(2)
const sampleArg = args.includes('--sample') ? args[args.indexOf('--sample') + 1] : null
const outArg = args.includes('--out') ? args[args.indexOf('--out') + 1] : 'benchmarks/results.json'
const DEFAULT_SAMPLE = 'D:\\dsh-ABM\\fixtures\\notepad.exe'

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b)
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))
  return sorted[index]
}

function summarize(name, samples, meta = {}) {
  const total = samples.reduce((sum, value) => sum + value, 0)
  const mean = total / samples.length
  return {
    name,
    iterations: samples.length,
    totalMs: Number(total.toFixed(2)),
    meanMs: Number(mean.toFixed(3)),
    p50Ms: Number(percentile(samples, 50).toFixed(3)),
    p95Ms: Number(percentile(samples, 95).toFixed(3)),
    p99Ms: Number(percentile(samples, 99).toFixed(3)),
    opsPerSec: Number((1000 / Math.max(mean, 0.0001)).toFixed(1)),
    ...meta,
  }
}

async function measure(name, fn, iterations, meta) {
  // One warm-up pass keeps JIT/module-load noise out of the samples.
  await fn(0)
  const samples = []
  for (let index = 0; index < iterations; index += 1) {
    const started = performance.now()
    await fn(index)
    samples.push(performance.now() - started)
  }
  const row = summarize(name, samples, meta)
  console.log(`${row.name.padEnd(34)} p50=${String(row.p50Ms).padStart(8)} ms  p95=${String(row.p95Ms).padStart(8)} ms  ${String(row.opsPerSec).padStart(10)} ops/s`)
  return row
}

function makePcap(packetCount) {
  const parts = []
  const global = Buffer.alloc(24)
  global.writeUInt32LE(0xa1b2c3d4, 0)
  global.writeUInt16LE(2, 4)
  global.writeUInt16LE(4, 6)
  global.writeUInt32LE(0, 8)
  global.writeUInt32LE(0, 12)
  global.writeUInt32LE(65535, 16)
  global.writeUInt32LE(1, 20)
  parts.push(global)
  const payload = Buffer.from('GET /index.html HTTP/1.1\r\nHost: lab.example.test\r\nUser-Agent: armorbreak-bench\r\n\r\n', 'ascii')
  for (let index = 0; index < packetCount; index += 1) {
    const frame = Buffer.alloc(14 + 20 + 8 + payload.length)
    // Ethernet
    frame.set([0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2], 0)
    frame.writeUInt16BE(0x0800, 12)
    // IPv4
    frame.writeUInt8(0x45, 14)
    frame.writeUInt8(0, 15)
    frame.writeUInt16BE(20 + 8 + payload.length, 16)
    frame.writeUInt16BE(index & 0xffff, 18)
    frame.writeUInt16BE(0x4000, 20)
    frame.writeUInt8(64, 22)
    frame.writeUInt8(17, 23)
    frame.set([10, 20, 0, 1], 26)
    frame.set([10, 20, 0, 2], 30)
    // UDP
    frame.writeUInt16BE(1024 + (index % 30000), 34)
    frame.writeUInt16BE(80, 36)
    frame.writeUInt16BE(8 + payload.length, 38)
    frame.writeUInt16BE(0, 40)
    payload.copy(frame, 42)
    const record = Buffer.alloc(16)
    record.writeUInt32LE(1700000000 + Math.floor(index / 1000), 0)
    record.writeUInt32LE((index % 1000) * 1000, 4)
    record.writeUInt32LE(frame.length, 8)
    record.writeUInt32LE(frame.length, 12)
    parts.push(record, frame)
  }
  return Buffer.concat(parts)
}

async function makeSourceTree(fileCount, root) {
  await mkdir(join(root, 'src'), { recursive: true })
  await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'bench-project', version: '1.0.0', dependencies: { lodash: '4.17.20', express: '4.18.2' } }))
  for (let index = 0; index < fileCount; index += 1) {
    const body = [
      `// synthetic module ${index}`,
      `export function handler${index}(userId) {`,
      `  const ret = eval("(" + userId + ")")`,
      `  return ret`,
      `}`,
      `export const key${index} = "AKIAIOSFODNN7EXAMPLE"`,
      '',
    ].join('\n')
    await writeFile(join(root, 'src', `module-${index}.js`), body)
  }
  return root
}

async function main() {
  const sample = sampleArg && existsSync(sampleArg) ? sampleArg : existsSync(DEFAULT_SAMPLE) ? DEFAULT_SAMPLE : null
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-bench-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-bench-ws-'))

  const startedInit = performance.now()
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const initMs = performance.now() - startedInit
  const capabilities = runtime.registry.list()
  console.log(`registry: ${capabilities.length} capabilities / ${runtime.registry.domainsList().length} domains, cold start ${initMs.toFixed(1)} ms\n`)

  const results = []
  results.push({ name: 'registry-cold-start', iterations: 1, totalMs: Number(initMs.toFixed(2)), meanMs: Number(initMs.toFixed(2)), p50Ms: Number(initMs.toFixed(2)), p95Ms: Number(initMs.toFixed(2)), p99Ms: Number(initMs.toFixed(2)), opsPerSec: Number((1000 / initMs).toFixed(2)), capabilityCount: capabilities.length, domainCount: runtime.registry.domainsList().length })

  const samplePath = sample ? await copySample(sample, workspace) : null
  const scope = runtime.workspace(workspace).scope
  const store = runtime.workspace(workspace).taskStore

  async function buildRawInput(capabilityId, targetPath, options = {}) {
    const capability = runtime.registry.get(capabilityId)
    if (!capability) return null
    const task = await store.create({ title: 'bench', targetPath, targetKind: capability.targetKind ?? 'file', steps: [{ id: 'bench', title: 'bench', capabilityId, options }] })
    await runtime.runner.prepareTask(task)
    const input = await runtime.runner.buildCapabilityInput({ task, capability, targetPath, options, controller: new AbortController(), log: [] })
    return { capability, input }
  }

  async function measureRaw(capabilityId, targetPath, iterations, options = {}) {
    const built = await buildRawInput(capabilityId, targetPath, options)
    if (!built) return null
    return measure(`${capabilityId} (parser)`, () => built.capability.run(built.input), iterations, { mode: 'parser', capability: capabilityId })
  }

  async function measureRunner(capabilityId, targetPath, iterations, options = {}) {
    const capability = runtime.registry.get(capabilityId)
    if (!capability) return null
    return measure(`${capabilityId} (through runner)`, async () => {
      const task = await store.create({ title: 'bench', targetPath, targetKind: capability.targetKind ?? 'file', steps: [{ id: 'bench', title: 'bench', capabilityId, options }] })
      await runtime.runner.prepareTask(task)
      await runtime.runner.runCapability({ task, capabilityId, targetPath, options, stepId: 'bench' })
    }, iterations, { mode: 'runner', capability: capabilityId })
  }

  if (samplePath) {
    results.push(await measureRaw('binary.identify', samplePath, 60))
    results.push(await measureRaw('binary.strings', samplePath, 60))
    results.push(await measureRaw('forensics.hash', samplePath, 80))
    results.push(await measureRaw('binary.entropy', samplePath, 60))
    results.push(await measureRunner('forensics.hash', samplePath, 20))
  }

  const pcap = makePcap(5000)
  const pcapPath = join(workspace, 'bench.pcap')
  await writeFile(pcapPath, pcap)
  results.push(await measureRaw('network.pcap_overview', pcapPath, 30))
  results.push(await measureRaw('network.flows', pcapPath, 30))

  const sourceRoot = join(workspace, 'bench-src')
  await makeSourceTree(200, sourceRoot)
  results.push(await measureRaw('sast.scan', sourceRoot, 10, { maxFiles: 500 }))

  // Report generation: 50 findings + 100 evidence records in one task.
  const reportTask = await store.create({ title: 'report benchmark', targetKind: 'none' })
  const evidenceStore = store.evidenceStore(reportTask.id)
  for (let index = 0; index < 100; index += 1) {
    await evidenceStore.addEvidence({ title: `evidence ${index}`, kind: 'bench', excerpt: `bench evidence ${index}` })
  }
  for (let index = 0; index < 50; index += 1) {
    await evidenceStore.addFinding({ title: `finding ${index}`, severity: 'medium', description: 'bench', verification: 'hypothesis', method: 'bench', cwe: 'CWE-200', cvss: 5.3, remediation: 'bench', target: `target-${index}` }, {})
  }
  results.push(await measure('report-markdown', () => generateTaskReport(runtime, reportTask, { format: 'markdown' }), 20))
  results.push(await measure('report-html', () => generateTaskReport(runtime, reportTask, { format: 'html' }), 20))
  results.push(await measure('report-sarif', () => generateTaskReport(runtime, reportTask, { format: 'sarif' }), 20))

  // End-to-end workflow (7 steps) through the state machine.
  if (samplePath) {
    const workflowTask = () => {
      return (async () => {
        const task = await store.create({ title: 'bench workflow', targetPath: samplePath, targetKind: 'file', workflowId: 'BinaryStaticAnalysis', steps: workflowSteps() })
        return runtime.runner.runWorkflow(task, { generateReport: true })
      })()
    }
    results.push(await measure('BinaryStaticAnalysis-workflow', workflowTask, 5))
  }

  const result = {
    schema: 'armorbreak/benchmarks/v1',
    generatedAt: new Date().toISOString(),
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpus: (await import('node:os')).cpus().length,
      cpu: (await import('node:os')).cpus()[0]?.model ?? 'unknown',
      totalMemGiB: Number(((await import('node:os')).totalmem() / 1024 ** 3).toFixed(2)),
      capabilityCount: capabilities.length,
      domainCount: runtime.registry.domainsList().length,
      sample: samplePath ?? null,
      sampleBytes: samplePath ? (await import('node:fs')).statSync(samplePath).size : null,
      pcapBytes: pcap.length,
      pcapPackets: 5000,
      sastFiles: 200,
      reportFindings: 50,
      reportEvidence: 100,
      notes: 'parser rows measure capability.run on a prepared bounded input; runner rows include task state transitions, evidence/finding persistence and audit logging',
    },
    results,
    memory: {
      rssMiB: Number((process.memoryUsage().rss / 1024 ** 2).toFixed(1)),
      heapUsedMiB: Number((process.memoryUsage().heapUsed / 1024 ** 2).toFixed(1)),
    },
  }
  await writeFile(outArg, `${JSON.stringify(result, null, 2)}\n`, 'utf8')
  console.log(`\nwrote ${outArg}`)
}

function workflowSteps() {
  return [
    { id: 'identify', title: 'identify', capabilityId: 'binary.identify', options: {} },
    { id: 'headers', title: 'headers', capabilityId: 'binary.headers', options: {} },
    { id: 'structure', title: 'structure', capabilityId: 'binary.structure', options: {} },
    { id: 'strings', title: 'strings', capabilityId: 'binary.strings', options: {} },
    { id: 'entropy', title: 'entropy', capabilityId: 'binary.entropy', options: {} },
    { id: 'hash', title: 'hash', capabilityId: 'forensics.hash', options: {} },
    { id: 'ioc', title: 'ioc', capabilityId: 'forensics.ioc', options: {} },
  ]
}

async function copySample(source, workspace) {
  const target = join(workspace, 'sample.exe')
  const { copyFile } = await import('node:fs/promises')
  await copyFile(source, target)
  return target
}

await main()
