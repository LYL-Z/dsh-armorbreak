/**
 * AB2-M1-10 frozen Core benchmark (initial runnable subset).
 *
 * Executes real L0 capabilities through the real TaskStore/Runner on generated
 * fixtures. The manifest is written next to the result so every input hash and
 * assertion is reproducible. The task-book target of 62 scenarios is reported as
 * coverage honestly; missing corpora are NOT_RUN, never PASS.
 */
import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../../lib/core/runtime.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

function makePcap(path) {
  const http = Buffer.from('GET /v2/flag HTTP/1.1\r\nHost: example.test\r\nUser-Agent: core-bench\r\n\r\n', 'latin1')
  const eth = Buffer.alloc(14)
  Buffer.from('001122334455', 'hex').copy(eth, 0)
  Buffer.from('66778899aabb', 'hex').copy(eth, 6)
  eth.writeUInt16BE(0x0800, 12)
  const ip = Buffer.alloc(20)
  ip[0] = 0x45; ip.writeUInt16BE(20 + 20 + http.length, 2); ip[8] = 64; ip[9] = 6
  ip.writeUInt32BE(0x0a000005, 12); ip.writeUInt32BE(0x5db8d822, 16)
  const tcp = Buffer.alloc(20)
  tcp.writeUInt16BE(12345, 0); tcp.writeUInt16BE(80, 2); tcp.writeUInt32BE(1, 4); tcp.writeUInt32BE(0, 8)
  tcp[12] = 0x50; tcp[13] = 0x18
  const frame = Buffer.concat([eth, ip, tcp, http])
  const global = Buffer.alloc(24)
  global.writeUInt32LE(0xa1b2c3d4, 0); global.writeUInt16LE(2, 4); global.writeUInt16LE(4, 6); global.writeUInt32LE(65535, 16); global.writeUInt32LE(1, 20)
  const header = Buffer.alloc(16)
  header.writeUInt32LE(1700000000, 0); header.writeUInt32LE(frame.length, 8); header.writeUInt32LE(frame.length, 12)
  return Buffer.concat([global, header, frame])
}

const workspace = await mkdtemp(join(tmpdir(), 'abm-core-bench-ws-'))
const stateRoot = await mkdtemp(join(tmpdir(), 'abm-core-bench-state-'))
const fixtures = {
  'flag.txt': 'CTF{b3nch_f1ag} and another flag{core_ready}\n',
  'base64.txt': 'SGVsbG8gQXJtb3JCcmVhayBWMiA=\n',
  'hash.txt': 'd41d8cd98f00b204e9800998ecf8427e\n',
  'ioc.txt': 'C2 http://malicious.example.test/payload 10.20.30.40 2001:db8::1\n',
  'http.txt': 'POST /api/login HTTP/1.1\r\nHost: app.example.test\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n',
  'headers.txt': 'Content-Type: text/html\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n',
  'openapi.yaml': 'openapi: 3.0.0\ninfo:\n  title: Core Bench\n  version: 1.0.0\nservers:\n  - url: https://api.example.test\npaths:\n  /health:\n    get:\n      responses:\n        "200":\n          description: ok\n',
  'random.bin': Buffer.from(Array.from({ length: 8192 }, (_, i) => (i * 73 + 19) & 0xff)),
  'strings.bin': Buffer.from('MZ\x90\x00ArmorBreakCoreBench http://bench.example.test/flag AKIAIOSFODNN7EXAMPLE\n', 'latin1'),
}
for (const [name, value] of Object.entries(fixtures)) await writeFile(join(workspace, name), value)
await writeFile(join(workspace, 'http-dns.pcap'), makePcap(join(workspace, 'http-dns.pcap')))
const sourceDir = join(workspace, 'source')
await mkdir(sourceDir, { recursive: true })
await writeFile(join(sourceDir, 'app.js'), 'const express = require("express")\nconst app = express()\napp.get("/x", (req, res) => { eval(req.query.code); res.send("ok") })\napp.listen(3000)\n')
await writeFile(join(sourceDir, 'package.json'), JSON.stringify({ name: 'core-bench', version: '1.0.0', dependencies: { express: '4.18.2' } }))

// Frozen scenario manifest: capabilities that are genuinely runnable with the
// generated fixtures above. The task-book target is 62; missing corpora are
// reported as NOT_RUN in offline-score.json, not silently counted.
const scenarios = [
  { id: 'CTF-001', domain: 'ctf', capability: 'ctf.flag_scan', target: 'flag.txt', kind: 'file', expectSummary: /flag/i },
  { id: 'CTF-002', domain: 'ctf', capability: 'ctf.decode', target: 'base64.txt', kind: 'file', options: { transforms: ['base64'] }, expectSummary: /base64|Hello|ArmorBreak/i },
  { id: 'CTF-003', domain: 'ctf', capability: 'ctf.hash_id', target: 'hash.txt', kind: 'file', expectSummary: /md5|MD5|hash/i },
  { id: 'FOR-001', domain: 'forensics', capability: 'forensics.hash', target: 'random.bin', kind: 'file', expectSummary: /sha256|SHA-256/i },
  { id: 'FOR-002', domain: 'forensics', capability: 'forensics.filetype', target: 'random.bin', kind: 'file', expectSummary: /未知|unknown|binary|data/i },
  { id: 'FOR-003', domain: 'forensics', capability: 'forensics.ioc', target: 'ioc.txt', kind: 'file', expectSummary: /ioc|指标|URL|IP/i },
  { id: 'WEB-001', domain: 'web', capability: 'web.http_message', target: 'http.txt', kind: 'file', expectSummary: /HTTP|请求|request/i },
  { id: 'WEB-002', domain: 'web', capability: 'web.headers', target: 'headers.txt', kind: 'file', expectSummary: /header|头|HSTS|Content/i },
  { id: 'WEB-003', domain: 'web', capability: 'web.openapi', target: 'openapi.yaml', kind: 'file', expectSummary: /openapi|paths|server/i },
  { id: 'BIN-001', domain: 'binary', capability: 'binary.strings', target: 'strings.bin', kind: 'file', expectSummary: /string|字符串/i },
  { id: 'BIN-002', domain: 'binary', capability: 'binary.entropy', target: 'random.bin', kind: 'file', expectSummary: /entropy|熵/i },
  { id: 'NET-001', domain: 'network', capability: 'network.pcap_overview', target: 'http-dns.pcap', kind: 'file', expectSummary: /pcap|packet|报文|flow|HTTP/i },
  { id: 'SAST-001', domain: 'sast', capability: 'sast.scan', target: 'source', kind: 'directory', expectSummary: /scan|finding|扫描|发现/i },
]

const runtime = new ArmorBreakRuntime({ stateRoot })
await runtime.init()
const ctx = runtime.workspace(workspace)
const results = []
let passed = 0
for (const scenario of scenarios) {
  const targetPath = join(workspace, scenario.target)
  const input = scenario.kind === 'directory'
    ? Buffer.concat([await readFile(join(targetPath, 'app.js')), await readFile(join(targetPath, 'package.json'))])
    : await readFile(targetPath)
  const task = await ctx.taskStore.create({
    title: `core-bench ${scenario.id}`,
    targetPath,
    targetKind: scenario.kind,
    steps: [{ id: 's1', title: scenario.id, capabilityId: scenario.capability, options: scenario.options ?? {} }],
  })
  let state = 'NOT_RUN'
  let error = null
  let summary = ''
  let evidence = 0
  try {
    const updated = await runtime.runner.runWorkflow(task, { generateReport: false })
    state = updated.state
    summary = updated.steps[0]?.summary ?? ''
    evidence = (await ctx.taskStore.evidenceStore(task.id).readEvidence(1000)).length
    const expected = scenario.expectSummary.test(summary) || scenario.expectSummary.test(JSON.stringify(updated.steps[0]?.data ?? {}))
    const pass = ['COMPLETED', 'PARTIAL_SUCCESS'].includes(state) && evidence > 0 && expected
    if (pass) passed += 1
    results.push({ id: scenario.id, domain: scenario.domain, capability: scenario.capability, target: scenario.target, inputSha256: sha256(input), state, evidence, pass, expectedSummary: scenario.expectSummary.source, summary: summary.slice(0, 500), error: updated.steps[0]?.error ?? null })
  } catch (cause) {
    error = String(cause?.message ?? cause)
    results.push({ id: scenario.id, domain: scenario.domain, capability: scenario.capability, target: scenario.target, inputSha256: sha256(input), state: 'FAILED', evidence, pass: false, error })
  }
}

const targetCounts = { binary: 10, android: 8, network: 10, sast: 12, forensics: 8, aiAgent: 8, knowledge: 6 }
const targetTotal = Object.values(targetCounts).reduce((a, b) => a + b, 0)
const report = {
  schemaVersion: 'armorbreak.offline-score/v1',
  generatedAt: new Date().toISOString(),
  baseSha: process.env.GITHUB_SHA ?? null,
  environment: { platform: process.platform, arch: process.arch, node: process.version, offlineEnv: process.env.ARMORBREAK_OFFLINE ?? null },
  targetCounts,
  targetTotal,
  runnableScenarios: scenarios.length,
  coverage: `${scenarios.length}/${targetTotal}`,
  summary: { total: scenarios.length, pass: passed, fail: scenarios.length - passed, notRun: targetTotal - scenarios.length },
  offlineRate: 'N/A',
  offlineRateReason: 'No frozen online-reference run exists yet; the architecture formula requires A_online(i)=1 for the same scenario set. Do not report 100%.',
  notRun: Object.entries(targetCounts).map(([domain, count]) => ({ domain, target: count, ready: scenarios.filter((s) => s.domain === domain).length, reason: 'frozen corpus/fixture not yet built in M1' })),
  scenarios: results,
}
await mkdir('docs/v2/benchmark', { recursive: true })
await writeFile('docs/v2/benchmark/core-scenarios.json', `${JSON.stringify({ schemaVersion: 'armorbreak.core-benchmark/v1', targetTotal, scenarios: scenarios.map((s) => ({ ...s, expectSummary: s.expectSummary.source })) }, null, 2)}\n`)
await writeFile('docs/v2/acceptance/offline-score.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ coverage: report.coverage, pass: passed, total: scenarios.length, targetTotal, offlineRate: report.offlineRate }, null, 2))
if (passed !== scenarios.length) process.exitCode = 1
