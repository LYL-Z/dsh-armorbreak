/**
 * v1.2.0 external adapter tests: TShark / Syft / JADX normalization and argv-call
 * seams. Real-tool Gate B lives in scripts/verify-gate-b-v2.mjs.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { parseTsharkJson, tsharkCapability } from '../lib/analyzers/network/tshark.js'
import { parseSyftReport, syftCapability } from '../lib/analyzers/sast/syft.js'
import { summarizeJadxSources, jadxCapability } from '../lib/analyzers/android/jadx.js'
import { parseGhidraSummary, ghidraCapability } from '../lib/analyzers/binary/ghidra.js'

const TS_JSON = JSON.stringify([
  {
    _source: {
      layers: {
        frame: { protocols: 'eth:ethertype:ip:tcp:http' },
        ip: { 'ip.src': '10.0.0.5', 'ip.dst': '93.184.216.34' },
        tcp: { 'tcp.stream': '0' },
        http: { 'http.request.method': 'GET', 'http_host': 'example.com', 'http_request_uri': '/login?x=1' },
      },
    },
  },
  {
    _source: {
      layers: {
        frame: { protocols: 'eth:ethertype:ip:udp:dns' },
        ip: { 'ip.src': '10.0.0.5', 'ip.dst': '8.8.8.8' },
        dns: { 'dns_qry_name': 'example.com' },
      },
    },
  },
])

const SBOM_JSON = JSON.stringify({
  bomFormat: 'CycloneDX',
  metadata: { component: { name: 'sample-workspace' } },
  components: [
    { name: 'left-pad', version: '1.3.0', type: 'library', purl: 'pkg:npm/left-pad@1.3.0', licenses: [{ license: { id: 'MIT' } }] },
    { name: 'no-version-lib', type: 'library' },
  ],
})

function envWith(execExternal) {
  return { signal: new AbortController().signal, workspaceRoot: tmpdir(), execExternal }
}

test('tshark: parses packet JSON into observed HTTP/DNS summary and hypothesis-safe findings', () => {
  const parsed = parseTsharkJson(TS_JSON, { maxPackets: 10 })
  assert.equal(parsed.data.packetCount, 2)
  assert.equal(parsed.data.httpRequests[0].host, 'example.com')
  assert.deepEqual(parsed.data.dnsQueries, ['example.com'])
  assert.ok(parsed.data.protocols.some((item) => item.name === 'http'))
  assert.equal(parsed.findings[0].verification, 'observed')
  assert.equal(parsed.findings[0].severity, 'low')
  assert.throws(() => parseTsharkJson('not-json'), /not valid JSON|unparsable/)
  assert.throws(() => parseTsharkJson('{}'), /not a packet array/)
})

test('tshark capability calls argv seam and returns bounded data; missing target rejects', async () => {
  const calls = []
  const capture = join(mkdtempSync(join(tmpdir(), 'abm-ts-')), 'sample.pcap')
  writeFileSync(capture, '')
  const result = await tsharkCapability.run({
    targetPath: capture,
    options: { maxPackets: 5 },
    limits: { timeoutMs: 5000, maxFindings: 10 },
    env: envWith(async (command, args) => {
      calls.push({ command, args })
      return { stdout: TS_JSON, stderr: '', exitCode: 0 }
    }),
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].command, 'tshark')
  assert.ok(calls[0].args.includes('-T'))
  assert.equal(result.meta.tool, 'tshark')
  assert.match(result.meta.stdoutSha256, /^[a-f0-9]{64}$/)
  await assert.rejects(() => tsharkCapability.run({ targetPath: null, env: envWith(async () => ({ stdout: '[]' })) }), /needs a capture/)
})

test('syft: normalizes CycloneDX, flags missing versions without CVE claims', () => {
  const parsed = parseSyftReport(SBOM_JSON, { maxComponents: 10 })
  assert.equal(parsed.data.componentCount, 2)
  assert.equal(parsed.data.components[0].purl, 'pkg:npm/left-pad@1.3.0')
  assert.deepEqual(parsed.data.components[0].licenses, ['MIT'])
  assert.equal(parsed.data.cveConclusion, false)
  assert.equal(parsed.findings[0].severity, 'info')
  assert.throws(() => parseSyftReport('{"components": "nope"}'), /missing components array/)
})

test('syft capability uses dir: argv with seam and never claims CVE', async () => {
  let seen = null
  const result = await syftCapability.run({
    targetPath: tmpdir(),
    options: {},
    limits: { timeoutMs: 5000 },
    env: envWith(async (command, args) => {
      seen = { command, args }
      return { stdout: SBOM_JSON, stderr: '', exitCode: 0 }
    }),
  })
  assert.equal(seen.command, 'syft')
  assert.ok(seen.args[0].startsWith('dir:'))
  assert.equal(result.data.cveConclusion, false)
  assert.equal(result.meta.tool, 'syft')
})

test('jadx: indexes sources/APIs without returning source, and seam writes temp output', async () => {
  const direct = summarizeJadxSources([
    { path: '/tmp/a/A.java', text: 'package com.example;\nclass A { void f(){ Runtime.getRuntime().exec("id"); Cipher.getInstance("AES"); } }' },
  ], { root: '/tmp/a' })
  assert.equal(direct.data.classCount, 1)
  assert.ok(direct.data.apiCategories['Runtime.exec'])
  assert.equal(direct.data.sourceReturned, false)
  assert.doesNotMatch(JSON.stringify(direct), /getRuntime\(\)\.exec\("id"\)/)

  const result = await jadxCapability.run({
    targetPath: process.execPath,
    options: { maxFiles: 10 },
    limits: { timeoutMs: 5000 },
    env: envWith(async (command, args) => {
      const output = args[1]
      mkdirSync(join(output, 'com', 'example'), { recursive: true })
      writeFileSync(join(output, 'com', 'example', 'A.java'), 'package com.example;\nclass A { void f(){ new ProcessBuilder("id"); } }')
      return { stdout: '', stderr: '', exitCode: 0 }
    }),
  })
  assert.equal(result.data.classCount, 1)
  assert.ok(result.data.apiCategories.ProcessBuilder)
  assert.equal(result.meta.tool, 'jadx')
  await assert.rejects(() => jadxCapability.run({ targetPath: null, env: envWith(async () => ({ stdout: '' })) }), /needs an APK/)
})

test('ghidra: parses bounded function summary and flags sensitive names as hypothesis', async () => {
  const raw = JSON.stringify({
    program: 'sample.exe',
    executableFormat: 'Portable Executable (PE)',
    processor: 'x86',
    language: 'x86:LE:64:default',
    imageBase: '140000000',
    functionCount: 2,
    internalFunctionCount: 2,
    externalFunctionCount: 0,
    functions: [
      { name: 'VirtualAllocEx', entry: '140001000', size: 32, external: true, thunk: false, callingConvention: 'unknown', callers: 2, byteHashStatus: 'UNAVAILABLE' },
      { name: 'main', entry: '140002000', fileOffset: '0x400', size: 64, external: false, thunk: false, callingConvention: '__stdcall', callers: 0, byteHashSha256: 'a'.repeat(64), byteHashBytes: 64, byteHashStatus: 'COMPLETE' },
    ],
    callEdgeCount: 2,
    callEdges: [
      { caller: 'main', callerEntry: '140002000', callSite: '140002010', callee: 'VirtualAllocEx', calleeEntry: '140001000', referenceType: 'UNCONDITIONAL_CALL' },
      { caller: 'main', callerEntry: '140002000', callSite: '140002020', callee: 'VirtualAllocEx', calleeEntry: '140001000', referenceType: 'UNCONDITIONAL_CALL' },
    ],
    callEdgeCountComplete: true,
    basicBlockCount: 2,
    basicBlocks: [
      { functionEntry: '140002000', start: '140002000', end: '140002020', size: 32, flowType: 'TERMINAL' },
      { functionEntry: '140002000', start: '140002021', end: '140002040', size: 31, flowType: 'TERMINAL' },
    ],
    basicBlockCountComplete: true,
    segments: [
      { name: '.text', start: '140001000', end: '140002000', fileOffset: '0x400', size: 4096, initialized: true, read: true, execute: true },
      { name: '.data', start: '140002000', end: '140003000', fileOffset: '0x1400', size: 4096, initialized: true, read: true, write: true },
    ],
    symbols: [
      { name: 'main', address: '140002000', fileOffset: '0x400', type: 'FUNCTION', source: 'ANALYSIS', external: false },
      { name: 'VirtualAllocEx', address: '140001000', fileOffset: '0x300', type: 'FUNCTION', source: 'IMPORTED', external: true },
    ],
    symbolCount: 2,
  })
  const parsed = parseGhidraSummary(raw, { maxFunctions: 10 })
  assert.equal(parsed.data.functionCount, 2)
  assert.equal(parsed.data.emitted, 2)
  assert.equal(parsed.data.processor, 'x86')
  assert.equal(parsed.data.functions[1].fileOffset, '0x400')
  assert.equal(parsed.data.functions[1].byteHashStatus, 'COMPLETE')
  assert.equal(parsed.data.callEdges[0].callSite, '140002010')
  assert.equal(parsed.data.basicBlocks.length, 2)
  assert.equal(parsed.data.symbols[0].name, 'main')
  assert.ok(parsed.data.suspiciousNames['process-injection'])
  assert.ok(parsed.findings.some((finding) => finding.verification === 'hypothesis'))
  assert.ok(parsed.findings.some((finding) => finding.verification === 'observed'))
  assert.throws(() => parseGhidraSummary('{"functions": "nope"}'), /missing functions array/)

  const bounded = parseGhidraSummary(raw, { maxFunctions: 1, maxBasicBlocks: 1, maxCallEdges: 1, maxSegments: 1, maxSymbols: 1 })
  assert.equal(bounded.data.truncated, true)
  assert.equal(bounded.data.functionScopeTruncated, true)
  assert.equal(bounded.data.callEdgesTruncated, true)
  assert.equal(bounded.data.basicBlocksTruncated, true)
  assert.equal(bounded.data.segmentsTruncated, true)
  assert.equal(bounded.data.symbolsTruncated, true)
  assert.equal(bounded.data.callEdgeCountComplete, false)
  assert.equal(bounded.data.basicBlockCountComplete, false)

  const exactInput = Buffer.from('authorized exact Ghidra fixture bytes', 'utf8')
  let importedTempPath = null
  const result = await ghidraCapability.run({
    targetPath: process.execPath,
    buffer: exactInput,
    options: { maxFunctions: 10 },
    limits: { timeoutMs: 5000 },
    env: envWith(async (command, args) => {
      importedTempPath = args[args.indexOf('-import') + 1]
      assert.notEqual(importedTempPath, process.execPath)
      assert.deepEqual(readFileSync(importedTempPath), exactInput)
      const output = args[args.indexOf('ExportSummary.java') + 1]
      writeFileSync(output, raw)
      return { stdout: 'ok', stderr: '', exitCode: 0 }
    }),
  })
  assert.equal(result.meta.tool, 'ghidra')
  assert.equal(result.data.emitted, 2)
  assert.equal(result.meta.inputBytes, exactInput.length)
  assert.equal(existsSync(importedTempPath), false, 'temporary sample copy is removed after analysis')
  await assert.rejects(() => ghidraCapability.run({
    targetPath: process.execPath,
    buffer: exactInput,
    env: { targetSize: exactInput.length + 1 },
  }), /refuses truncated or size-mismatched/)
})
