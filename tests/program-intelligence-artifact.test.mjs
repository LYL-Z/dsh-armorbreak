import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { access, mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { deflateRawSync, gzipSync } from 'node:zlib'
import test from 'node:test'

import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { getWorkflow, listWorkflows } from '../lib/core/workflows.js'
import { boundedOptions, fitArtifactGraphToResultBudget, identifyArtifact, inventoryFiles, readZipIndex } from '../lib/analyzers/artifact/intake.js'

function crc32(buffer) {
  let crc = 0xffffffff
  for (const byte of buffer) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
  }
  return (crc ^ 0xffffffff) >>> 0
}

function makeZip(entries) {
  const localRecords = []
  const centralRecords = []
  let offset = 0
  for (const entry of entries) {
    const name = Buffer.from(entry.name, entry.utf8 ? 'utf8' : 'ascii')
    const data = Buffer.from(entry.data ?? '')
    const method = entry.method ?? 0
    const compressed = method === 8 ? deflateRawSync(data) : data
    const crc = crc32(data)
    const flags = entry.flags ?? (entry.utf8 ? 0x0800 : 0)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(flags, 6)
    local.writeUInt16LE(method, 8)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(compressed.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(name.length, 26)
    local.writeUInt16LE(0, 28)
    localRecords.push(local, name, compressed)

    const central = Buffer.alloc(46)
    central.writeUInt32LE(0x02014b50, 0)
    central.writeUInt16LE(entry.unixMode === undefined ? 20 : (3 << 8) | 20, 4)
    central.writeUInt16LE(20, 6)
    central.writeUInt16LE(flags, 8)
    central.writeUInt16LE(method, 10)
    central.writeUInt32LE(crc, 16)
    central.writeUInt32LE(compressed.length, 20)
    central.writeUInt32LE(data.length, 24)
    central.writeUInt16LE(name.length, 28)
    central.writeUInt16LE(0, 30)
    central.writeUInt16LE(0, 32)
    central.writeUInt16LE(0, 34)
    central.writeUInt32LE(entry.externalAttributes ?? (entry.unixMode === undefined ? 0 : (entry.unixMode << 16) >>> 0), 38)
    central.writeUInt32LE(offset, 42)
    centralRecords.push(central, name)
    offset += local.length + name.length + compressed.length
  }
  const localBytes = Buffer.concat(localRecords)
  const centralBytes = Buffer.concat(centralRecords)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(centralBytes.length, 12)
  eocd.writeUInt32LE(localBytes.length, 16)
  return Buffer.concat([localBytes, centralBytes, eocd])
}

function makeTar(entries) {
  const records = []
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? '')
    const header = Buffer.alloc(512)
    header.write(entry.name, 0, 100, 'utf8')
    header.write('0000644\0', 100, 8, 'ascii')
    header.write('0000000\0', 108, 8, 'ascii')
    header.write('0000000\0', 116, 8, 'ascii')
    header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii')
    header.write('00000000000\0', 136, 12, 'ascii')
    header.fill(0x20, 148, 156)
    header.write(entry.type ?? '0', 156, 1, 'ascii')
    if (entry.linkName) header.write(entry.linkName, 157, 100, 'utf8')
    header.write('ustar\0', 257, 6, 'ascii')
    header.write('00', 263, 2, 'ascii')
    let sum = 0
    for (const byte of header) sum += byte
    header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
    records.push(header)
    if (data.length) {
      records.push(data)
      const pad = (512 - (data.length % 512)) % 512
      if (pad) records.push(Buffer.alloc(pad))
    }
  }
  records.push(Buffer.alloc(1024))
  return Buffer.concat(records)
}

function peFixture() {
  const bytes = Buffer.alloc(128)
  bytes.write('MZ', 0, 'ascii')
  bytes.writeUInt32LE(64, 0x3c)
  bytes.write('PE\0\0', 64, 'binary')
  return bytes
}

function elfFixture(bits = 64) {
  const bytes = Buffer.alloc(64)
  bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, 1, 1], 0)
  return bytes
}

function machoFatFixture() {
  const bytes = Buffer.alloc(32)
  bytes.writeUInt32BE(0xcafebabe, 0)
  bytes.writeUInt32BE(1, 4)
  bytes.writeUInt32BE(0x01000007, 8)
  bytes.writeUInt32BE(3, 12)
  bytes.writeUInt32BE(28, 16)
  bytes.writeUInt32BE(4, 20)
  bytes.writeUInt32BE(0, 24)
  bytes.writeUInt32BE(0xfeedfacf, 28)
  return bytes
}

function tarHeaderPath(name, type = '0', data = Buffer.from('x')) {
  return makeTar([{ name, type, data, linkName: type === '1' || type === '2' ? 'target' : undefined }])
}

const nestedZip = makeZip([{ name: 'inner.zip', data: makeZip([{ name: 'readme.txt', data: 'authorized fixture' }]) }])
const packageFixtures = {
  zip: makeZip([{ name: 'readme.txt', data: 'read me' }]),
  apk: makeZip([{ name: 'AndroidManifest.xml', data: 'manifest' }, { name: 'classes.dex', data: 'dex\n035\0' }]),
  jar: makeZip([{ name: 'META-INF/MANIFEST.MF', data: 'Manifest-Version: 1.0\n' }, { name: 'Main.class', data: Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 1]) }]),
  aab: makeZip([{ name: 'BundleConfig.pb', data: 'config' }, { name: 'base/manifest/AndroidManifest.xml', data: 'manifest' }]),
  ipa: makeZip([{ name: 'Payload/Demo.app/Info.plist', data: 'plist' }]),
  hap: makeZip([{ name: 'module.json', data: '{}' }, { name: 'ets/index.abc', data: 'abc' }]),
}

const normalFixtures = [
  ['pe.exe', peFixture(), 'pe'],
  ['elf32', elfFixture(32), 'elf'],
  ['elf64', elfFixture(64), 'elf'],
  ['mach32', Buffer.from([0xfe, 0xed, 0xfa, 0xce]), 'macho'],
  ['mach64', Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), 'macho'],
  ['mach-fat', machoFatFixture(), 'macho-fat'],
  ['archive.zip', packageFixtures.zip, 'zip'],
  ['archive.tar', makeTar([{ name: 'readme.txt', data: 'hello' }]), 'tar'],
  ['archive.gz', gzipSync(Buffer.from('readable gzip payload')), 'gzip'],
  ['application.apk', packageFixtures.apk, 'apk'],
  ['application.jar', packageFixtures.jar, 'jar'],
  ['application.aab', packageFixtures.aab, 'aab'],
  ['application.ipa', packageFixtures.ipa, 'ipa'],
  ['application.hap', packageFixtures.hap, 'hap-candidate'],
  ['classes.dex', Buffer.from('dex\n035\0'), 'dex'],
  ['module.wasm', Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), 'wasm'],
  ['Main.class', Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 1]), 'jvm-class'],
  ['document.pdf', Buffer.from('%PDF-1.7\n'), 'pdf'],
  ['picture.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), 'png'],
  ['picture.jpg', Buffer.from([0xff, 0xd8, 0xff, 0xd9]), 'jpeg'],
  ['picture.gif', Buffer.from('GIF87a'), 'gif'],
  ['picture.gif', Buffer.from('GIF89a'), 'gif'],
  ['picture.webp', Buffer.from('RIFF0000WEBP'), 'webp'],
  ['data.sqlite', Buffer.from('SQLite format 3\0'), 'sqlite'],
  ['app.js', Buffer.from('export const value = 1\n'), 'source'],
  ['app.ts', Buffer.from('export const value: number = 1\n'), 'source'],
  ['app.py', Buffer.from('def value():\n    return 1\n'), 'source'],
  ['App.java', Buffer.from('class App {}\n'), 'source'],
  ['app.go', Buffer.from('package main\nfunc main() {}\n'), 'source'],
  ['lib.rs', Buffer.from('fn main() {}\n'), 'source'],
  ['App.cs', Buffer.from('class App {}\n'), 'source'],
  ['header.h', Buffer.from('int main(void);\n'), 'source'],
  ['app.php', Buffer.from('<?php echo 1;'), 'source'],
  ['script.sh', Buffer.from('#!/bin/sh\necho ok\n'), 'script'],
  ['settings.json', Buffer.from('{"ok":true}\n'), 'structured-text'],
  ['settings.yaml', Buffer.from('ok: true\n'), 'structured-text'],
  ['page.html', Buffer.from('<!doctype html><title>x</title>'), 'structured-text'],
  ['style.css', Buffer.from('body { color: black }'), 'structured-text'],
  ['query.sql', Buffer.from('select 1;'), 'structured-text'],
  ['unknown.bin', Buffer.from([0, 0xff, 0x01, 0x88, 0]), 'unknown'],
]

const hostileFixtures = [
  ['zip parent traversal', () => makeZip([{ name: '../escape.txt', data: 'no write' }]), 'PARENT_PATH_COMPONENT'],
  ['zip absolute path', () => makeZip([{ name: '/root/escape.txt', data: 'no write' }]), 'ABSOLUTE_PATH'],
  ['zip drive path', () => makeZip([{ name: 'C:/escape.txt', data: 'no write' }]), 'ABSOLUTE_PATH'],
  ['zip backslash traversal', () => makeZip([{ name: '..\\escape.txt', data: 'no write' }]), 'BACKSLASH_PATH'],
  ['zip alternate data stream', () => makeZip([{ name: 'report.txt:payload', data: 'no write' }]), 'WINDOWS_ADS_OR_DRIVE_PATH'],
  ['zip reserved device name', () => makeZip([{ name: 'CON.txt', data: 'no write' }]), 'WINDOWS_RESERVED_NAME'],
  ['zip symbolic link', () => makeZip([{ name: 'link', data: 'outside', unixMode: 0xa1ff }]), 'REJECTED_SYMLINK'],
  ['zip reparse point flag', () => makeZip([{ name: 'junction', data: 'outside', externalAttributes: 0x400 }]), 'REJECTED_REPARSE_POINT'],
  ['zip case-fold collision', () => makeZip([{ name: 'A.txt', data: 'one' }, { name: 'a.TXT', data: 'two' }]), 'CASE_OR_UNICODE_COLLISION'],
  ['zip compression ratio bomb', () => makeZip([{ name: 'bomb.txt', data: Buffer.alloc(1024 * 1024, 65), method: 8 }]), 'EXPANSION_RATIO_LIMIT'],
  ['zip malformed/truncated end record', () => makeZip([{ name: 'x.txt', data: 'x' }]).subarray(0, -1), 'MALFORMED'],
  ['zip64 sentinel', () => { const b = makeZip([{ name: 'x.txt', data: 'x' }]); b.writeUInt16LE(0xffff, b.length - 12); return b }, 'UNSUPPORTED_ZIP64'],
  ['zip local/central method mismatch', () => { const b = makeZip([{ name: 'x.txt', data: 'x' }]); b.writeUInt16LE(99, 8); return b }, 'LOCAL_CENTRAL_MISMATCH'],
  ['zip unsupported encryption feature', () => makeZip([{ name: 'x.txt', data: 'x', flags: 0x0040 }]), 'UNSUPPORTED_ENCRYPTED'],
  ['zip unsupported general-purpose flag', () => makeZip([{ name: 'x.txt', data: 'x', flags: 0x0010 }]), 'UNSUPPORTED_FLAGS'],
  ['tar parent traversal', () => tarHeaderPath('../escape', '0'), 'PARENT_PATH_COMPONENT'],
  ['tar symbolic link', () => tarHeaderPath('link', '2'), 'REJECTED_LINK'],
  ['tar hard link', () => tarHeaderPath('hardlink', '1'), 'REJECTED_LINK'],
  ['tar device node', () => tarHeaderPath('device', '3'), 'REJECTED_SPECIAL_FILE'],
  ['tar PAX path override', () => makeTar([{ name: 'pax-header', type: 'x', data: 'path=../escape\n' }, { name: 'reported-safe-name', data: 'not indexed' }]), 'UNSUPPORTED_METADATA_TARGET'],
  ['tar global PAX metadata', () => makeTar([{ name: 'global-pax', type: 'g', data: 'path=../escape\n' }, { name: 'not-indexed', data: 'payload' }]), 'UNSUPPORTED_GLOBAL_METADATA'],
  ['tar missing end markers', () => makeTar([{ name: 'x.txt', data: 'x' }]).subarray(0, -1024), 'PARTIAL_MISSING_TERMINATOR'],
]

const limits = { maxInputBytes: 32 * 1024 * 1024, maxFileReadBytes: 4 * 1024 * 1024, maxItems: 300 }

function graphFor(path, bytes, options = {}) {
  const bounded = boundedOptions(options, limits)
  return inventoryFiles([{ path, bytes, inputCompleteness: 'complete' }], { bounded })
}

test('M1 recognizes the benign multi-class fixture set using the production detector', async (t) => {
  assert.ok(normalFixtures.length >= 30)
  for (const [name, bytes, expected] of normalFixtures) {
    await t.test(name, () => {
      const result = identifyArtifact(bytes, name)
      assert.equal(result.format, expected, `expected ${expected}, got ${result.format}`)
      assert.equal(result.sha256, createHash('sha256').update(bytes).digest('hex'))
      assert.ok(result.detector.startsWith('armorbreak-artifact-intake/'))
      assert.ok(result.structuralFacts.printableFragmentCount >= 0)
    })
  }
})

test('M1 rejects hostile or malformed archive cases without extraction', async (t) => {
  assert.ok(hostileFixtures.length >= 10)
  for (const [name, makeFixture, expected] of hostileFixtures) {
    await t.test(name, () => {
      const bytes = makeFixture()
      const before = readZipIndex(bytes, 200)
      const graph = graphFor(name.endsWith('traversal') ? 'sample.tar' : 'sample.zip', bytes, { maxEntries: 100, maxExpandedBytes: 8 * 1024 * 1024 })
      const suspiciousNodes = graph.nodes.filter((node) => node.pathStatus || (node.typeStatus && node.typeStatus !== 'OK') || (node.status && !['INDEXED', 'IDENTIFIED', 'OK', 'DIRECTORY'].includes(node.status)))
      if (['MALFORMED', 'UNSUPPORTED_ZIP64', 'LOCAL_CENTRAL_MISMATCH', 'UNSUPPORTED_ENCRYPTED', 'UNSUPPORTED_FLAGS', 'UNSUPPORTED_GLOBAL_METADATA', 'PARTIAL_MISSING_TERMINATOR'].includes(expected)) {
        assert.ok(['PARTIAL', 'COMPLETE'].includes(graph.analysis.status))
        assert.ok(graph.analysis.warnings.length > 0 || graph.nodes.some((node) => node.containerStatus))
        if (expected === 'UNSUPPORTED_ZIP64') assert.equal(before.status, 'UNSUPPORTED_ZIP64')
        if (['UNSUPPORTED_ENCRYPTED', 'UNSUPPORTED_FLAGS'].includes(expected)) assert.ok(graph.nodes.some((node) => node.status === expected))
        if (expected === 'UNSUPPORTED_GLOBAL_METADATA' || expected === 'PARTIAL_MISSING_TERMINATOR') assert.ok(graph.nodes.some((node) => node.containerStatus === expected))
      } else {
        const suspicious = suspiciousNodes.find((node) => `${node.pathStatus ?? ''} ${node.typeStatus ?? ''} ${node.status ?? ''}`.includes(expected))
        assert.ok(suspicious, `expected ${expected} in ${JSON.stringify(suspiciousNodes)}`)
        assert.equal(graph.analysis.status, 'PARTIAL')
      }
      assert.equal(graph.analysis.extraction, 'IN_MEMORY_ONLY_NO_FILES_WRITTEN')
    })
  }
})

test('M1 does not confirm package identity from an incomplete ZIP directory', () => {
  const bytes = makeZip([
    { name: 'AndroidManifest.xml', data: 'manifest' },
    { name: 'classes.dex', data: 'dex\n035\0' },
  ])
  const eocd = bytes.length - 22
  const firstCentralRecordSize = 46 + Buffer.byteLength('AndroidManifest.xml')
  bytes.writeUInt32LE(firstCentralRecordSize, eocd + 12)
  const result = identifyArtifact(bytes, 'incomplete.apk')
  assert.notEqual(result.format, 'apk')
  assert.ok(result.candidates.some((candidate) => candidate.type === 'apk-candidate'))
})

test('M1 builds nested ZIP/TAR relationships and makes limits explicit', () => {
  const graph = graphFor('outer.zip', nestedZip, { maxEntries: 50, maxDepth: 5 })
  assert.equal(graph.analysis.status, 'COMPLETE')
  assert.ok(graph.nodes.some((node) => node.path === 'outer.zip!/inner.zip'))
  assert.ok(graph.nodes.some((node) => node.path === 'outer.zip!/inner.zip!/readme.txt'))
  assert.ok(graph.edges.some((edge) => edge.type === 'contains'))
  assert.ok(graph.nodes.every((node) => node.sha256 === null || /^[a-f0-9]{64}$/.test(node.sha256)))

  const limited = graphFor('outer.zip', nestedZip, { maxDepth: 0 })
  assert.equal(limited.analysis.status, 'PARTIAL')
  assert.ok(limited.analysis.limitsApplied.includes('maxDepth'))
})

test('M1 integrates through the live registry, PolicyGateway runner and UniversalArtifactTriage workflow', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-artifact-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-artifact-ws-'))
  await mkdir(join(workspace, 'packages'), { recursive: true })
  await mkdir(join(workspace, 'attacks'), { recursive: true })
  await writeFile(join(workspace, 'packages', 'nested.zip'), packageFixtures.zip)
  const escapePath = join(dirname(workspace), `${basename(workspace)}-escape.txt`)
  await writeFile(join(workspace, 'attacks', 'traversal.zip'), makeZip([{ name: `../${basename(workspace)}-escape.txt`, data: 'must remain in memory' }]))
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  assert.equal(runtime.registry.diagnostics.length, 0)
  assert.ok(runtime.registry.get('artifact.identify'))
  assert.equal(runtime.registry.get('artifact.identify').riskLevel, 'L0')
  assert.equal(runtime.registry.get('artifact.inventory').targetKind, 'directory')
  assert.ok(listWorkflows().some((workflow) => workflow.id === 'UniversalArtifactTriage'))
  const workflow = getWorkflow('UniversalArtifactTriage')
  const workflowTask = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized artifact triage workflow fixture',
    targetPath: workspace,
    targetKind: 'directory',
    workflowId: workflow.id,
    steps: workflow.steps,
  })
  await runtime.runner.prepareTask(workflowTask)
  const workflowResult = await runtime.runner.runWorkflow(workflowTask, { generateReport: false })
  assert.equal(workflowResult.state, 'COMPLETED')
  assert.equal(workflowResult.steps[0].status, 'DONE')
  assert.ok(workflowResult.steps[0].evidenceIds.length >= 1)
  const task = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized artifact inventory fixture',
    targetPath: workspace,
    targetKind: 'directory',
    steps: [{ id: 'inventory', capabilityId: 'artifact.inventory' }],
  })
  const result = await runtime.runner.runCapability({ task, capabilityId: 'artifact.inventory' })
  assert.equal(result.capability, 'artifact.inventory')
  assert.equal(result.data.schemaVersion, 'armorbreak.artifact-graph/v1')
  assert.ok(result.data.nodes.some((node) => node.path === 'packages/nested.zip'))
  assert.ok(result.data.nodes.some((node) => node.path === 'packages/nested.zip!/readme.txt'))
  assert.ok(result.data.nodes.some((node) => node.pathStatus === 'PARENT_PATH_COMPONENT'))
  assert.equal(result.data.analysis.status, 'PARTIAL')
  await assert.rejects(() => access(escapePath), /ENOENT/, 'archive inventory must not materialize traversal members')
  assert.ok(result.evidenceIds.length >= 1)

  const identifyTask = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized artifact identify fixture',
    targetPath: join(workspace, 'packages', 'nested.zip'),
    targetKind: 'file',
    steps: [{ id: 'identify', capabilityId: 'artifact.identify' }],
  })
  const identified = await runtime.runner.runCapability({ task: identifyTask, capabilityId: 'artifact.identify' })
  assert.equal(identified.data.format, 'zip')
  assert.equal(identified.data.sha256, createHash('sha256').update(packageFixtures.zip).digest('hex'))
})

test('M1 preserves the explicit partial-hash boundary at a directory read cap', () => {
  const graph = inventoryFiles([{ path: 'large.bin', bytes: Buffer.alloc(8), inputCompleteness: 'unknown_at_read_limit', sha256Scope: 'observed_bytes_only' }], {
    bounded: boundedOptions({}, limits),
  })
  const node = graph.nodes.find((item) => item.path === 'large.bin')
  assert.equal(node.inputCompleteness, 'unknown_at_read_limit')
  assert.equal(node.sha256Scope, 'observed_bytes_only')
})

test('M1 keeps oversized result graphs within budget with consistent counts and edges', () => {
  const nodes = Array.from({ length: 300 }, (_, index) => ({
    id: `artifact-${index}`,
    type: index === 0 ? 'workspace' : 'artifact',
    path: `fixture-${index}-${'x'.repeat(1200)}`,
    sha256: null,
    physicalBytes: 0,
    logicalBytes: 0,
    status: 'INDEXED',
  }))
  const edges = nodes.slice(1).map((node, index) => ({ from: nodes[index].id, to: node.id, type: 'contains' }))
  const graph = fitArtifactGraphToResultBudget({
    schemaVersion: 'armorbreak.artifact-graph/v1',
    detector: 'test',
    summary: { filesProvided: 299, filesListed: 299, filesRead: 299, unreadableFiles: 0, truncatedOrCappedFiles: 0, nodes: nodes.length, edges: edges.length, bytesRead: 0, expandedBytes: 0, suspiciousEntries: 0 },
    nodes,
    edges,
    analysis: { level: 'S1', status: 'COMPLETE', warnings: [], limitsApplied: [], coverageNotes: [], extraction: 'IN_MEMORY_ONLY_NO_FILES_WRITTEN' },
  }, 16 * 1024)
  const ids = new Set(graph.nodes.map((node) => node.id))
  assert.ok(Buffer.byteLength(JSON.stringify(graph), 'utf8') <= 16 * 1024)
  assert.equal(graph.summary.nodes, graph.nodes.length)
  assert.equal(graph.summary.edges, graph.edges.length)
  assert.ok(graph.edges.every((edge) => ids.has(edge.from) && ids.has(edge.to)))
  assert.equal(graph.summary.resultTruncated, true)
  assert.equal(graph.analysis.status, 'PARTIAL')
  assert.ok(graph.analysis.limitsApplied.includes('maxResultBytes'))
})

test('M1 schemas are versioned Draft 2020-12 contracts', async () => {
  const identification = JSON.parse(await readFile('docs/v2.3/schemas/artifact-identification.schema.json', 'utf8'))
  const graph = JSON.parse(await readFile('docs/v2.3/schemas/artifact-graph.schema.json', 'utf8'))
  for (const schema of [identification, graph]) {
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
    assert.match(schema.$id, /^https:\/\/armorbreak\.dev\/schemas\/v2\.3\//)
    assert.ok(Array.isArray(schema.required))
  }
  assert.equal(identification.properties.schemaVersion.const, 'armorbreak.artifact-identification/v1')
  assert.equal(graph.properties.schemaVersion.const, 'armorbreak.artifact-graph/v1')
  assert.equal(graph.properties.analysis.properties.extraction.const, 'IN_MEMORY_ONLY_NO_FILES_WRITTEN')
})
