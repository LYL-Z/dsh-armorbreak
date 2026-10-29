import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ArmorBreakRuntime } from '../../lib/core/runtime.js'
import { resolveGhidra, resolveJava21 } from '../../packages/core/src/externalTools.js'
import { getWorkflow, listWorkflows } from '../../packages/core/src/workflows.js'

const repoRoot = fileURLToPath(new URL('../..', import.meta.url))
const fixtureRoot = join(repoRoot, 'docs', 'v2.3', 'evidence', 'm3', 'fixtures')
const outputFlag = process.argv.indexOf('--output')
const outputPath = outputFlag >= 0 ? process.argv[outputFlag + 1] : null
if (outputFlag >= 0 && (!outputPath || outputPath.startsWith('--'))) throw new Error('--output requires a path')
const cases = [
  { file: 'native_fixture_x64.exe', expectedFormat: 'pe', expectedArchitecture: 'x86-64' },
  { file: 'native_fixture_x64_stripped.exe', expectedFormat: 'pe', expectedArchitecture: 'x86-64' },
  { file: 'native_fixture_i386.elf', expectedFormat: 'elf', expectedArchitecture: 'x86' },
  { file: 'native_fixture_i386_stripped.elf', expectedFormat: 'elf', expectedArchitecture: 'x86' },
  { file: 'native_fixture_x86_64_macho.macho', expectedFormat: 'macho', expectedArchitecture: 'x86-64', expectedFunctions: 3, expectedCalls: 2 },
  { file: 'native_fixture_x86_64_macho_stripped.macho', expectedFormat: 'macho', expectedArchitecture: 'x86-64', expectedFunctions: 3, expectedCalls: 2 },
]

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function summarizeFunction(fn) {
  return {
    name: fn.name,
    entry: fn.entry,
    fileOffset: fn.fileOffset,
    size: fn.size,
    byteHashSha256: fn.byteHashSha256 ?? null,
    byteHashBytes: fn.byteHashBytes ?? null,
    byteHashStatus: fn.byteHashStatus ?? null,
  }
}

const tempRoot = await mkdtemp(join(tmpdir(), 'armorbreak-m3-native-e2e-'))
const workspace = join(tempRoot, 'workspace')
const stateRoot = join(tempRoot, 'state')
const ghidra = resolveGhidra()
const gitSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, encoding: 'utf8' }).trim()
const javaProbe = spawnSync(resolveJava21(), ['-version'], { encoding: 'utf8', windowsHide: true })
assert.equal(javaProbe.status, 0, 'JDK 21 version probe should succeed')
const javaVersion = `${javaProbe.stdout}${javaProbe.stderr}`.match(/version "([^"]+)"/)?.[1] ?? 'UNKNOWN'

await mkdir(workspace, { recursive: true })
const runtime = new ArmorBreakRuntime({ stateRoot })

try {
  await runtime.init()
  assert.equal(runtime.registry.diagnostics.length, 0, 'registry must load without diagnostics')
  assert.equal(runtime.registry.get('binary.program_ir')?.riskLevel, 'L0')
  assert.ok(listWorkflows().some((workflow) => workflow.id === 'NativeProgramIRReview'))
  assert.equal(getWorkflow('NativeProgramIRReview').steps.at(-1).capabilityId, 'binary.program_ir')

  const results = []
  for (const item of cases) {
    const sourcePath = join(fixtureRoot, item.file)
    const targetPath = join(workspace, item.file)
    await copyFile(sourcePath, targetPath)
    const bytes = await readFile(targetPath)
    const task = await runtime.workspace(workspace).taskStore.create({
      title: `M3 static Ghidra fixture ${item.file}`,
      objective: 'Run the authorized ArmorBreak binary.program_ir L0 static-analysis path against a self-authored fixture.',
      targetPath,
      targetKind: 'file',
      steps: [{ id: 'program-ir', capabilityId: 'binary.program_ir', options: { includeGhidra: true } }],
    })
    const result = await runtime.runner.runCapability({
      task,
      capabilityId: 'binary.program_ir',
      options: {
        includeGhidra: true,
        maxFunctions: 100,
        maxBasicBlocks: 300,
        maxCallEdges: 500,
        maxSymbols: 500,
        timeoutMs: 180_000,
      },
    })
    const data = result.data
    assert.equal(data.artifact.sha256, digest(bytes), `${item.file}: result hash must match copied input`)
    assert.equal(data.artifact.format, item.expectedFormat, `${item.file}: format`)
    assert.equal(data.program.architecture, item.expectedArchitecture, `${item.file}: architecture`)
    assert.equal(data.ghidra.status, 'ANALYZED', `${item.file}: Ghidra must actually analyze the fixture`)
    assert.equal(data.ghidra.toolVersion, ghidra.version)
    assert.equal(data.analysis.backendVersion, ghidra.version)
    assert.equal(data.analysis.inputExecuted, false)
    assert.ok(result.evidenceIds.length > 0, `${item.file}: Runner should persist evidence`)
    if (item.expectedFunctions !== undefined) assert.equal(data.functionCount, item.expectedFunctions, `${item.file}: Ghidra function count`)
    if (item.expectedCalls !== undefined) assert.equal(data.callEdgeCount, item.expectedCalls, `${item.file}: Ghidra call-edge count`)

    results.push({
      fixture: item.file,
      fixtureSha256: digest(bytes),
      fixtureBytes: bytes.length,
      format: data.artifact.format,
      architecture: data.program.architecture,
      bitness: data.program.bitness,
      ghidraStatus: data.ghidra.status,
      ghidraVersion: data.ghidra.toolVersion,
      functionCount: data.functionCount,
      functionsEmitted: data.emittedFunctions,
      callEdgeCount: data.callEdgeCount,
      callEdgesEmitted: data.callEdges.length,
      basicBlockCount: data.basicBlockCount,
      basicBlocksEmitted: data.basicBlocks.length,
      analysisTruncated: data.analysis.truncated,
      inputExecuted: data.analysis.inputExecuted,
      evidenceCount: result.evidenceIds.length,
      functions: data.functions.map(summarizeFunction),
      callEdges: data.callEdges.map((edge) => ({
        caller: edge.caller,
        callerEntry: edge.callerEntry,
        callSite: edge.callSite,
        callee: edge.callee,
        calleeEntry: edge.calleeEntry,
        referenceType: edge.referenceType,
      })),
    })
  }

  const report = {
    schemaVersion: 'armorbreak.v2.3.m3-ghidra-e2e/v1',
    checkedAt: new Date().toISOString(),
    sourceCommit: gitSha,
    runner: 'ArmorBreakRuntime.runner.runCapability + PolicyGateway',
    capability: 'binary.program_ir',
    workflow: 'NativeProgramIRReview (registry presence checked; individual E2E invokes the capability via Runner)',
    inputExecution: false,
    externalToolExecution: 'Ghidra headless static analysis only',
    environment: {
      platform: `${process.platform}-${process.arch}`,
      node: process.version,
      java: javaVersion,
      ghidra: ghidra.version,
    },
    registry: {
      capabilityCount: runtime.registry.list().length,
      domains: runtime.registry.domainsList(),
      capabilitiesByRisk: Object.fromEntries(['L0', 'L1', 'L2', 'L3'].map((riskLevel) => [riskLevel, runtime.registry.list({ riskLevel }).length])),
      capabilitiesByDomain: Object.fromEntries(runtime.registry.domainsList().map((domain) => [domain, runtime.registry.list({ domain }).length])),
      workflowCount: listWorkflows().length,
      registryDiagnostics: runtime.registry.diagnostics,
    },
    resultCount: results.length,
    results,
  }
  const serialized = `${JSON.stringify(report, null, 2)}\n`
  if (outputPath) {
    const destination = join(repoRoot, outputPath)
    await mkdir(join(destination, '..'), { recursive: true })
    await writeFile(destination, serialized, 'utf8')
    process.stdout.write(`Wrote ${outputPath} for source ${gitSha}\n`)
  } else {
    process.stdout.write(serialized)
  }
} finally {
  await rm(tempRoot, { recursive: true, force: true })
}
