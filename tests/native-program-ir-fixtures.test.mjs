import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import test from 'node:test'

import { programIrCapability } from '../lib/analyzers/binary/programIr.js'

function fixture(name) {
  return readFileSync(new URL(`../docs/v2.3/evidence/m3/fixtures/${name}`, import.meta.url))
}

async function inspect(buffer) {
  return programIrCapability.run({
    targetPath: null,
    buffer,
    options: { includeGhidra: false },
    limits: { maxBytes: 8 * 1024 * 1024, maxItems: 200, maxStrings: 500, maxFindings: 100, timeoutMs: 15_000 },
    env: { signal: new AbortController().signal, targetSize: buffer.length, targetTruncated: false },
  })
}

test('M3 compiled PE/ELF fixtures preserve identity, symbol presence, and strip evidence', async () => {
  const pe = fixture('native_fixture_x64.exe')
  const peResult = await inspect(pe)
  assert.equal(peResult.data.artifact.format, 'pe')
  assert.equal(peResult.data.program.architecture, 'x86-64')
  assert.equal(peResult.data.program.sourceSymbolSummary.counts.coffFunctions > 0, true)
  assert.equal(peResult.data.ghidra.status, 'DISABLED')
  assert.equal(peResult.data.analysis.inputExecuted, false)

  const strippedPeBytes = fixture('native_fixture_x64_stripped.exe')
  const strippedPe = await inspect(strippedPeBytes)
  assert.equal(strippedPe.data.artifact.format, 'pe')
  assert.equal(strippedPe.data.program.sourceSymbolSummary.counts.coffSymbols, 0)
  assert.equal(strippedPe.data.program.sourceSymbolSummary.counts.exportFunctions, 0)

  const elfBytes = fixture('native_fixture_i386.elf')
  const elf = await inspect(elfBytes)
  assert.equal(elf.data.artifact.format, 'elf')
  assert.equal(elf.data.program.architecture, 'x86')
  assert.equal(elf.data.program.bitness, 32)
  assert.equal(elf.data.program.sourceSymbolSummary.counts.symtabPresent, true)

  const strippedElfBytes = fixture('native_fixture_i386_stripped.elf')
  const strippedElf = await inspect(strippedElfBytes)
  assert.equal(strippedElf.data.artifact.format, 'elf')
  assert.equal(strippedElf.data.program.sourceSymbolSummary.counts.symtabPresent, false)
  assert.equal(strippedElf.data.program.sourceSymbolSummary.counts.symtabFunctions, 0)
  assert.equal(elf.data.analysis.inputExecuted, false)
  assert.equal(strippedElf.data.analysis.inputExecuted, false)

  const digests = [pe, strippedPeBytes, elfBytes, strippedElfBytes]
    .map((bytes) => createHash('sha256').update(bytes).digest('hex'))
  assert.equal(new Set(digests).size, 4)
})

test('M3 corrupted PE/ELF/Mach-O fixtures return bounded structured partial or unsupported results', async () => {
  const cases = [
    ['malformed_pe.bin', 'pe', 'PARTIAL'],
    ['malformed_elf.bin', 'elf', 'PARTIAL'],
    ['malformed_macho.bin', 'unknown', 'UNSUPPORTED'],
  ]
  for (const [name, expectedFormat, expectedStatus] of cases) {
    const result = await inspect(fixture(name))
    assert.equal(result.data.artifact.format, expectedFormat, name)
    assert.equal(result.data.analysis.status, expectedStatus, name)
    assert.equal(result.data.analysis.inputExecuted, false, name)
    assert.ok(result.data.analysis.reason || result.data.analysis.parserWarnings.length > 0, `${name} should preserve a parse explanation`)
  }
})
