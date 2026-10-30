import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = fileURLToPath(new URL('../..', import.meta.url))
const fixtureRoot = join(repoRoot, 'docs', 'v2.3', 'evidence', 'm3', 'fixtures')
const inputFlag = process.argv.indexOf('--input')
const inputPath = inputFlag >= 0 ? process.argv[inputFlag + 1] : null
if (!inputPath || inputPath.startsWith('--')) throw new Error('Usage: node scripts/v2/derive-m3-macho-fixtures.mjs --input <compiled-macho-with-symbol-table>')

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function withoutSymbolLoadCommands(bytes) {
  assert.ok(bytes.length >= 32, 'Mach-O header is truncated')
  assert.equal(bytes.readUInt32LE(0), 0xfeedfacf, 'fixture must be little-endian 64-bit Mach-O')
  const commandCount = bytes.readUInt32LE(16)
  const commandBytes = bytes.readUInt32LE(20)
  const commandsEnd = 32 + commandBytes
  assert.ok(commandsEnd <= bytes.length, 'load commands extend past file bounds')

  const commands = []
  let offset = 32
  for (let index = 0; index < commandCount; index += 1) {
    assert.ok(offset + 8 <= commandsEnd, `load command ${index} header is truncated`)
    const command = bytes.readUInt32LE(offset)
    const size = bytes.readUInt32LE(offset + 4)
    assert.ok(size >= 8 && offset + size <= commandsEnd, `load command ${index} has an invalid size`)
    commands.push({ command, size, offset })
    offset += size
  }
  assert.equal(offset, commandsEnd, 'load command count and size disagree')

  const removed = commands.filter(({ command }) => command === 0x2 || command === 0xb)
  assert.equal(removed.filter(({ command }) => command === 0x2).length, 1, 'expected one LC_SYMTAB')
  assert.equal(removed.filter(({ command }) => command === 0xb).length, 1, 'expected one LC_DYSYMTAB')
  const retained = commands.filter(({ command }) => command !== 0x2 && command !== 0xb)
  const output = Buffer.from(bytes)
  let writeOffset = 32
  for (const item of retained) {
    bytes.copy(output, writeOffset, item.offset, item.offset + item.size)
    writeOffset += item.size
  }
  output.fill(0, writeOffset, commandsEnd)
  output.writeUInt32LE(retained.length, 16)
  output.writeUInt32LE(writeOffset - 32, 20)
  return { output, removedCount: removed.length, removedBytes: removed.reduce((sum, item) => sum + item.size, 0) }
}

const fullPath = join(fixtureRoot, 'native_fixture_x86_64_macho.macho')
const strippedPath = join(fixtureRoot, 'native_fixture_x86_64_macho_stripped.macho')
const truncatedPath = join(fixtureRoot, 'native_fixture_x86_64_macho_truncated.macho')
const [input, full] = await Promise.all([readFile(inputPath), readFile(fullPath)])
const { output, removedCount, removedBytes } = withoutSymbolLoadCommands(input)
await writeFile(strippedPath, output)
await writeFile(truncatedPath, full.subarray(0, 512))

process.stdout.write(`${JSON.stringify({
  inputBytes: input.length,
  inputSha256: sha256(input),
  removedLoadCommands: ['LC_SYMTAB', 'LC_DYSYMTAB'],
  removedCommandCount: removedCount,
  removedCommandBytes: removedBytes,
  strippedBytes: output.length,
  strippedSha256: sha256(output),
  truncatedBytes: Math.min(full.length, 512),
  truncatedSha256: sha256(full.subarray(0, 512)),
}, null, 2)}\n`)
