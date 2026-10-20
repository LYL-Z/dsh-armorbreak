import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { ghidraCapability } from '../lib/analyzers/binary/ghidra.js'

const target = 'C:\\Windows\\System32\\notepad.exe'
if (!existsSync(target)) throw new Error('notepad.exe missing')
const bytes = readFileSync(target)
const started = Date.now()
const result = await ghidraCapability.run({ targetPath: target, options: { maxFunctions: 500 }, limits: { timeoutMs: 300000 }, env: {} })
const elapsed = Date.now() - started
const evidencePath = 'docs/acceptance/adapter-v2-real.json'
let summary = {}
try { summary = JSON.parse(readFileSync(evidencePath, 'utf8')) } catch { summary = {} }
summary.ghidra = {
  summary: result.summary,
  functionCount: result.data.functionCount,
  emitted: result.data.emitted,
  suspiciousNames: Object.keys(result.data.suspiciousNames ?? {}),
  findings: result.findings.length,
  target: target,
  targetSha256: createHash('sha256').update(bytes).digest('hex'),
  elapsedMs: elapsed,
}
writeFileSync(evidencePath, JSON.stringify(summary, null, 2))
console.log(JSON.stringify(summary.ghidra, null, 2))
