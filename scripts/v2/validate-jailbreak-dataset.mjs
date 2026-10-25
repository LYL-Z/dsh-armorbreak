#!/usr/bin/env node
/**
 * AB2-M3-07 live JailbreakBench metadata validation.
 * Raw harmful/benign rows are processed in memory, aggregated, then discarded.
 */
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { aggregateDataset, validateDataset } from '../../lib/aisec/jailbreakDataset.js'
import { writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))

const base = 'https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main'
const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex')
async function get(url) {
  const response = await fetch(url, { headers: { 'user-agent': 'ArmorBreak/2.0 research-metadata-only' } })
  return { status: response.status, buffer: Buffer.from(await response.arrayBuffer()) }
}
function parseCsv(text) {
  const rows = []
  let row = []
  let cell = ''
  let quoted = false
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i += 1 }
      else if (ch === '"') quoted = false
      else cell += ch
    } else if (ch === '"') quoted = true
    else if (ch === ',') { row.push(cell); cell = '' }
    else if (ch === '\n') { row.push(cell.replace(/\r$/, '')); rows.push(row); row = []; cell = '' }
    else cell += ch
  }
  if (cell || row.length) { row.push(cell); rows.push(row) }
  return rows.filter((line) => line.some((value) => value !== ''))
}

const harmful = await get(`${base}/data/harmful-behaviors.csv`)
const benign = await get(`${base}/data/benign-behaviors.csv`)
const license = await get(`${base}/LICENSE`)
const harmfulRows = harmful.status === 200 ? parseCsv(harmful.buffer.toString('utf8')) : []
const benignRows = benign.status === 200 ? parseCsv(benign.buffer.toString('utf8')) : []
const header = harmfulRows[0] ?? []
const categoryIndex = header.findIndex((value) => /category/i.test(value))
const records = []
if (harmfulRows.length > 1) {
  for (let i = 1; i < harmfulRows.length; i += 1) {
    const row = harmfulRows[i]
    if (!row[0]) continue
    records.push({ id: `harmful-${i}`, category: categoryIndex >= 0 ? row[categoryIndex] : 'harmful' })
  }
}
const dataset = { authorized: true, license: 'MIT (repository LICENSE)', source: 'JailbreakBench/JBB-Behaviors', records }
const check = validateDataset(dataset)
if (!check.valid) throw new Error(`dataset validation failed: ${check.errors.join('; ')}`)
const aggregate = aggregateDataset(dataset)
const report = {
  schemaVersion: 'armorbreak.jailbreak-live/v1',
  generatedAt: new Date().toISOString(),
  source: 'https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors',
  revision: 'main',
  files: {
    harmful: { status: harmful.status, bytes: harmful.buffer.length, sha256: sha256(harmful.buffer) },
    benign: { status: benign.status, bytes: benign.buffer.length, sha256: sha256(benign.buffer) },
    license: { status: license.status, bytes: license.buffer.length, sha256: sha256(license.buffer) },
  },
  parse: { harmfulRows: harmfulRows.length - 1, benignRows: benignRows.length - 1, columns: header.length },
  aggregate,
  rawStored: false,
  result: harmful.status === 200 && benign.status === 200 && license.status === 200 ? 'PASS' : 'FAIL',
}
writeSafeRepoFile(root, 'docs/v2/acceptance/jailbreak-live.json', `${JSON.stringify(report, null, 2)}\n`, { requiredPrefix: 'docs/v2/acceptance/' })
console.log(JSON.stringify({ result: report.result, files: report.files, aggregate, rawStored: false }, null, 2))
if (report.result !== 'PASS') process.exitCode = 1
