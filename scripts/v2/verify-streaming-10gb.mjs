#!/usr/bin/env node
/** AB2-M1-09 10 GiB sparse streaming hash measurement. */
import { open, stat, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { hashFileStream } from '../../lib/workers/contentStore.js'

const file = join(tmpdir(), `abm-stream-10g-${process.pid}.bin`)
const bytes = 10 * 1024 * 1024 * 1024
const handle = await open(file, 'w')
await handle.truncate(bytes)
await handle.close()
const started = Date.now()
let peakRss = process.memoryUsage().rss
const timer = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss) }, 50)
try {
  const result = await hashFileStream(file, { highWaterMark: 1024 * 1024 })
  clearInterval(timer)
  peakRss = Math.max(peakRss, process.memoryUsage().rss)
  const info = await stat(file)
  const report = {
    schemaVersion: 'armorbreak.streaming-proof/v1',
    generatedAt: new Date().toISOString(),
    fileBytes: bytes,
    statBytes: info.size,
    hashedBytes: result.bytes,
    sha256: result.sha256,
    elapsedMs: Date.now() - started,
    peakRssBytes: peakRss,
    rssBudgetBytes: 512 * 1024 * 1024,
    withinRssBudget: peakRss < 512 * 1024 * 1024,
    method: 'fs.truncate sparse file + createReadStream 1 MiB + SHA-256',
    platform: process.platform,
    node: process.version,
  }
  await writeFile('docs/v2/acceptance/streaming-10gb.json', `${JSON.stringify(report, null, 2)}\n`)
  console.log(JSON.stringify(report, null, 2))
  if (result.bytes !== bytes) process.exitCode = 1
  if (!report.withinRssBudget) process.exitCode = 1
} finally {
  clearInterval(timer)
  await unlink(file).catch(() => {})
}
