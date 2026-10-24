#!/usr/bin/env node
/** AB2-M1-09 10 GiB sparse streaming hash measurement. */
import { mkdtemp, open, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { hashFileStream } from '../../lib/workers/contentStore.js'
import { writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
export async function createSparseStreamingFixture(bytes, parent = tmpdir()) {
  if (!Number.isSafeInteger(bytes) || bytes < 1) throw new Error('streaming fixture size must be a positive safe integer')
  const directory = await mkdtemp(join(parent, 'abm-stream-10g-'))
  const file = join(directory, 'sample.bin')
  try {
    const handle = await open(file, 'wx')
    try { await handle.truncate(bytes) } finally { await handle.close() }
    return { directory, file }
  } catch (error) {
    await rm(directory, { recursive: true, force: true })
    throw error
  }
}

export async function main() {
  const bytes = 10 * 1024 * 1024 * 1024
  const fixture = await createSparseStreamingFixture(bytes)
  let timer
  try {
    const started = Date.now()
    let peakRss = process.memoryUsage().rss
    timer = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss) }, 50)
    const result = await hashFileStream(fixture.file, { highWaterMark: 1024 * 1024 })
    clearInterval(timer)
    timer = undefined
    peakRss = Math.max(peakRss, process.memoryUsage().rss)
    const info = await stat(fixture.file)
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
    writeSafeRepoFile(root, 'docs/v2/acceptance/streaming-10gb.json', `${JSON.stringify(report, null, 2)}\n`, { requiredPrefix: 'docs/v2/acceptance/' })
    console.log(JSON.stringify(report, null, 2))
    if (result.bytes !== bytes || !report.withinRssBudget) process.exitCode = 1
  } finally {
    if (timer) clearInterval(timer)
    await rm(fixture.directory, { recursive: true, force: true })
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(String(error?.stack ?? error))
    process.exitCode = 1
  })
}
