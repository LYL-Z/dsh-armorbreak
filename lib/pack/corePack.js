/**
 * AB2-M1-09 Core pack manifest/lockfile prototype.
 *
 * The pack is a deterministic list of shipped Core files with streaming SHA-256
 * sizes; workspace state, tests, docs, node_modules and .git are excluded. It is
 * not a tarball yet; M2 installer will consume this lockfile.
 */
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { readdir } from 'node:fs/promises'
import { join, relative } from 'node:path'

const DEFAULT_INCLUDE = ['package.json', 'index.js', 'tools.js', 'skills.js', 'client.js', 'cordis.patch.yml', 'lib', 'skills', 'locale', 'icon.svg']
const EXCLUDE = new Set(['.git', 'node_modules', '.armorbreak', 'tests', 'docs', 'benchmarks', 'scripts', 'dev'])

async function hashFile(file) {
  const hash = createHash('sha256')
  let bytes = 0
  await new Promise((resolve, reject) => {
    const stream = createReadStream(file, { highWaterMark: 1024 * 1024 })
    stream.on('data', (chunk) => { bytes += chunk.length; hash.update(chunk) })
    stream.on('error', reject)
    stream.on('end', resolve)
  })
  return { sha256: hash.digest('hex'), bytes }
}

async function walk(path, root, out) {
  const entries = await readdir(path, { withFileTypes: true })
  for (const entry of entries) {
    if (EXCLUDE.has(entry.name)) continue
    const full = join(path, entry.name)
    if (entry.isDirectory()) await walk(full, root, out)
    else if (entry.isFile()) out.push(full)
  }
}

export async function buildCorePack(input) {
  const root = input.root
  const files = []
  const include = input.include ?? DEFAULT_INCLUDE
  for (const item of include) {
    const full = join(root, item)
    try {
      const { stat } = await import('node:fs/promises')
      const info = await stat(full)
      if (info.isDirectory()) await walk(full, root, files)
      else if (info.isFile()) files.push(full)
    } catch {
      /* missing optional item is reported by the caller's manifest consumers */
    }
  }
  files.sort()
  const entries = []
  for (const file of files) {
    const { sha256, bytes } = await hashFile(file)
    entries.push({ path: relative(root, file).replace(/\\/g, '/'), sha256, bytes })
  }
  const aggregate = createHash('sha256')
  for (const entry of entries) aggregate.update(`${entry.path}\0${entry.sha256}\0${entry.bytes}\n`)
  return {
    schemaVersion: 'armorbreak.core-pack/v1',
    generatedAt: new Date().toISOString(),
    entries,
    aggregateSha256: aggregate.digest('hex'),
    fileCount: entries.length,
    totalBytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
  }
}
