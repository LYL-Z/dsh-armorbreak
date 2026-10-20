/**
 * Remove the temporary directories this project's test suite leaves in the OS
 * temp directory (prefixes `abm-` and `dbg-`). Only directories directly under
 * the temp root whose names match those prefixes are touched; everything else
 * is ignored.
 *
 * Usage: node scripts/clean-temp.mjs [--dry-run]
 */
import { readdir, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dryRun = process.argv.includes('--dry-run')
const roots = [tmpdir(), process.env.TEMP, process.env.TMP].filter(Boolean)
const seen = new Set()
let removed = 0
let bytes = 0

/** @param {string} dir */
async function sizeOf(dir) {
  let total = 0
  try {
    const entries = await readdir(dir, { withFileTypes: true })
    for (const entry of entries) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) total += await sizeOf(full)
      else {
        const info = await stat(full).catch(() => null)
        total += info?.size ?? 0
      }
    }
  } catch {
    /* ignore unreadable entries */
  }
  return total
}

for (const root of [...new Set(roots)]) {
  let entries = []
  try {
    entries = await readdir(root, { withFileTypes: true })
  } catch {
    continue
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    if (!/^(abm-|dbg-)/.test(entry.name)) continue
    const full = join(root, entry.name)
    if (seen.has(full)) continue
    seen.add(full)
    const size = await sizeOf(full)
    if (!dryRun) await rm(full, { recursive: true, force: true })
    removed += 1
    bytes += size
  }
}

console.log(`${dryRun ? '[dry-run] ' : ''}removed ${removed} test temp dirs, ${(bytes / 1024 / 1024).toFixed(2)} MiB`)
