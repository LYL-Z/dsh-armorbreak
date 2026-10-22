#!/usr/bin/env node
/** ABU-003: hash all acceptance evidence for the current commit. */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'

const root = process.cwd()
const dir = 'docs/v2/acceptance'
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const files = {}
const skip = (name) => name === 'evidence-manifest.json' || name === 'release-gates.json' || name === 'release-smoke.json' || name.endsWith('.log')
function walk(current) {
  for (const name of readdirSync(current).sort()) {
    if (skip(name)) continue
    const full = join(current, name)
    if (statSync(full).isDirectory()) { walk(full); continue }
    const relativePath = relative(root, full).replaceAll('\\', '/')
    files[relativePath] = {
      sha256: createHash('sha256').update(readFileSync(full)).digest('hex'),
      size: statSync(full).size,
    }
  }
}
walk(dir)
const manifest = {
  schemaVersion: 'armorbreak.evidence-manifest/v1',
  commit,
  generatedAt: new Date().toISOString(),
  files,
}
writeFileSync(join(dir, 'evidence-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
console.log(JSON.stringify({ commit, files: Object.keys(files).length, output: join(dir, 'evidence-manifest.json') }, null, 2))
