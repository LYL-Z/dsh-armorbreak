#!/usr/bin/env node
/** ABU-003: hash regular acceptance evidence for the current source commit. */
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstatSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = process.cwd()
const dir = 'docs/v2/acceptance'
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const dirtyPaths = execFileSync('git', ['diff', '--name-only', 'HEAD'], { cwd: root, encoding: 'utf8' }).split(/\r?\n/).filter(Boolean)
const dirtySourcePaths = dirtyPaths.filter((path) => !path.startsWith(`${dir}/`) && path !== 'docs/v2/release/readiness.json')
if (dirtySourcePaths.length) throw new Error(`evidence manifest must bind committed source; dirty paths: ${dirtySourcePaths.join(', ')}`)
const files = {}
const INCLUDED_LOG_PATHS = new Set(['docs/v2/acceptance/host-model/pi/install-uninstall.log'])
const skip = (relativePath) => {
  const name = relativePath.slice(relativePath.lastIndexOf('/') + 1)
  return name === 'evidence-manifest.json' || name === 'release-gates.json' || name === 'release-smoke.json' ||
    (name.endsWith('.log') && !INCLUDED_LOG_PATHS.has(relativePath))
}

function walk(relativeDirectory) {
  const absoluteDirectory = join(root, ...relativeDirectory.split('/'))
  const directoryInfo = lstatSync(absoluteDirectory)
  if (directoryInfo.isSymbolicLink() || !directoryInfo.isDirectory()) throw new Error(`refusing non-directory acceptance path: ${relativeDirectory}`)
  const entries = readdirSync(absoluteDirectory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name))
  for (const entry of entries) {
    const relativePath = `${relativeDirectory}/${entry.name}`
    if (entry.isSymbolicLink()) throw new Error(`refusing symlink or junction in acceptance evidence: ${relativePath}`)
    if (skip(relativePath)) continue
    if (entry.isDirectory()) {
      walk(relativePath)
      continue
    }
    if (!entry.isFile()) throw new Error(`refusing non-regular acceptance evidence: ${relativePath}`)
    const bytes = readSafeRepoFile(root, relativePath, { requiredPrefix: `${dir}/` })
    files[relativePath] = {
      sha256: createHash('sha256').update(bytes).digest('hex'),
      size: bytes.length,
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
const output = `${dir}/evidence-manifest.json`
writeSafeRepoFile(root, output, `${JSON.stringify(manifest, null, 2)}\n`, { requiredPrefix: `${dir}/` })
console.log(JSON.stringify({ commit, files: Object.keys(files).length, output }, null, 2))
