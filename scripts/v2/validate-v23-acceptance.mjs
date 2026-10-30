#!/usr/bin/env node
/** Validate the separate V2.3 evidence bundle without rewriting V2.2 evidence. */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, normalize } from 'node:path'
import { findForbiddenPostSourcePaths, isFullCommitSha } from './v23-provenance.mjs'

const root = process.cwd()
const manifestPath = 'docs/v2.3/evidence/p0-h/acceptance-manifest.json'
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
// Git may check text files out with CRLF on Windows and LF on Unix. Bind
// evidence to its content using canonical LF bytes so one manifest validates
// identically on every supported runner.
const canonicalBytes = (path, bytes) => {
  if (!/\.(?:c|json|log|md|ya?ml)$/i.test(path)) return bytes
  return Buffer.from(bytes.toString('utf8').replaceAll('\r\n', '\n'), 'utf8')
}
const git = (args, options = {}) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], ...options }).trim()
const fail = (message) => { console.error(`V2.3 acceptance integrity: FAIL: ${message}`); process.exitCode = 1 }

function trackedEvidencePaths() {
  const paths = git(['ls-files', '-z']).split('\0').filter((path) =>
    /^docs\/v2\.3\/evidence\/m[0-6]\//.test(path) || (/^docs\/v2\.3\/evidence\/p0-h\//.test(path) && path !== manifestPath) || [
      'docs/v2.3/acceptance-report.md',
      'docs/v2.3/architecture.md',
      'docs/v2.3/threat-model.md',
      'docs/v2.3/performance-report.md',
      'docs/v2.3/migration-and-rollback.md',
      'docs/v2.3/baseline.md',
      'docs/v2.3/compatibility-matrix.json',
      'docs/v2.3/fixture-catalog.json',
      'docs/releases/v2.3.0.md',
      'scripts/v2/validate-v23-acceptance.mjs',
      'scripts/v2/v23-provenance.mjs',
      '.github/workflows/ci.yml',
      '.github/workflows/v2.3-validation.yml',
    ].includes(path),
  )
  const p0hRoot = join(root, 'docs', 'v2.3', 'evidence', 'p0-h')
  try {
    const visit = (absolute, relative) => {
      for (const entry of readdirSync(absolute, { withFileTypes: true })) {
        const childPath = `${relative}/${entry.name}`
        const childAbsolute = join(absolute, entry.name)
        const info = lstatSync(childAbsolute)
        if (info.isSymbolicLink()) throw new Error(`symlink in P0-H evidence directory: ${childPath}`)
        if (childPath === manifestPath) continue
        if (entry.isDirectory()) visit(childAbsolute, childPath)
        else if (entry.isFile()) paths.push(childPath)
        else throw new Error(`unsupported P0-H evidence entry: ${childPath}`)
      }
    }
    visit(p0hRoot, 'docs/v2.3/evidence/p0-h')
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
  return [...new Set(paths)].sort()
}

function regularFile(relativePath) {
  const clean = normalize(relativePath).replaceAll('\\', '/')
  if (clean !== relativePath || clean.startsWith('../') || clean.startsWith('/') || /^[a-z]:/i.test(clean)) throw new Error(`unsafe evidence path: ${relativePath}`)
  let current = root
  for (const part of clean.split('/')) {
    current = join(current, part)
    const info = lstatSync(current)
    if (info.isSymbolicLink()) throw new Error(`symlink in evidence path: ${relativePath}`)
  }
  const info = lstatSync(current)
  if (!info.isFile()) throw new Error(`evidence is not a regular file: ${relativePath}`)
  return canonicalBytes(relativePath, readFileSync(current))
}

if (process.argv.includes('--generate') || process.argv.includes('--regenerate')) {
  const regenerate = process.argv.includes('--regenerate')
  const sourceCommit = git(['rev-parse', 'HEAD'])
  if (!isFullCommitSha(sourceCommit)) throw new Error('HEAD must be a full commit SHA')
  const files = Object.fromEntries(trackedEvidencePaths().map((path) => {
    const bytes = regularFile(path)
    return [path, { size: bytes.length, sha256: sha256(bytes) }]
  }))
  const manifest = {
    schemaVersion: 'armorbreak.v2.3-acceptance-manifest/v1',
    baselineSha: '66ec0017af4b9d636f09e45f7cf55eed060512ac',
    sourceCommit,
    generatedAt: new Date().toISOString(),
    scope: 'M0-M6 local evidence integrity; P0-H release readiness is reported separately and remains NOT_READY until all owner-approved release gates pass.',
    files,
  }
  const absolute = join(root, ...manifestPath.split('/'))
  mkdirSync(dirname(absolute), { recursive: true })
  if (!regenerate) {
    try { lstatSync(absolute); throw new Error(`${manifestPath} already exists; use --regenerate only after reviewing the changed evidence`) } catch (error) { if (error?.code !== 'ENOENT') throw error }
  }
  writeFileSync(absolute, `${JSON.stringify(manifest, null, 2)}\n`, { flag: regenerate ? 'w' : 'wx' })
  console.log(JSON.stringify({ generated: manifestPath, sourceCommit, files: Object.keys(files).length }, null, 2))
  process.exit(0)
}

let manifest
try {
  manifest = JSON.parse(regularFile(manifestPath).toString('utf8'))
} catch (error) {
  fail(`cannot read manifest: ${error?.message ?? error}`)
  process.exit(1)
}

const head = git(['rev-parse', 'HEAD'])
const expectedHead = process.env.V23_EXPECTED_HEAD ?? process.env.GITHUB_SHA
if (expectedHead && expectedHead !== head) fail(`checked out HEAD ${head} does not match expected exact head ${expectedHead}`)
if (manifest?.schemaVersion !== 'armorbreak.v2.3-acceptance-manifest/v1') fail('manifest schema is invalid')
if (manifest?.baselineSha !== '66ec0017af4b9d636f09e45f7cf55eed060512ac') fail('manifest baseline SHA does not match the frozen M0 baseline')
if (!isFullCommitSha(manifest?.sourceCommit)) fail('manifest sourceCommit is not a full Git SHA')

try {
  git(['rev-parse', '--verify', `${manifest.sourceCommit}^{commit}`])
  git(['merge-base', '--is-ancestor', manifest.sourceCommit, head])
} catch {
  fail('manifest source commit is missing or is not an ancestor of the validated head')
}

try {
  const changed = git(['diff', '--name-only', '--no-renames', '-z', `${manifest.sourceCommit}..${head}`]).split('\0').filter(Boolean)
  const forbidden = findForbiddenPostSourcePaths(changed)
  if (forbidden.length) fail(`post-source changes escape the evidence-only allowlist: ${forbidden.join(', ')}`)
} catch (error) {
  fail(`cannot verify source-to-head path lineage: ${error?.message ?? error}`)
}

const records = manifest?.files
if (!records || typeof records !== 'object' || Array.isArray(records)) fail('manifest files must be an object')
else {
  try {
    const expectedPaths = trackedEvidencePaths()
    const recordedPaths = Object.keys(records)
    const unbound = expectedPaths.filter((path) => !Object.hasOwn(records, path))
    const stale = recordedPaths.filter((path) => !expectedPaths.includes(path))
    if (unbound.length || stale.length) fail(`manifest inventory mismatch; unbound: ${unbound.join(', ') || 'none'}; stale: ${stale.join(', ') || 'none'}`)
  } catch (error) {
    fail(`cannot enumerate evidence inventory: ${error?.message ?? error}`)
  }
  const requiredStages = ['m0', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6']
  for (const stage of requiredStages) {
    const present = Object.keys(records).some((path) => path.startsWith(`docs/v2.3/evidence/${stage}/`))
    if (!present) fail(`manifest lacks ${stage.toUpperCase()} evidence`)
  }
  for (const [path, record] of Object.entries(records)) {
    try {
      const bytes = regularFile(path)
      if (!Number.isSafeInteger(record?.size) || record.size !== bytes.length || !/^[a-f0-9]{64}$/i.test(record?.sha256 ?? '') || record.sha256.toLowerCase() !== sha256(bytes)) {
        fail(`size or SHA-256 mismatch: ${path}`)
      }
    } catch (error) {
      fail(`${path}: ${error?.message ?? error}`)
    }
  }
}

try {
  const matrix = JSON.parse(regularFile('docs/v2.3/compatibility-matrix.json').toString('utf8'))
  const milestone = (id) => matrix.milestones.find((item) => item.id === id)
  if (milestone('M5')?.status !== 'PARTIAL_LOCAL_TESTED' || milestone('M6')?.status !== 'PARTIAL_LOCAL_TESTED') fail('M5/M6 matrix status is missing or inconsistent')
  if (milestone('P0-H')?.status !== 'IN_PROGRESS') fail('P0-H must not be reported complete by this local evidence gate')
  const report = regularFile('docs/v2.3/acceptance-report.md').toString('utf8')
  if (!report.includes('RELEASE READINESS') || !report.includes('NOT_READY')) fail('acceptance report must retain the explicit NOT_READY release status')
  const m6 = JSON.parse(regularFile('docs/v2.3/evidence/m6/m6-validation.json').toString('utf8'))
  if (m6.sourceCommit !== '965fbe4fa9abd2af73644865a56d8db64c8a6089' || m6.tests?.full?.passed !== 647 || m6.tests?.full?.failed !== 0 || m6.tests?.focused?.passed !== 24 || m6.tests?.typecheck?.exitCode !== 0) {
    fail('M6 exact-source evidence does not match its recorded test results')
  }
} catch (error) {
  fail(`milestone/report validation failed: ${error?.message ?? error}`)
}

if (!process.exitCode) {
  console.log(JSON.stringify({
    ok: true,
    mode: 'V2.3-evidence-integrity-only',
    baselineSha: manifest.baselineSha,
    evidenceSourceCommit: manifest.sourceCommit,
    validatedHead: head,
    checkedFiles: Object.keys(records ?? {}).length,
    releaseReadiness: 'NOT_READY',
    limitations: ['This validates hashes and recorded milestone boundaries; it is not the Stable release gate.'],
  }, null, 2))
}
