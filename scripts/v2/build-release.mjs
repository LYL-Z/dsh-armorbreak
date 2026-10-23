#!/usr/bin/env node
/**
 * Deterministic candidate artifact builder:
 * sorted ustar entries, zero mtime/uid/gid, gzip, SHA-256, CycloneDX SBOM.
 * A test Ed25519 signature is generated to verify the mechanism; it is never
 * labelled a production signature.
 */
import { createHash, generateKeyPairSync } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { signArtifact, verifyArtifactSignature } from './artifact-signature.mjs'
import { deterministicGzip } from './deterministic-gzip.mjs'
import { readSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const args = process.argv.slice(2)
const value = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback }
const outDir = resolve(value('--out', join(root, 'dist')))
const evidencePath = resolve(value('--evidence', join(root, 'docs/v2/acceptance/release-build.json')))
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
function gitPaths(args) {
  return execFileSync('git', args, { cwd: root }).toString('utf8').split('\0').filter(Boolean).map((path) => path.replaceAll('\\', '/'))
}

const dirtyPaths = [...new Set([
  ...gitPaths(['diff', '--name-only', '-z', 'HEAD', '--']),
  ...gitPaths(['ls-files', '--others', '--exclude-standard', '-z']),
])]
const reviewEvidence = (path) => path === 'FOUR_REVIEW_UNIFIED_FINDINGS.json' || path === 'FOUR_REVIEW_RECONCILIATION.md'
const evidenceOnly = (path) => path.startsWith('docs/v2/acceptance/') || path === 'docs/v2/release/readiness.json' || reviewEvidence(path)
const dirtySourcePaths = dirtyPaths.filter((path) => !evidenceOnly(path))
if (dirtySourcePaths.length) throw new Error(`release build requires committed source; dirty source paths: ${dirtySourcePaths.join(', ')}`)

const EXCLUDE = new Set(['.git', 'node_modules', 'dist', '.armorbreak', '.github'])
const EXCLUDE_PATHS = new Set([
  'docs/v2/release/readiness.json', 'docs/v2/release/sbom.spdx.json',
  'FOUR_REVIEW_UNIFIED_FINDINGS.json', 'FOUR_REVIEW_RECONCILIATION.md',
])
function files() {
  return gitPaths(['ls-files', '-z']).filter((rel) => {
    if (EXCLUDE_PATHS.has(rel) || rel.startsWith('docs/v2/acceptance/') || rel.endsWith('.pyc')) return false
    return ![...EXCLUDE].some((directory) => rel === directory || rel.startsWith(`${directory}/`))
  }).map((path) => {
    const bytes = readSafeRepoFile(root, path)
    return { path, bytes, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }
  }).sort((left, right) => left.path.localeCompare(right.path))
}

function octal(value, length) { return `${value.toString(8).padStart(length - 1, '0')}\0` }
function splitName(name) {
  const bytes = Buffer.byteLength(name)
  if (bytes <= 100) return { name, prefix: '' }
  for (let i = name.lastIndexOf('/'); i > 0; i -= 1) {
    const prefix = name.slice(0, i)
    const rest = name.slice(i + 1)
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(rest) <= 100) return { name: rest, prefix }
  }
  throw new Error(`path too long for ustar: ${name}`)
}
function header(name, size, type = '0') {
  const split = splitName(name)
  const block = Buffer.alloc(512, 0)
  block.write(split.name, 0, 100, 'utf8')
  block.write(octal(0o644, 8), 100, 8, 'ascii')
  block.write(octal(0, 8), 108, 8, 'ascii')
  block.write(octal(0, 8), 116, 8, 'ascii')
  block.write(octal(size, 12), 124, 12, 'ascii')
  block.write(octal(0, 12), 136, 12, 'ascii')
  block.write('        ', 148, 8, 'ascii')
  block.write(type, 156, 1, 'ascii')
  block.write('ustar\0', 257, 6, 'ascii')
  block.write('00', 263, 2, 'ascii')
  block.write('root', 265, 32, 'ascii')
  block.write('root', 297, 32, 'ascii')
  if (split.prefix) block.write(split.prefix, 345, 155, 'utf8')
  let sum = 0
  for (const byte of block) sum += byte
  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
  return block
}
function tar(entries) {
  const chunks = []
  for (const entry of entries) {
    const body = entry.bytes
    chunks.push(header(entry.path, body.length), body)
    const pad = (512 - (body.length % 512)) % 512
    if (pad) chunks.push(Buffer.alloc(pad))
  }
  chunks.push(Buffer.alloc(1024))
  return Buffer.concat(chunks)
}

function buildOnce(name, entries) {
  const archive = deterministicGzip(tar(entries))
  const target = join(outDir, name)
  writeFileSync(target, archive)
  return { target, sha256: createHash('sha256').update(archive).digest('hex'), bytes: archive.length, entries }
}

mkdirSync(outDir, { recursive: true })
const name = `armorbreak-portable-${pkg.version}.tar.gz`
const sourceEntries = files()
const first = buildOnce(name, sourceEntries)
const second = buildOnce(`${name}.reproduce`, sourceEntries)
const reproducible = first.sha256 === second.sha256
if (!reproducible) console.error(`reproducibility mismatch: ${first.sha256} != ${second.sha256}`)
const sbomPath = join(outDir, `${name}.sbom.cdx.json`)
const sbom = {
  bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
  metadata: { component: { type: 'application', name: pkg.name, version: pkg.version, hashes: [{ alg: 'SHA-256', content: first.sha256 }] } },
  components: [...new Set(sourceEntries.map((entry) => entry.path.startsWith('packages/') ? entry.path.split('/')[1] : null).filter(Boolean))]
    .sort()
    .map((name) => {
      const componentFiles = sourceEntries.filter((entry) => entry.path.startsWith(`packages/${name}/`))
        .map(({ path, size, sha256 }) => ({ path, size, sha256 }))
      return {
        type: 'library', name: `@armorbreak/${name}`, version: pkg.version,
        hashes: [{ alg: 'SHA-256', content: createHash('sha256').update(JSON.stringify(componentFiles)).digest('hex') }],
      }
    }),
}
writeFileSync(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`)
const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const signature = await signArtifact(first.target, privateKey.export({ type: 'pkcs8', format: 'pem' }))
const signatureValid = await verifyArtifactSignature(first.target, signature.signature, publicKey.export({ type: 'spki', format: 'pem' }))
const cleanDir = mkdtempSync(join(tmpdir(), 'abm-cleanroom-'))
let cleanRoom
try {
  execFileSync('tar', ['-xzf', '-'], { cwd: cleanDir, input: readFileSync(first.target), stdio: ['pipe', 'pipe', 'pipe'] })
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'capabilities', '--json'], {
    cwd: cleanDir,
    env: { ...process.env, ARMORBREAK_STATE_ROOT: join(cleanDir, '.state'), ARMORBREAK_WORKSPACE: cleanDir },
    encoding: 'utf8', timeout: 120_000,
  })
  const capabilities = cli.status === 0 ? JSON.parse(cli.stdout).length : 0
  cleanRoom = { extracted: true, cliCapabilities: capabilities, result: capabilities === 46 ? 'PASS' : 'FAIL', stderr: String(cli.stderr ?? '').slice(0, 1000) }
} catch (error) {
  cleanRoom = { extracted: false, cliCapabilities: 0, result: 'FAIL', error: String(error.message) }
} finally {
  rmSync(cleanDir, { recursive: true, force: true })
}
const manifest = {
  schemaVersion: 'armorbreak.release-build/v1', generatedAt: new Date().toISOString(), commit, package: pkg.name, version: pkg.version,
  artifact: basename(first.target), bytes: first.bytes, sha256: first.sha256, reproducible,
  sbom: basename(sbomPath), sbomSha256: createHash('sha256').update(readFileSync(sbomPath)).digest('hex'),
  files: first.entries.length,
  contentManifest: first.entries.map(({ path, size, sha256 }) => ({ path, size, sha256 })),
  contentManifestSha256: createHash('sha256').update(JSON.stringify(first.entries.map(({ path, size, sha256 }) => ({ path, size, sha256 })))).digest('hex'),
  toolchain: { node: process.version, platform: process.platform, arch: process.arch, zlib: process.versions.zlib },
  cleanRoom, signature: { algorithm: 'ed25519', testKey: true, valid: signatureValid, signature: signature.signature, publicKey: publicKey.export({ type: 'spki', format: 'pem' }) },
  productionSigned: false,
  limitations: ['Test Ed25519 key verifies the signing mechanism; it is not a production identity.', 'Docker/npm publish not performed by this builder.'],
}
writeFileSync(join(outDir, `${name}.manifest.json`), `${JSON.stringify(manifest, null, 2)}\n`)
mkdirSync(resolve(evidencePath, '..'), { recursive: true })
writeFileSync(evidencePath, `${JSON.stringify(manifest, null, 2)}\n`)
if (!process.argv.includes('--no-portable-evidence')) writeFileSync(join(root, 'docs/v2/acceptance/portable-artifact.json'), `${JSON.stringify({
  schemaVersion: 'armorbreak.portable-artifact/v1', generatedAt: manifest.generatedAt, sourceCommit: commit, version: pkg.version,
  artifact: basename(first.target), bytes: first.bytes, sha256: first.sha256, sbom: basename(sbomPath),
  cleanRoom, signed: false,
  limitations: ['Test Ed25519 signature only; no production identity.', 'Docker/npm publish not performed.'],
}, null, 2)}\n`)
console.log(JSON.stringify({ artifact: first.target, sha256: first.sha256, reproducible, signatureValid, sbom: sbomPath, manifest: join(outDir, `${name}.manifest.json`), evidence: evidencePath }, null, 2))
if (!reproducible || !signatureValid) process.exitCode = 1
