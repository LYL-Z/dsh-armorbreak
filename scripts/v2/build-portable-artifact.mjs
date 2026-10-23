/**
 * Build a self-contained portable artifact from the repository without
 * node_modules/.git, then emit SHA-256 manifest + minimal CycloneDX SBOM.
 * Usage: node scripts/v2/build-portable-artifact.mjs --out <dir>
 */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import { readSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const args = process.argv.slice(2)
const outIndex = args.indexOf('--out')
const outDir = resolve(outIndex >= 0 ? args[outIndex + 1] : join(root, 'dist'))
mkdirSync(outDir, { recursive: true })
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim()
const name = `armorbreak-portable-${pkg.version}.tar.gz`
const artifactPath = join(outDir, name)
const paths = ['package.json', 'LICENSE', 'lib', 'packages', 'skills', 'plugins', 'docs/v2/core', 'docs/v2/provider-matrix.md']
const includePath = (path) => path === 'package.json' || path === 'LICENSE' ||
  ['lib/', 'packages/', 'skills/', 'plugins/', 'docs/v2/core/', 'docs/v2/provider-matrix.md'].some((prefix) =>
    prefix.endsWith('/') ? path.startsWith(prefix) : path === prefix)
const gitPaths = (args) => execFileSync('git', args, { cwd: root }).toString('utf8').split('\0').filter(Boolean).map((path) => path.replaceAll('\\', '/'))
const dirtyInputs = [...new Set([
  ...gitPaths(['diff', '--name-only', '-z', 'HEAD', '--']),
  ...gitPaths(['ls-files', '--others', '--exclude-standard', '-z']),
])].filter(includePath)
if (dirtyInputs.length) throw new Error(`portable artifact inputs must be committed: ${dirtyInputs.join(', ')}`)
const tracked = gitPaths(['ls-tree', '-r', '--name-only', '-z', commit]).filter(includePath)
const sourceFiles = tracked.filter((path) => !path.endsWith('.pyc')).map((path) => {
  const bytes = readSafeRepoFile(root, path)
  return { path, bytes, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }
}).sort((left, right) => left.path.localeCompare(right.path))
const tarBytes = execFileSync('git', ['archive', '--format=tar', commit, ...paths, ':(exclude)**/*.pyc'], { cwd: root, maxBuffer: 64 * 1024 * 1024 })
writeFileSync(artifactPath, gzipSync(tarBytes, { level: 9 }))
const bytes = readFileSync(artifactPath)
const sha256 = createHash('sha256').update(bytes).digest('hex')
const manifest = {
  schemaVersion: 'armorbreak.portable-artifact/v1',
  name: pkg.name,
  version: pkg.version,
  commit,
  artifact: basename(artifactPath),
  bytes: statSync(artifactPath).size,
  sha256,
  sourcePinned: true,
  signed: false,
  contents: paths,
  contentManifest: sourceFiles.map(({ path, size, sha256 }) => ({ path, size, sha256 })),
  contentManifestSha256: createHash('sha256').update(JSON.stringify(sourceFiles.map(({ path, size, sha256 }) => ({ path, size, sha256 })))).digest('hex'),
  limitations: ['No Ed25519 release signature in this slice.', 'Archive digest can vary by host toolchain; compare the content manifest for cross-toolchain source identity.'],
}
writeFileSync(join(outDir, `${name}.manifest.json`), `${JSON.stringify(manifest, null, 2)}\n`)
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { component: { type: 'application', name: pkg.name, version: pkg.version, hashes: [{ alg: 'SHA-256', content: sha256 }] } },
  components: [...new Set(sourceFiles.map((file) => file.path.startsWith('packages/') ? file.path.split('/')[1] : null).filter(Boolean))]
    .sort()
    .map((component) => {
      const componentFiles = sourceFiles.filter((file) => file.path.startsWith(`packages/${component}/`))
        .map(({ path, size, sha256: fileSha256 }) => ({ path, size, sha256: fileSha256 }))
      return {
        type: 'library', name: `@armorbreak/${component}`, version: pkg.version,
        hashes: [{ alg: 'SHA-256', content: createHash('sha256').update(JSON.stringify(componentFiles)).digest('hex') }],
      }
    }),
}
writeFileSync(join(outDir, `${name}.sbom.cdx.json`), `${JSON.stringify(sbom, null, 2)}\n`)
console.log(JSON.stringify({ artifact: artifactPath, manifest: join(outDir, `${name}.manifest.json`), bytes: manifest.bytes, sha256, commit }, null, 2))
