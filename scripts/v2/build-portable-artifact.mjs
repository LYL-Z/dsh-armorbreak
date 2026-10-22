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
execFileSync('tar', ['-czf', artifactPath, ...paths], { cwd: root, stdio: 'pipe' })
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
  limitations: ['No Ed25519 release signature in this slice.', 'Tar metadata is not reproducible byte-for-byte across hosts.'],
}
writeFileSync(join(outDir, `${name}.manifest.json`), `${JSON.stringify(manifest, null, 2)}\n`)
const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  version: 1,
  metadata: { component: { type: 'application', name: pkg.name, version: pkg.version, hashes: [{ alg: 'SHA-256', content: sha256 }] } },
  components: ['@armorbreak/core', '@armorbreak/protocol', '@armorbreak/engine-node', '@armorbreak/mcp-server', '@armorbreak/cli', '@armorbreak/provider-router', '@armorbreak/installer', '@armorbreak/adapter-dsh', '@armorbreak/skill-router'].map((component) => ({ type: 'library', name: component, version: pkg.version })),
}
writeFileSync(join(outDir, `${name}.sbom.cdx.json`), `${JSON.stringify(sbom, null, 2)}\n`)
console.log(JSON.stringify({ artifact: artifactPath, manifest: join(outDir, `${name}.manifest.json`), bytes: manifest.bytes, sha256, commit }, null, 2))
