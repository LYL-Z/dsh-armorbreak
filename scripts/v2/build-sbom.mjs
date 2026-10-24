#!/usr/bin/env node
/** Build a minimal SPDX 2.3 SBOM for the zero-runtime-dependency Core bundle. */
import { createHash } from 'node:crypto'
import { lstat, readdir } from 'node:fs/promises'
import { join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const spdxId = (kind, value) => `SPDXRef-${kind}-${sha256(value).slice(0, 24)}`

async function sourceFiles(directory, packageRoot, repoRoot) {
  const result = []
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const absolute = join(directory, entry.name)
    if (entry.isSymbolicLink()) throw new Error(`SBOM refuses linked source entries: ${absolute}`)
    if (entry.isDirectory()) {
      result.push(...await sourceFiles(absolute, packageRoot, repoRoot))
      continue
    }
    const info = await lstat(absolute)
    if (!info.isFile()) throw new Error(`SBOM refuses non-regular source entries: ${absolute}`)
    const path = relative(packageRoot, absolute).split(sep).join('/')
    const repoRelative = relative(repoRoot, absolute).split(sep).join('/')
    const bytes = readSafeRepoFile(repoRoot, repoRelative, { requiredPrefix: 'packages/' })
    result.push({ path, bytes, sha256: sha256(bytes) })
  }
  return result
}

export async function createSpdx({ repoRoot = root, created = new Date().toISOString() } = {}) {
  repoRoot = resolve(repoRoot)
  const pkg = JSON.parse(readSafeRepoFile(repoRoot, 'package.json').toString('utf8').replace(/^\uFEFF/, ''))
  const external = [
    ['TShark', 'GPL-2.0-or-later', 'optional external, not bundled'],
    ['Ghidra', 'Apache-2.0', 'optional external, not bundled'],
    ['JADX', 'Apache-2.0', 'optional external, not bundled'],
    ['Syft', 'Apache-2.0', 'optional external, not bundled'],
    ['Semgrep', 'LGPL-2.1', 'optional external, not bundled'],
    ['Trivy', 'Apache-2.0', 'optional external, not bundled'],
  ]
  const packageDirectories = (await readdir(join(repoRoot, 'packages'), { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .sort((a, b) => a.name.localeCompare(b.name))
  const packages = []
  const files = []
  const relationships = [{
    spdxElementId: 'SPDXRef-DOCUMENT',
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: 'SPDXRef-Package-dsh-armorbreak',
  }]

  for (const [index, [name, license, purpose]] of external.entries()) {
    const id = `SPDXRef-External-${index + 1}`
    packages.push({
      name,
      SPDXID: id,
      downloadLocation: 'NOASSERTION',
      licenseDeclared: license,
      licenseConcluded: 'NOASSERTION',
      primaryPackagePurpose: 'TOOL',
      comment: purpose,
    })
  }

  for (const entry of packageDirectories) {
    const packageRoot = join(repoRoot, 'packages', entry.name)
    let manifest = null
    try { manifest = JSON.parse(readSafeRepoFile(repoRoot, `packages/${entry.name}/package.json`, { requiredPrefix: 'packages/' }).toString('utf8')) } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
    const name = manifest?.name ?? `@armorbreak/${entry.name}`
    const version = manifest?.version ?? pkg.version
    const id = spdxId('Package', name)
    const componentFiles = await sourceFiles(packageRoot, packageRoot, repoRoot)
    packages.push({
      name,
      versionInfo: version,
      SPDXID: id,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: true,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      primaryPackagePurpose: 'LIBRARY',
      sourceInfo: 'Internal source component; its files and SHA-256 digests are listed in this document.',
    })
    relationships.push({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: id,
    })

    for (const componentFile of componentFiles) {
      const fileName = `./packages/${entry.name}/${componentFile.path}`
      const fileId = spdxId('File', fileName)
      files.push({
        fileName,
        SPDXID: fileId,
        checksums: [{ algorithm: 'SHA256', checksumValue: componentFile.sha256 }],
        licenseConcluded: 'NOASSERTION',
        licenseInfoInFiles: ['NOASSERTION'],
        fileCopyrightText: 'NOASSERTION',
      })
      relationships.push({
        spdxElementId: id,
        relationshipType: 'CONTAINS',
        relatedSpdxElement: fileId,
      })
    }
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${pkg.name}-${pkg.version}`,
    documentNamespace: `https://github.com/LYL-Z/dsh-armorbreak/sbom/${pkg.version}`,
    creationInfo: { created, creators: ['Tool: scripts/v2/build-sbom.mjs'] },
    packages: [
      {
        name: pkg.name,
        versionInfo: pkg.version,
        SPDXID: 'SPDXRef-Package-dsh-armorbreak',
        downloadLocation: pkg.repository?.url ?? 'NOASSERTION',
        licenseConcluded: 'MIT',
        licenseDeclared: 'MIT',
        copyrightText: 'Copyright (c) 2026 LYL-Z',
        primaryPackagePurpose: 'APPLICATION',
      },
      ...external.map(([name, license, purpose], index) => ({
        name,
        SPDXID: `SPDXRef-External-${index + 1}`,
        downloadLocation: 'NOASSERTION',
        licenseDeclared: license,
        licenseConcluded: 'NOASSERTION',
        primaryPackagePurpose: 'TOOL',
        comment: purpose,
      })),
      ...packages.filter((component) => component.primaryPackagePurpose === 'LIBRARY'),
    ],
    files,
    relationships,
    annotations: [{
      annotationType: 'OTHER',
      annotator: 'Tool: scripts/v2/build-sbom.mjs',
      annotationDate: created,
      comment: 'External tools are not bundled; their licenses must be reviewed separately before distribution.',
    }],
  }
}

export async function main() {
  const sbom = await createSpdx()
  writeSafeRepoFile(root, 'docs/v2/release/sbom.spdx.json', `${JSON.stringify(sbom, null, 2)}\n`, { requiredPrefix: 'docs/v2/release/' })
  console.log(JSON.stringify({
    packages: sbom.packages.length,
    internalComponents: sbom.packages.filter((component) => component.primaryPackagePurpose === 'LIBRARY').length,
    componentFiles: sbom.files.length,
    bundledDependencies: Object.keys(JSON.parse(readSafeRepoFile(root, 'package.json').toString('utf8')).dependencies ?? {}).length,
    output: 'docs/v2/release/sbom.spdx.json',
  }, null, 2))
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(String(error?.stack ?? error))
    process.exitCode = 1
  })
}
