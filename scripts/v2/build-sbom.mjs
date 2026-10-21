#!/usr/bin/env node
/** Build a minimal SPDX 2.3 SBOM for the zero-runtime-dependency Core bundle. */
import { readFile, writeFile } from 'node:fs/promises'

const pkg = JSON.parse((await readFile('package.json', 'utf8')).replace(/^\uFEFF/, ''))
const external = [
  ['TShark', 'GPL-2.0-or-later', 'optional external, not bundled'],
  ['Ghidra', 'Apache-2.0', 'optional external, not bundled'],
  ['JADX', 'Apache-2.0', 'optional external, not bundled'],
  ['Syft', 'Apache-2.0', 'optional external, not bundled'],
  ['Semgrep', 'LGPL-2.1', 'optional external, not bundled'],
  ['Trivy', 'Apache-2.0', 'optional external, not bundled'],
]
const sbom = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `${pkg.name}-${pkg.version}`,
  documentNamespace: `https://github.com/LYL-Z/dsh-armorbreak/sbom/${pkg.version}`,
  creationInfo: { created: new Date().toISOString(), creators: ['Tool: scripts/v2/build-sbom.mjs'] },
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
  ],
  relationships: external.map((_, index) => ({ spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: `SPDXRef-Package-dsh-armorbreak` })).slice(0, 1),
  annotations: [{ annotationType: 'OTHER', annotator: 'Tool: scripts/v2/build-sbom.mjs', annotationDate: new Date().toISOString(), comment: 'External tools are not bundled; their licenses must be reviewed separately before distribution.' }],
}
await writeFile('docs/v2/release/sbom.spdx.json', `${JSON.stringify(sbom, null, 2)}\n`)
console.log(JSON.stringify({ packages: sbom.packages.length, bundledDependencies: Object.keys(pkg.dependencies ?? {}).length, output: 'docs/v2/release/sbom.spdx.json' }, null, 2))
