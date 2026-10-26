#!/usr/bin/env node
/** Read-only verification of an already owner-published Stable release tag.
 * Publication eligibility remains the separate, owner-authenticated Stable Gate.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { verifyPortableArtifactAttestation } from '../../lib/release/artifactAttestation.js'
import { validateEvidence } from '../../lib/release/evidenceValidator.js'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = process.cwd()
const repository = 'LYL-Z/dsh-armorbreak'
const tag = 'v2.2.0'
assert.equal(process.env.GITHUB_REF, `refs/tags/${tag}`, 'this verifier applies only to the published Stable tag')
assert.equal(process.env.GITHUB_EVENT_NAME, 'push')
const run = (command, args) => execFileSync(command, args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }).trim()
const gh = (args) => JSON.parse(run('gh', args))
const commit = run('git', ['rev-parse', 'HEAD'])
assert.equal(commit, process.env.GITHUB_SHA)
assert.equal(run('git', ['ls-remote', 'origin', 'refs/heads/main']).split(/\s+/)[0], commit, 'tag must match the current protected main source')
const release = gh(['api', `repos/${repository}/releases/tags/${tag}`])
assert.equal(release.tag_name, tag)
assert.equal(release.draft, false)
assert.equal(release.prerelease, false)
assert.equal(release.author?.login, 'LYL-Z')
assert.equal(release.author?.id, 250811935, 'local evidence cannot substitute for authenticated owner publication')
const ci = gh(['run', 'list', '--repo', repository, '--workflow', '.github/workflows/ci.yml', '--branch', 'main', '--limit', '100', '--json', 'databaseId,headSha,event,conclusion'])
const exact = ci.find((item) => item.headSha === commit && item.event === 'push')
assert.equal(exact?.conclusion, 'success', 'exact-main CI must have succeeded before this published tag')
const detail = gh(['run', 'view', String(exact.databaseId), '--repo', repository, '--json', 'jobs'])
for (const name of ['Node 24 on ubuntu-latest', 'Node 24 on windows-latest', 'L0 offline boundary (static gate)', 'L1 Docker integration (real daemon)', 'Release evidence checks (commit-bound)']) {
  assert.equal(detail.jobs.find((job) => job.name === name)?.conclusion, 'success', name)
}
const download = '.runtime/published-stable'
mkdirSync(download, { recursive: true })
const artifact = 'armorbreak-portable-2.2.0.tar.gz'
const sbom = `${artifact}.sbom.cdx.json`
const names = [artifact, sbom, `${artifact}.manifest.json`, 'stable-gate.json']
run('gh', ['release', 'download', tag, '--repo', repository, '--dir', download, ...names.flatMap((name) => ['--pattern', name])])
const read = (name) => readSafeRepoFile(root, `${download}/${name}`, { requiredPrefix: '.runtime/' })
const manifest = JSON.parse(read(`${artifact}.manifest.json`))
const gate = JSON.parse(read('stable-gate.json'))
const required = ['VERSIONED_STABLE_POLICY', 'EXACT_CLEAN_MAIN_SOURCE', 'PR18_MERGED', 'PR17_MERGED', 'PROTECTED_GITHUB_RELEASE_AUTHORITY', 'PACKAGE_VERSION', 'LEGACY_FULL_GA_PRESERVED', 'EXACT_SHA_GITHUB_CI', 'EXACT_SHA_ATTESTATION_RUN', 'ARTIFACT_SBOM_CONTENT', 'GITHUB_OIDC_PROVENANCE', 'CURRENT_SHA_SECURITY_REVIEW']
assert.equal(gate.schemaVersion, 'armorbreak.v2.2-stable-gate-result/v1')
assert.equal(gate.sourceCommit, commit)
assert.equal(gate.releasable, true)
assert.equal(gate.fullGaReady, false)
assert.deepEqual(gate.blockers, [])
assert.equal(gate.checks.length, required.length)
for (const id of required) assert.equal(gate.checks.find((item) => item.id === id)?.status, 'PASS', id)
assert.equal(manifest.commit, commit)
assert.equal(manifest.artifact, artifact)
assert.equal(manifest.sbom, sbom)
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex')
assert.equal(sha(read(artifact)), manifest.sha256)
assert.equal(sha(read(sbom)), manifest.sbomSha256)
assert.equal(read(artifact).length, manifest.bytes)
const cyclonedx = JSON.parse(read(sbom))
assert.equal(cyclonedx.metadata.component.hashes.find((item) => item.alg === 'SHA-256')?.content, manifest.sha256)
const inventory = JSON.parse(cyclonedx.metadata.component.properties.find((item) => item.name === 'armorbreak:included-file-inventory').value)
assert.deepEqual(inventory, manifest.contentManifest)
assert.equal(sha(Buffer.from(JSON.stringify(inventory))), manifest.contentManifestSha256)
mkdirSync('dist', { recursive: true })
writeSafeRepoFile(root, `dist/${artifact}`, read(artifact), { requiredPrefix: 'dist/' })
const provenance = verifyPortableArtifactAttestation({ repoRoot: root, artifactPath: `dist/${artifact}`, artifactEvidence: { ...manifest, sourceCommit: manifest.commit }, sourceCommit: commit })
assert.equal(provenance.ok, true, provenance.code)
// Only after live owner publication, exact-main CI, and cryptographic provenance
// are established may the non-authorizing validator inspect the S -> E lineage.
const evidence = validateEvidence({ repoRoot: root, commit, allowEvidenceAncestor: true, allowReadiness: true })
assert.equal(evidence.ok, true, evidence.issues.join('; '))
const result = { sourceCommit: commit, tag, releaseUrl: release.html_url, publisher: release.author.login, provenance, evidence, publicationAuthorityGrantedByThisVerifier: false }
writeFileSync(resolve(download, 'verification.json'), `${JSON.stringify(result, null, 2)}\n`)
console.log(JSON.stringify(result, null, 2))
