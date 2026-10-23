import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, linkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { verifyPortableArtifactAttestation } from '../lib/release/artifactAttestation.js'

const commit = 'a'.repeat(40)
const workflowPath = '.github/workflows/attest.yml'
const sourceUri = 'https://github.com/LYL-Z/dsh-armorbreak'
const workflowIdentity = `${sourceUri}/${workflowPath}@refs/heads/main`
const predicateType = 'https://slsa.dev/provenance/v1'

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'abm-attestation-'))
  mkdirSync(join(root, 'dist'))
  const bytes = Buffer.from('synthetic portable release artifact')
  const artifact = 'armorbreak-portable-test.tar.gz'
  writeFileSync(join(root, 'dist', artifact), bytes)
  const evidence = { artifact, sourceCommit: commit, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), signed: true }
  return { root, bytes, artifact, evidence, artifactEvidence: evidence, path: `dist/${artifact}` }
}

function verifiedCliResult(artifact, digest, overrides = {}) {
  const certificate = {
    sourceRepositoryURI: sourceUri,
    sourceRepositoryDigest: commit,
    sourceRepositoryRef: 'refs/heads/main',
    subjectAlternativeName: workflowIdentity,
    ...overrides.certificate,
  }
  const statement = {
    predicateType,
    subject: [{ name: artifact, digest: { sha256: digest } }],
    predicate: {
      buildDefinition: {
        externalParameters: { workflow: { repository: sourceUri, path: workflowPath, ref: 'refs/heads/main' } },
        resolvedDependencies: [{ digest: { gitCommit: commit } }],
      },
    },
    ...overrides.statement,
  }
  return JSON.stringify([{ verificationResult: { signature: { certificate }, statement } }])
}

test('signed metadata alone cannot satisfy the release artifact attestation gate', () => {
  const fixture = setup()
  try {
    let called = false
    const result = verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: fixture.path, sourceCommit: commit, runGh: () => { called = true; return '[]' } })
    assert.equal(result.ok, false)
    assert.equal(result.code, 'ATTESTATION_IDENTITY_OR_SUBJECT_MISMATCH')
    assert.equal(called, true)
    assert.equal(verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: undefined, sourceCommit: commit }).code, 'ARTIFACT_PATH_NOT_PROVIDED')
  } finally { rmSync(fixture.root, { recursive: true, force: true }) }
})

test('accepts only GitHub-verified provenance for the exact artifact, current commit, and main workflow', () => {
  const fixture = setup()
  try {
    let seenArgs
    const result = verifyPortableArtifactAttestation({
      ...fixture,
      repoRoot: fixture.root,
      artifactPath: fixture.path,
      sourceCommit: commit,
      runGh: (args) => { seenArgs = args; return verifiedCliResult(fixture.artifact, fixture.evidence.sha256) },
    })
    assert.equal(result.ok, true)
    assert.equal(result.sha256, fixture.evidence.sha256)
    assert.ok(seenArgs.includes('--cert-identity'))
    assert.ok(seenArgs.includes(workflowIdentity))
    assert.ok(seenArgs.includes('--signer-workflow'))
  } finally { rmSync(fixture.root, { recursive: true, force: true }) }
})

test('rejects provenance for a different branch, artifact digest, or source commit', () => {
  const fixture = setup()
  try {
    for (const output of [
      verifiedCliResult(fixture.artifact, 'b'.repeat(64)),
      verifiedCliResult(fixture.artifact, fixture.evidence.sha256, { certificate: { sourceRepositoryRef: 'refs/heads/feature/other' } }),
      verifiedCliResult(fixture.artifact, fixture.evidence.sha256, { certificate: { sourceRepositoryDigest: 'c'.repeat(40) } }),
    ]) {
      const result = verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: fixture.path, sourceCommit: commit, runGh: () => output })
      assert.equal(result.ok, false)
      assert.equal(result.code, 'ATTESTATION_IDENTITY_OR_SUBJECT_MISMATCH')
    }
    assert.equal(verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: fixture.path, sourceCommit: 'c'.repeat(40) }).code, 'ARTIFACT_SOURCE_COMMIT_MISMATCH')
  } finally { rmSync(fixture.root, { recursive: true, force: true }) }
})

test('rejects artifact digest mismatch before calling GitHub CLI', () => {
  const fixture = setup()
  try {
    let called = false
    fixture.evidence.sha256 = 'b'.repeat(64)
    const result = verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: fixture.path, sourceCommit: commit, runGh: () => { called = true; return '[]' } })
    assert.equal(result.code, 'ARTIFACT_DIGEST_MISMATCH')
    assert.equal(called, false)
  } finally { rmSync(fixture.root, { recursive: true, force: true }) }
})

test('rejects hard-linked and path-escaped artifacts', () => {
  const fixture = setup()
  try {
    const hardlinkPath = join(fixture.root, 'dist', 'hardlinked.tar.gz')
    linkSync(join(fixture.root, 'dist', fixture.artifact), hardlinkPath)
    const hardlink = verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: `dist/${fixture.artifact}`, sourceCommit: commit, runGh: () => '[]' })
    assert.equal(hardlink.code, 'ARTIFACT_FILE_UNSAFE_OR_MISSING')
    assert.equal(verifyPortableArtifactAttestation({ ...fixture, repoRoot: fixture.root, artifactPath: '../outside.tar.gz', sourceCommit: commit }).code, 'ARTIFACT_PATH_OUTSIDE_DIST')
  } finally { rmSync(fixture.root, { recursive: true, force: true }) }
})

test('every GitHub Actions dependency is pinned to a full commit SHA', () => {
  for (const workflow of ['.github/workflows/ci.yml', '.github/workflows/attest.yml']) {
    const text = readFileSync(workflow, 'utf8')
    const refs = [...text.matchAll(/^\s*uses:\s*([^\s#]+)/gm)].map((match) => match[1])
    assert.ok(refs.length > 0, `${workflow} should declare workflow actions`)
    for (const ref of refs) assert.match(ref, /^[^@]+@[a-f0-9]{40}$/i, `${workflow} has an unpinned action: ${ref}`)
  }
})
