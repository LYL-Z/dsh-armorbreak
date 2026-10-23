import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { resolve, relative, sep, basename } from 'node:path'
import { readSafeRepoFile } from './safeEvidenceFile.js'

const REPOSITORY = 'LYL-Z/dsh-armorbreak'
const SOURCE_URI = 'https://github.com/LYL-Z/dsh-armorbreak'
const WORKFLOW_PATH = '.github/workflows/attest.yml'
const WORKFLOW_IDENTITY = `https://github.com/${REPOSITORY}/${WORKFLOW_PATH}@refs/heads/main`
const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1'
const SHA256_RE = /^[a-f0-9]{64}$/i
const COMMIT_RE = /^[a-f0-9]{40}$/i

function failure(code) { return { ok: false, code } }

/**
 * Verify a portable release artifact against GitHub's cryptographic provenance.
 * A checked-in `signed: true` flag is deliberately not accepted as proof.
 */
export function verifyPortableArtifactAttestation({
  repoRoot,
  artifactPath,
  artifactEvidence,
  sourceCommit,
  runGh = (args, cwd) => execFileSync('gh', args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  }),
}) {
  if (typeof artifactPath !== 'string' || artifactPath.length === 0) return failure('ARTIFACT_PATH_NOT_PROVIDED')
  if (!artifactEvidence || !COMMIT_RE.test(sourceCommit ?? '') || artifactEvidence.sourceCommit !== sourceCommit) {
    return failure('ARTIFACT_SOURCE_COMMIT_MISMATCH')
  }
  if (typeof artifactEvidence.artifact !== 'string' || basename(artifactEvidence.artifact) !== artifactEvidence.artifact ||
      !SHA256_RE.test(artifactEvidence.sha256 ?? '')) return failure('ARTIFACT_METADATA_INVALID')

  let absoluteRoot
  let absoluteArtifact
  let relativeArtifact
  let bytes
  try {
    absoluteRoot = resolve(repoRoot)
    absoluteArtifact = resolve(absoluteRoot, artifactPath)
    relativeArtifact = relative(absoluteRoot, absoluteArtifact).split(sep).join('/')
    if (!relativeArtifact.startsWith('dist/') || basename(relativeArtifact) !== artifactEvidence.artifact) {
      return failure('ARTIFACT_PATH_OUTSIDE_DIST')
    }
    bytes = readSafeRepoFile(absoluteRoot, relativeArtifact, { requiredPrefix: 'dist/' })
  } catch {
    return failure('ARTIFACT_FILE_UNSAFE_OR_MISSING')
  }

  const digest = createHash('sha256').update(bytes).digest('hex')
  if (digest !== artifactEvidence.sha256.toLowerCase() ||
      (Number.isSafeInteger(artifactEvidence.bytes) && artifactEvidence.bytes !== bytes.length)) {
    return failure('ARTIFACT_DIGEST_MISMATCH')
  }

  let verified
  try {
    const args = [
      'attestation', 'verify', absoluteArtifact,
      '--repo', REPOSITORY,
      '--signer-workflow', `${REPOSITORY}/${WORKFLOW_PATH}`,
      '--cert-identity', WORKFLOW_IDENTITY,
      '--predicate-type', PREDICATE_TYPE,
      '--format', 'json',
    ]
    const output = runGh(args, absoluteRoot)
    const entries = JSON.parse(String(output))
    if (!Array.isArray(entries)) return failure('ATTESTATION_OUTPUT_INVALID')
    const expectedDigest = digest.toLowerCase()
    verified = entries.find((entry) => {
      const result = entry?.verificationResult
      const certificate = result?.signature?.certificate
      const statement = result?.statement
      const predicate = statement?.predicate
      const build = predicate?.buildDefinition
      const workflow = build?.externalParameters?.workflow
      const subjectMatches = statement?.predicateType === PREDICATE_TYPE &&
        Array.isArray(statement.subject) && statement.subject.some((subject) =>
          subject?.name === artifactEvidence.artifact && subject?.digest?.sha256?.toLowerCase() === expectedDigest)
      const sourceMatches = certificate?.sourceRepositoryURI === SOURCE_URI &&
        certificate?.sourceRepositoryDigest?.toLowerCase() === sourceCommit.toLowerCase() &&
        certificate?.sourceRepositoryRef === 'refs/heads/main' &&
        certificate?.subjectAlternativeName === WORKFLOW_IDENTITY
      const workflowMatches = workflow?.repository === SOURCE_URI &&
        workflow?.path === WORKFLOW_PATH && workflow?.ref === 'refs/heads/main'
      const dependencyMatches = Array.isArray(build?.resolvedDependencies) &&
        build.resolvedDependencies.some((item) => item?.digest?.gitCommit?.toLowerCase() === sourceCommit.toLowerCase())
      return subjectMatches && sourceMatches && workflowMatches && dependencyMatches
    })
  } catch {
    return failure('ATTESTATION_VERIFICATION_FAILED')
  }

  if (!verified) return failure('ATTESTATION_IDENTITY_OR_SUBJECT_MISMATCH')
  return {
    ok: true,
    code: 'ATTESTATION_VERIFIED',
    artifact: artifactEvidence.artifact,
    sha256: digest,
    sourceCommit,
    signerWorkflow: WORKFLOW_PATH,
    sourceRef: 'refs/heads/main',
  }
}
