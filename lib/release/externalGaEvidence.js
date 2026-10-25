import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto'
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import { readSafeRepoFile } from './safeEvidenceFile.js'

const REPOSITORY = 'LYL-Z/dsh-armorbreak'
const BUNDLE_ENV = 'ARMORBREAK_EXTERNAL_GA_EVIDENCE_BUNDLE'
const TRUSTED_SIGNERS_HASH_ENV = 'ARMORBREAK_EXTERNAL_GA_TRUSTED_SIGNERS_SHA256'
const EVIDENCE_PREFIX = 'docs/v2/acceptance/external-evidence/'
const MAX_BUNDLE_BYTES = 2 * 1024 * 1024
const BUNDLE_SCHEMA = 'armorbreak.external-ga-evidence/v1'
const CLAIM_SCHEMA = 'armorbreak.external-ga-claim/v1'
const PRODUCTION_SIGNATURE_SCHEMA = 'armorbreak.production-signature-evidence/v1'
const HASH_RE = /^[a-f0-9]{64}$/i
const SIGNER_ROLES = new Set(['provider-verifier', 'independent-reviewer', 'host-verifier', 'production-signer'])

export const REQUIRED_HOST_INSTALLS = Object.freeze([
  'DSH', 'Codex', 'Hermes Agent', 'Claude Cowork', 'Cursor', 'WorkBuddy', 'ZCode', 'Pi', 'TRAE', 'Antigravity',
])

export const REQUIRED_EXTERNAL_GA_CLAIMS = Object.freeze([
  ...['ABU-311', 'ABU-312', 'ABU-313', 'ABU-314', 'ABU-318'].map((taskId) => ({
    claimId: `realEndpoint:${taskId}`,
    criterion: 'realEndpoint',
    subject: taskId,
    signerRole: 'provider-verifier',
    blockerCode: `${taskId}_REAL_ENDPOINT_BLOCKED`,
  })),
  {
    claimId: 'independentReview:ABU-409',
    criterion: 'independentReview',
    subject: 'ABU-409',
    signerRole: 'independent-reviewer',
    blockerCode: 'ABU-409_INDEPENDENT_REVIEW_BLOCKED',
  },
  ...REQUIRED_HOST_INSTALLS.map((host) => ({
    claimId: `hostInstall:${host}`,
    criterion: 'hostInstall',
    subject: host,
    signerRole: 'host-verifier',
    blockerCode: `HOST_${host.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_EXTERNAL_EVIDENCE_NOT_VERIFIED`,
  })),
  {
    claimId: 'productionSignature:ABU-408',
    criterion: 'productionSignature',
    subject: 'ABU-408',
    signerRole: 'production-signer',
    blockerCode: 'ABU-408_PRODUCTION_SIGNATURE_BLOCKED',
  },
])

function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    return `{${entries.join(',')}}`
  }
  throw new TypeError('external evidence payload contains a non-JSON value')
}

function claimPayload(repository, sourceCommit, claim) {
  const { signature, ...signedClaim } = claim
  return canonicalJson({ schemaVersion: CLAIM_SCHEMA, repository, sourceCommit, claim: signedClaim })
}

export function productionArtifactSignaturePayload({ repository = REPOSITORY, sourceCommit, artifact, sha256 }) {
  return canonicalJson({
    schemaVersion: PRODUCTION_SIGNATURE_SCHEMA,
    repository,
    sourceCommit,
    artifact,
    sha256: String(sha256).toLowerCase(),
  })
}

function parseTrustedSigners(raw) {
  if (typeof raw !== 'string' || raw.trim() === '') return new Map()
  let parsed
  try { parsed = JSON.parse(raw) } catch { return new Map() }
  if (!Array.isArray(parsed)) return new Map()
  const trusted = new Map()
  const fingerprints = new Set()
  for (const entry of parsed) {
    if (!entry || typeof entry.id !== 'string' || !entry.id || typeof entry.publicKeyPem !== 'string') continue
    const roles = Array.isArray(entry.roles) ? entry.roles : typeof entry.role === 'string' ? [entry.role] : []
    if (roles.length !== 1 || roles.some((role) => !SIGNER_ROLES.has(role))) continue
    try {
      const publicKey = createPublicKey(entry.publicKeyPem.replace(/\\n/g, '\n'))
      if (publicKey.asymmetricKeyType !== 'ed25519') continue
      const fingerprint = createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex')
      if (trusted.has(entry.id) || fingerprints.has(fingerprint)) continue
      fingerprints.add(fingerprint)
      trusted.set(entry.id, { id: entry.id, roles: new Set(roles), publicKey })
    } catch { /* Invalid keys fail closed and are not trusted. */ }
  }
  return trusted
}

function verifyTrustedSignerConfiguration(raw, expectedSha256) {
  const bytes = Buffer.from(typeof raw === 'string' ? raw : '', 'utf8')
  const actualSha256 = bytes.length > 0 ? createHash('sha256').update(bytes).digest('hex') : null
  if (!HASH_RE.test(expectedSha256 ?? '')) {
    return { trusted: new Map(), status: 'UNVERIFIED', sha256: actualSha256, reason: 'trusted signer configuration SHA-256 pin is missing or invalid' }
  }
  if (!actualSha256 || actualSha256 !== expectedSha256.toLowerCase()) {
    return { trusted: new Map(), status: 'UNVERIFIED', sha256: actualSha256, reason: 'trusted signer configuration SHA-256 does not match the protected pin' }
  }
  const trusted = parseTrustedSigners(raw)
  if (trusted.size === 0) {
    return { trusted, status: 'UNVERIFIED', sha256: actualSha256, reason: 'pinned trusted signer configuration has no valid signers' }
  }
  return { trusted, status: 'PIN_MATCHED', sha256: actualSha256, reason: null }
}

function safeEvidencePath(value) {
  if (typeof value !== 'string' || !value.startsWith(EVIDENCE_PREFIX) || value.includes('\\')) return false
  const segments = value.split('/')
  return segments.every((segment) => segment && segment !== '.' && segment !== '..')
}

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

function readExternalBundle(repoRoot, bundlePath) {
  if (typeof bundlePath !== 'string' || !bundlePath || !isAbsolute(bundlePath)) {
    throw new Error(`${BUNDLE_ENV} must name an absolute path to an external receipt bundle`)
  }
  const absolute = resolve(bundlePath)
  const repositoryRoot = realpathSync(resolve(repoRoot))
  const canonical = realpathSync(absolute)
  const rel = relative(repositoryRoot, canonical)
  if (rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))) {
    throw new Error('external receipt bundle must be stored outside the repository tree')
  }
  const initial = lstatSync(absolute, { bigint: true })
  if (initial.isSymbolicLink() || !initial.isFile() || initial.nlink > 1n || initial.size > BigInt(MAX_BUNDLE_BYTES)) {
    throw new Error('external receipt bundle must be a bounded, single-link regular file')
  }
  if (!samePath(canonical, absolute)) throw new Error('external receipt bundle path is not canonical')

  let descriptor
  try {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)
    descriptor = openSync(absolute, flags)
    const opened = fstatSync(descriptor, { bigint: true })
    if (!opened.isFile() || opened.nlink > 1n || opened.dev !== initial.dev || opened.ino === 0n || opened.ino !== initial.ino || opened.size !== initial.size) {
      throw new Error('external receipt bundle identity changed while opening')
    }
    const buffer = Buffer.alloc(Number(opened.size))
    let bytesRead = 0
    while (bytesRead < buffer.length) {
      const count = readSync(descriptor, buffer, bytesRead, buffer.length - bytesRead, bytesRead)
      if (count === 0) break
      bytesRead += count
    }
    const after = fstatSync(descriptor, { bigint: true })
    const latestPath = lstatSync(absolute, { bigint: true })
    if (bytesRead !== buffer.length || latestPath.isSymbolicLink() || latestPath.dev !== initial.dev || latestPath.ino !== initial.ino ||
        after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs) {
      throw new Error('external receipt bundle changed while reading')
    }
    return buffer
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

function readClaimEvidence(repoRoot, claim, requirement) {
  if (!HASH_RE.test(claim.evidenceSha256 ?? '')) throw new Error('evidence SHA-256 is invalid')
  const hasPath = typeof claim.evidencePath === 'string'
  const hasInlineEvidence = typeof claim.evidenceBase64 === 'string'
  if (hasPath === hasInlineEvidence) throw new Error('exactly one evidencePath or evidenceBase64 is required')
  if (hasInlineEvidence) {
    if (requirement.criterion !== 'productionSignature') throw new Error('inline evidence is only allowed for the production signature receipt')
    const bytes = Buffer.from(claim.evidenceBase64, 'base64')
    if (bytes.length > 16 * 1024 * 1024 || bytes.toString('base64') !== claim.evidenceBase64) throw new Error('inline evidence is malformed or too large')
    return bytes
  }
  if (!safeEvidencePath(claim.evidencePath)) throw new Error('evidence path is invalid')
  return readSafeRepoFile(repoRoot, claim.evidencePath, {
    requiredPrefix: EVIDENCE_PREFIX,
    maxBytes: 16 * 1024 * 1024,
  })
}

function verifyProductionSignature(proofBytes, signer, artifactEvidence, sourceCommit) {
  if (!artifactEvidence || artifactEvidence.sourceCommit !== sourceCommit ||
      typeof artifactEvidence.artifact !== 'string' || !HASH_RE.test(artifactEvidence.sha256 ?? '')) {
    return 'artifact evidence is not bound to this source commit and digest'
  }
  let proof
  try { proof = JSON.parse(proofBytes.toString('utf8')) } catch { return 'production signature evidence is not valid JSON' }
  if (proof?.schemaVersion !== PRODUCTION_SIGNATURE_SCHEMA || proof.sourceCommit !== sourceCommit ||
      proof.repository !== REPOSITORY || proof.artifact !== artifactEvidence.artifact ||
      proof.sha256?.toLowerCase() !== artifactEvidence.sha256.toLowerCase() ||
      typeof proof.signature !== 'string') return 'production signature subject does not match the candidate artifact'
  let signature
  try { signature = Buffer.from(proof.signature, 'base64') } catch { return 'production signature is malformed' }
  if (signature.length !== 64 || signature.toString('base64') !== proof.signature) return 'production signature is malformed'
  const payload = productionArtifactSignaturePayload({
    sourceCommit,
    artifact: artifactEvidence.artifact,
    sha256: artifactEvidence.sha256,
  })
  return verifySignature(null, Buffer.from(payload), signer.publicKey, signature)
    ? null
    : 'production artifact signature is invalid'
}

function failureFor(requirement, reason) {
  return {
    claimId: requirement.claimId,
    verified: false,
    signerRole: requirement.signerRole,
    reason,
    blocker: {
      code: requirement.blockerCode,
      detail: `${requirement.subject} ${requirement.criterion} evidence is not verified: ${reason}`,
    },
  }
}

/**
 * Validate externally signed GA evidence. Task Markdown stays a readable mirror;
 * a claim only releases its GA blocker when a role-authorized Ed25519 signer has
 * signed a commit-bound claim that names a safe, hash-matched evidence file.
 */
export function verifyExternalGaEvidence({
  repoRoot,
  sourceCommit,
  artifactEvidence,
  trustedSignersRaw = process.env.ARMORBREAK_EXTERNAL_GA_TRUSTED_SIGNERS,
  trustedSignersSha256 = process.env[TRUSTED_SIGNERS_HASH_ENV],
  bundlePath = process.env[BUNDLE_ENV],
}) {
  const trustConfiguration = verifyTrustedSignerConfiguration(trustedSignersRaw, trustedSignersSha256)
  let bundle
  let bundleBytes
  try {
    bundleBytes = readExternalBundle(repoRoot, bundlePath)
    bundle = JSON.parse(bundleBytes.toString('utf8'))
  } catch { bundle = null; bundleBytes = null }

  const bundleError = !bundle
    ? 'signed external GA evidence bundle is missing or unsafe'
    : bundle.schemaVersion !== BUNDLE_SCHEMA
      ? 'external GA evidence schema is unsupported'
      : bundle.repository !== REPOSITORY
        ? 'external GA evidence repository does not match'
        : bundle.sourceCommit !== sourceCommit
          ? 'external GA evidence is not bound to the current commit'
          : null

  const verifiedClaims = []
  const failures = []
  const claims = Array.isArray(bundle?.claims) ? bundle.claims : []
  for (const requirement of REQUIRED_EXTERNAL_GA_CLAIMS) {
    let reason = bundleError ?? trustConfiguration.reason
    let signer
    let proofBytes
    const matches = claims.filter((claim) => claim?.claimId === requirement.claimId)
    if (!reason && matches.length !== 1) reason = matches.length === 0 ? 'signed claim is missing' : 'duplicate signed claims are not allowed'
    const claim = matches[0]
    if (!reason && (claim.status !== 'PASS' || claim.criterion !== requirement.criterion || claim.subject !== requirement.subject)) {
      reason = 'claim status or subject does not match the required acceptance criterion'
    }
    if (!reason) {
      try { proofBytes = readClaimEvidence(repoRoot, claim, requirement) }
      catch (error) { reason = `referenced evidence is missing or unsafe: ${error.message}` }
    }
    if (!reason && createHash('sha256').update(proofBytes).digest('hex') !== claim.evidenceSha256.toLowerCase()) {
      reason = 'referenced evidence SHA-256 does not match'
    }
    if (!reason && typeof claim.verifiedAt !== 'string') reason = 'claim verification time is missing'
    if (!reason && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(claim.verifiedAt) ||
        !Number.isFinite(Date.parse(claim.verifiedAt)))) reason = 'claim verification time is invalid'
    if (!reason) {
      signer = trustConfiguration.trusted.get(claim.signerId)
      if (!signer) reason = 'claim signer is not in the externally configured trust set'
      else if (!signer.roles.has(requirement.signerRole)) reason = `claim signer lacks the ${requirement.signerRole} role`
    }
    if (!reason && requirement.criterion === 'productionSignature') {
      reason = verifyProductionSignature(proofBytes, signer, artifactEvidence, sourceCommit)
    }
    if (!reason) {
      if (typeof claim.signature !== 'string') reason = 'claim signature is missing'
      else {
        let signature
        try { signature = Buffer.from(claim.signature, 'base64') } catch { signature = Buffer.alloc(0) }
        if (signature.length !== 64 || signature.toString('base64') !== claim.signature ||
            !verifySignature(null, Buffer.from(claimPayload(REPOSITORY, sourceCommit, claim)), signer.publicKey, signature)) {
          reason = 'claim signature is invalid'
        }
      }
    }
    if (reason) failures.push(failureFor(requirement, reason))
    else verifiedClaims.push({ claimId: requirement.claimId, verified: true, signerId: signer.id, signerRole: requirement.signerRole })
  }

  return {
    ok: failures.length === 0,
    code: failures.length === 0 ? 'EXTERNAL_GA_EVIDENCE_VERIFIED' : 'EXTERNAL_GA_EVIDENCE_NOT_VERIFIED',
    bundleSource: BUNDLE_ENV,
    bundleSha256: bundleBytes ? createHash('sha256').update(bundleBytes).digest('hex') : null,
    trustConfiguration: {
      status: trustConfiguration.status,
      source: TRUSTED_SIGNERS_HASH_ENV,
      sha256: trustConfiguration.sha256,
    },
    releaseAuthorization: {
      status: 'REVIEW',
      reason: 'Evidence validation does not grant release authority; formal publication requires a protected external approval path.',
    },
    sourceCommit,
    requiredClaims: REQUIRED_EXTERNAL_GA_CLAIMS.length,
    verifiedClaims,
    blockers: failures.map((failure) => failure.blocker),
    claimResults: [...verifiedClaims, ...failures.map(({ blocker, ...failure }) => failure)],
  }
}

export function externalGaEvidenceSigningPayload(repository, sourceCommit, claim) {
  return claimPayload(repository, sourceCommit, claim)
}
