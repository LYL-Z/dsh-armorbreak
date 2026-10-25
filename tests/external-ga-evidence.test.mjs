import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import fsSync from 'node:fs'
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import path from 'node:path'
import test from 'node:test'
import {
  REQUIRED_EXTERNAL_GA_CLAIMS,
  externalGaEvidenceSigningPayload,
  productionArtifactSignaturePayload,
  verifyExternalGaEvidence,
} from '../lib/release/externalGaEvidence.js'

const repository = 'LYL-Z/dsh-armorbreak'
const sourceCommit = 'a'.repeat(40)
const artifactEvidence = {
  sourceCommit,
  artifact: 'armorbreak-portable-2.2.0.tar.gz',
  sha256: 'b'.repeat(64),
}
const roleNames = ['provider-verifier', 'independent-reviewer', 'host-verifier', 'production-signer']

function makeRoot(t) {
  const runtime = path.join(process.cwd(), '.runtime', 'tests')
  mkdirSync(runtime, { recursive: true })
  const base = mkdtempSync(path.join(runtime, 'external-ga-evidence-'))
  t.after(() => rmSync(base, { recursive: true, force: true }))
  const repoRoot = path.join(base, 'repo')
  const bundlePath = path.join(base, 'signed-receipts.json')
  mkdirSync(path.join(repoRoot, 'docs', 'v2', 'acceptance', 'external-evidence'), { recursive: true })
  return { repoRoot, bundlePath }
}

function makeSigners() {
  return new Map(roleNames.map((role) => {
    const pair = generateKeyPairSync('ed25519')
    const id = `test-${role}`
    return [role, {
      id,
      role,
      privateKey: pair.privateKey,
      publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }),
    }]
  }))
}

function proofPath(claimId) {
  return `docs/v2/acceptance/external-evidence/${claimId.replace(/[^A-Za-z0-9-]+/g, '-')}.json`
}

function writeProof(root, requirement, signer, commit = sourceCommit, badProductionSignature = false) {
  let content
  if (requirement.criterion === 'productionSignature') {
    const statement = productionArtifactSignaturePayload({ ...artifactEvidence, sourceCommit: commit })
    const signature = sign(null, Buffer.from(statement), signer.privateKey).toString('base64')
    const proof = {
      schemaVersion: 'armorbreak.production-signature-evidence/v1',
      repository,
      sourceCommit: commit,
      artifact: artifactEvidence.artifact,
      sha256: badProductionSignature ? 'c'.repeat(64) : artifactEvidence.sha256,
      signature,
    }
    content = Buffer.from(`${JSON.stringify(proof, null, 2)}\n`)
  } else {
    content = Buffer.from(`${JSON.stringify({ sourceCommit: commit, claimId: requirement.claimId }, null, 2)}\n`)
  }
  const evidenceSha256 = createHash('sha256').update(content).digest('hex')
  if (requirement.criterion === 'productionSignature') {
    return { evidenceBase64: content.toString('base64'), evidenceSha256 }
  }
  const relativePath = proofPath(requirement.claimId)
  writeFileSync(path.join(root.repoRoot, ...relativePath.split('/')), content)
  return { evidencePath: relativePath, evidenceSha256 }
}

function makeBundle(root, signers, options = {}) {
  const claims = REQUIRED_EXTERNAL_GA_CLAIMS.map((requirement) => {
    const signerRole = requirement.claimId === options.wrongRoleClaimId ? 'provider-verifier' : requirement.signerRole
    const signer = signers.get(signerRole)
    const proof = writeProof(root, requirement, signers.get(requirement.signerRole), options.commit ?? sourceCommit,
      requirement.claimId === options.badProductionSignatureClaimId)
    const claim = {
      ...proof,
      claimId: requirement.claimId,
      criterion: requirement.criterion,
      subject: requirement.subject,
      status: 'PASS',
      verifiedAt: '2026-10-24T00:00:00.000Z',
      signerId: signer.id,
    }
    claim.signature = sign(null, Buffer.from(externalGaEvidenceSigningPayload(repository, options.commit ?? sourceCommit, claim)), signer.privateKey).toString('base64')
    return claim
  })
  const bundle = {
    schemaVersion: 'armorbreak.external-ga-evidence/v1',
    repository,
    sourceCommit: options.bundleCommit ?? sourceCommit,
    claims,
  }
  writeFileSync(root.bundlePath, `${JSON.stringify(bundle, null, 2)}\n`)
  return bundle
}

function trustedSignersJson(signers) {
  return JSON.stringify([...signers.values()].map(({ id, role, publicKeyPem }) => ({ id, roles: [role], publicKeyPem })))
}

function trustOptions(signers) {
  const trustedSignersRaw = trustedSignersJson(signers)
  const trustedSignersSha256 = createHash('sha256').update(trustedSignersRaw).digest('hex')
  return { trustedSignersRaw, trustedSignersSha256 }
}

test('missing external receipts block every Full GA external claim', (t) => {
  const root = makeRoot(t)
  const result = verifyExternalGaEvidence({ repoRoot: root.repoRoot, sourceCommit, artifactEvidence, trustedSignersRaw: '[]', bundlePath: '' })
  assert.equal(result.ok, false)
  assert.equal(result.requiredClaims, 17)
  assert.equal(result.blockers.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
  assert.ok(result.blockers.every((blocker) => blocker.detail.includes('bundle is missing')))
})

test('valid role-authorized signed evidence verifies and binds the production artifact digest', (t) => {
  const root = makeRoot(t)
  const signers = makeSigners()
  makeBundle(root, signers)
  const result = verifyExternalGaEvidence({
    repoRoot: root.repoRoot,
    sourceCommit,
    artifactEvidence,
    ...trustOptions(signers),
    bundlePath: root.bundlePath,
  })
  assert.equal(result.ok, true, JSON.stringify(result.blockers))
  assert.equal(result.verifiedClaims.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
  assert.equal(result.blockers.length, 0)
  assert.match(result.bundleSha256, /^[a-f0-9]{64}$/)
  assert.equal(result.trustConfiguration.status, 'PIN_MATCHED')
  assert.equal(result.releaseAuthorization.status, 'REVIEW')
})

test('self-consistent signed claims without an externally supplied trust pin remain UNVERIFIED', (t) => {
  const root = makeRoot(t)
  const attackerSigners = makeSigners()
  makeBundle(root, attackerSigners)
  const result = verifyExternalGaEvidence({
    repoRoot: root.repoRoot,
    sourceCommit,
    artifactEvidence,
    trustedSignersRaw: trustedSignersJson(attackerSigners),
    bundlePath: root.bundlePath,
  })
  assert.equal(result.ok, false)
  assert.equal(result.trustConfiguration.status, 'UNVERIFIED')
  assert.equal(result.blockers.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
  assert.ok(result.blockers.every((blocker) => blocker.detail.includes('SHA-256 pin is missing')))
  assert.equal(result.releaseAuthorization.status, 'REVIEW')
})

test('replacing trusted signer keys and re-signing every claim fails the externally pinned signer hash', (t) => {
  const root = makeRoot(t)
  const trustedSigners = makeSigners()
  const trustPin = trustOptions(trustedSigners).trustedSignersSha256
  const attackerSigners = makeSigners()
  makeBundle(root, attackerSigners)
  const attackerConfig = trustedSignersJson(attackerSigners)
  const result = verifyExternalGaEvidence({
    repoRoot: root.repoRoot,
    sourceCommit,
    artifactEvidence,
    trustedSignersRaw: attackerConfig,
    trustedSignersSha256: trustPin,
    bundlePath: root.bundlePath,
  })
  assert.equal(result.ok, false)
  assert.equal(result.trustConfiguration.status, 'UNVERIFIED')
  assert.equal(result.trustConfiguration.sha256, createHash('sha256').update(attackerConfig).digest('hex'))
  assert.equal(result.blockers.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
  assert.ok(result.blockers.every((blocker) => blocker.detail.includes('does not match the protected pin')))
})

test('receipt bundle replacement between metadata check and open is rejected', (t) => {
  const root = makeRoot(t)
  const signers = makeSigners()
  makeBundle(root, signers)
  const preservedBundlePath = `${root.bundlePath}.preserved`
  const replacementBytes = Buffer.from('{"schemaVersion":"forged-after-path-check"}\n')
  const originalOpen = fsSync.openSync
  const observedOpenPaths = []
  let swapped = false
  fsSync.openSync = (file, ...args) => {
    observedOpenPaths.push(String(file))
    if (!swapped) {
      assert.equal(path.basename(String(file)).toLowerCase(), 'signed-receipts.json', `first opened file must be the external receipt bundle: ${String(file)}`)
      swapped = true
      renameSync(root.bundlePath, preservedBundlePath)
      writeFileSync(root.bundlePath, replacementBytes)
    }
    return originalOpen(file, ...args)
  }
  syncBuiltinESMExports()
  try {
    const result = verifyExternalGaEvidence({
      repoRoot: root.repoRoot,
      sourceCommit,
      artifactEvidence,
      ...trustOptions(signers),
      bundlePath: root.bundlePath,
    })
    assert.equal(swapped, true, `the fixture must replace the external bundle after lstat and before open; opened paths: ${observedOpenPaths.join(', ')}`)
    assert.equal(result.ok, false)
    assert.equal(result.bundleSha256, null)
    assert.equal(result.blockers.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
    assert.ok(result.blockers.every((blocker) => blocker.detail.includes('bundle is missing or unsafe')))
    assert.deepEqual(readFileSync(root.bundlePath), replacementBytes)
    assert.ok(readFileSync(preservedBundlePath).length > 0)
  } finally {
    fsSync.openSync = originalOpen
    syncBuiltinESMExports()
  }
})

test('receipt bundle inside the candidate repository is rejected to prevent commit-hash self-reference', (t) => {
  const root = makeRoot(t)
  const signers = makeSigners()
  makeBundle(root, signers)
  const insideRepoPath = path.join(root.repoRoot, 'docs', 'v2', 'acceptance', 'external-ga-evidence.json')
  mkdirSync(path.dirname(insideRepoPath), { recursive: true })
  writeFileSync(insideRepoPath, readFileSync(root.bundlePath))
  const result = verifyExternalGaEvidence({
    repoRoot: root.repoRoot,
    sourceCommit,
    artifactEvidence,
    ...trustOptions(signers),
    bundlePath: insideRepoPath,
  })
  assert.equal(result.ok, false)
  assert.equal(result.blockers.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
  assert.ok(result.blockers.every((blocker) => blocker.detail.includes('bundle is missing or unsafe')))
})

test('evidence hash tampering blocks only the affected signed claim', (t) => {
  const root = makeRoot(t)
  const signers = makeSigners()
  const bundle = makeBundle(root, signers)
  const claim = bundle.claims.find((item) => item.claimId === 'realEndpoint:ABU-311')
  writeFileSync(path.join(root.repoRoot, ...claim.evidencePath.split('/')), 'tampered evidence\n')
  const result = verifyExternalGaEvidence({ repoRoot: root.repoRoot, sourceCommit, artifactEvidence, ...trustOptions(signers), bundlePath: root.bundlePath })
  assert.equal(result.ok, false)
  assert.equal(result.blockers.length, 1)
  assert.equal(result.blockers[0].code, 'ABU-311_REAL_ENDPOINT_BLOCKED')
  assert.match(result.blockers[0].detail, /SHA-256 does not match/)
})

test('wrong signer role, wrong commit, and invalid production signature fail closed', (t) => {
  const root = makeRoot(t)
  const signers = makeSigners()
  makeBundle(root, signers, { wrongRoleClaimId: 'independentReview:ABU-409' })
  let result = verifyExternalGaEvidence({ repoRoot: root.repoRoot, sourceCommit, artifactEvidence, ...trustOptions(signers), bundlePath: root.bundlePath })
  let reviewBlocker = result.blockers.find((blocker) => blocker.code === 'ABU-409_INDEPENDENT_REVIEW_BLOCKED')
  assert.match(reviewBlocker.detail, /lacks the independent-reviewer role/)

  makeBundle(root, signers, { bundleCommit: 'f'.repeat(40) })
  result = verifyExternalGaEvidence({ repoRoot: root.repoRoot, sourceCommit, artifactEvidence, ...trustOptions(signers), bundlePath: root.bundlePath })
  assert.equal(result.blockers.length, REQUIRED_EXTERNAL_GA_CLAIMS.length)
  assert.ok(result.blockers.every((blocker) => blocker.detail.includes('not bound to the current commit')))

  makeBundle(root, signers, { badProductionSignatureClaimId: 'productionSignature:ABU-408' })
  result = verifyExternalGaEvidence({ repoRoot: root.repoRoot, sourceCommit, artifactEvidence, ...trustOptions(signers), bundlePath: root.bundlePath })
  const productionBlocker = result.blockers.find((blocker) => blocker.code === 'ABU-408_PRODUCTION_SIGNATURE_BLOCKED')
  assert.match(productionBlocker.detail, /subject does not match/)
})
