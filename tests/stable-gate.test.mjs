import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { gzipSync } from 'node:zlib'
import test from 'node:test'
import { evaluateStableGate, stableGateRequiredCiJobs, stableGateRequiredCheckAppId, stableGateRequiredPublisher, stableGateRequiredReleaseTag, stableGateRequiredRulesetName } from '../lib/release/stableGate.js'

const commit = 'a'.repeat(40)
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
function tarFiles(files) {
  const members = []
  for (const { path, bytes } of files) {
  const header = Buffer.alloc(512)
  header.write(path, 0, 100, 'utf8')
  header.write('0000644\0', 100, 8, 'ascii')
  header.write('0000000\0', 108, 8, 'ascii')
  header.write('0000000\0', 116, 8, 'ascii')
  header.write(`${bytes.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii')
  header.write('00000000000\0', 136, 12, 'ascii')
  header.fill(0x20, 148, 156)
  header[156] = '0'.charCodeAt(0)
  header.write('ustar\0', 257, 6, 'ascii')
  let sum = 0
  for (const byte of header) sum += byte
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
  const padding = Buffer.alloc((512 - (bytes.length % 512)) % 512)
    members.push(header, bytes, padding)
  }
  return Buffer.concat([...members, Buffer.alloc(1024)])
}

function tarFile(path, bytes) {
  return tarFiles([{ path, bytes }])
}

function fixture() {
  const content = Buffer.from('stable core bytes')
  const packageManifest = Buffer.from(JSON.stringify({ name: '@armorbreak/core', version: '2.2.0' }))
  const packageFile = Buffer.from('core source')
  const packageInventory = [
    { path: 'packages/core/index.js', size: packageFile.length, sha256: digest(packageFile) },
    { path: 'packages/core/package.json', size: packageManifest.length, sha256: digest(packageManifest) },
  ]
  const files = [
    { path: 'README.md', bytes: content },
    { path: 'packages/core/package.json', bytes: packageManifest },
    { path: 'packages/core/index.js', bytes: packageFile },
  ]
  const inventory = files.map(({ path, bytes }) => ({ path, size: bytes.length, sha256: digest(bytes) }))
  const artifactBytes = gzipSync(tarFiles(files), { mtime: 0 })
  const sbom = {
    bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: { component: { type: 'application', name: 'dsh-armorbreak', version: '2.2.0', hashes: [{ alg: 'SHA-256', content: digest(artifactBytes) }], properties: [{ name: 'armorbreak:included-file-inventory', value: JSON.stringify(inventory) }] } },
    components: [{
      type: 'library', name: '@armorbreak/core', version: '2.2.0',
      properties: [
        { name: 'armorbreak:package-manifest-path', value: 'packages/core/package.json' },
        { name: 'armorbreak:included-file-inventory', value: JSON.stringify(packageInventory) },
        { name: 'armorbreak:included-file-inventory-sha256', value: digest(Buffer.from(JSON.stringify(packageInventory))) },
      ],
    }],
  }
  const sbomBytes = Buffer.from(JSON.stringify(sbom))
  const buildManifest = {
    schemaVersion: 'armorbreak.release-build/v1', commit, version: '2.2.0', artifact: 'armorbreak-portable-2.2.0.tar.gz',
    bytes: artifactBytes.length, sha256: digest(artifactBytes), sbom: 'armorbreak-portable-2.2.0.tar.gz.sbom.cdx.json', sbomSha256: digest(sbomBytes), contentManifest: inventory,
  }
  const policy = {
    schemaVersion: 'armorbreak.v2.2-stable-scope/v1', channel: 'stable', packageVersion: '2.2.0', tag: 'v2.2.0', releaseName: 'Stable',
    assurance: {
      reviewType: 'AI_ASSISTED_SECURITY_REVIEW', independentHumanSecurityAuditRequired: false,
      aiReviewIsHumanCertification: false, fullHistoricalFourReviewerRepeatRequired: false,
      focusedCurrentShaImpactReviewRequired: true, maintainerRiskAcceptanceAllowed: true,
      unhandledP0P1OrHighBlocksStable: true,
    },
    experimentalProviderIntegrations: {
      status: 'EXPERIMENTAL', liveCertificationRequiredForStable: false,
      providers: { 'OpenAI-compatible': 'LIVE_UNVERIFIED', 'OpenAI Responses': 'LIVE_UNVERIFIED', 'Anthropic Messages': 'LIVE_UNVERIFIED', 'Gemini Native': 'LIVE_UNVERIFIED' },
    },
    provenance: { localEvidenceCanGrantPublishAuthority: false, acceptedMechanism: 'GitHub Actions OIDC/Sigstore build provenance', isSecurityCertification: false },
    legacyFullGa: {
      readinessFileSha256: digest(Buffer.from('legacy-full-ga-readiness')),
      legacyReleaseSnapshot: { sha256: digest(Buffer.from('historical-rc-readiness')) },
      stableDoesNotSatisfyFullGa: true, mustRemainGaReadyFalseWhenBlockersRemain: true,
      gate: 'node scripts/v2/v2-readiness.mjs --require-ga --no-waivers',
    },
    securityReviewEvidence: {
      exactSourceCommitRequired: true, toolRunsRequireSha256VerifiedEvidenceIds: true,
      raceTestsRequired: ['windows', 'linux'], codeqlAlertsMustAllBeTriaged: true,
      severeFindingClosuresRequireEvidence: true, falsePositiveRequiresRationaleAndEvidence: true,
      maintainerRiskAcceptanceSeverities: ['LOW', 'MEDIUM', 'INFO'],
      riskAcceptanceOwner: { login: 'LYL-Z', githubUserId: 250811935, minimumRationaleCharacters: 20 },
    },
    stableGate: {
      createsRelease: false,
      requiresLiveGitHubMainProtection: true,
      requiredStatusChecksMustBeFromGitHubActionsAppId: stableGateRequiredCheckAppId,
      requiredCiJobs: [...stableGateRequiredCiJobs],
      requiresReleaseTagRuleset: {
        name: stableGateRequiredRulesetName,
        tag: stableGateRequiredReleaseTag,
        allowedPublisher: { login: stableGateRequiredPublisher.login, githubUserId: stableGateRequiredPublisher.id },
      },
    },
  }
  const securityReview = {
    schemaVersion: 'armorbreak.v2.2-stable-security-review/v1', sourceCommit: commit, overallVerdict: 'PASS', reviewType: 'AI_ASSISTED_SECURITY_REVIEW',
    toolRuns: {
      semgrep: { status: 'PASS', sourceCommit: commit, exitCode: 0, findingsCount: 0, evidenceIds: ['semgrep'] },
      codeql: { status: 'REVIEWED', sourceCommit: commit, alertCount: 2, triagedAlertCount: 2, evidenceIds: ['codeql'] },
      trivy: { status: 'PASS', sourceCommit: commit, artifactSha256: digest(artifactBytes), findingsCount: 0, evidenceIds: ['trivy'] },
    },
    raceTests: {
      windows: { status: 'PASS', sourceCommit: commit, evidenceIds: ['windows-race'] },
      linux: { status: 'PASS', sourceCommit: commit, evidenceIds: ['linux-race'] },
    },
    releaseTrust: { status: 'PASS', sourceCommit: commit, localFabricationRejected: true, githubWriteRequired: true, evidenceIds: ['release-trust'] },
    findings: [
      { id: 'AB22-R-001', severity: 'HIGH', disposition: 'FIXED', evidenceIds: ['linux-race'] },
      { id: 'CODEQL-FS-RACE', severity: 'HIGH', disposition: 'MITIGATED', evidenceIds: ['codeql'] },
    ],
    evidence: ['semgrep', 'codeql', 'trivy', 'windows-race', 'linux-race', 'release-trust'].map((id, index) => ({
      id, path: `.runtime/stable-release/${id}.json`, sha256: String(index + 1).repeat(64), verified: true,
    })),
  }
  const ciRun = {
    workflow: 'CI', event: 'push', branch: 'main', conclusion: 'success', headSha: commit,
    jobs: stableGateRequiredCiJobs.map((name) => ({ name, conclusion: 'success' })),
  }
  const attestationRun = { workflow: 'Release attestation', event: 'push', branch: 'main', conclusion: 'success', headSha: commit }
  const repositoryProtection = {
    main: {
      requiredStatusChecks: {
        strict: true,
        contexts: [...stableGateRequiredCiJobs],
        checks: stableGateRequiredCiJobs.map((context) => ({ context, app_id: stableGateRequiredCheckAppId })),
      },
      enforceAdmins: true,
    },
    tagRulesets: [{
      name: stableGateRequiredRulesetName,
      target: 'tag',
      enforcement: 'active',
      conditions: { ref_name: { include: [stableGateRequiredReleaseTag] } },
      rules: ['creation', 'update', 'deletion'].map((type) => ({ type })),
      bypass_actors: [{ actor_type: 'User', actor_id: stableGateRequiredPublisher.id, bypass_mode: 'always' }],
    }],
  }
  const input = {
    policy, packageManifest: { version: '2.2.0' }, packageLock: { version: '2.2.0', packages: { '': { version: '2.2.0' } } },
    legacyReadiness: { gaReady: false, gaBlockers: [{ code: 'legacy' }] },
    legacyReadinessBytes: Buffer.from('legacy-full-ga-readiness'),
    legacyReleaseReadinessBytes: Buffer.from('historical-rc-readiness'),
    legacyScope: { v22FullGa: { status: 'BLOCKED_EXTERNAL' } },
    sourceCommit: commit, branchName: 'main', remoteMainCommit: commit, trackedWorktreeClean: true, pr18Merged: true, pr17Merged: true,
    ciRun, attestationRun, repositoryProtection,
    publisherIdentity: { ...stableGateRequiredPublisher, repositoryAdmin: true },
    attestation: { ok: true, code: 'ATTESTATION_VERIFIED', sourceCommit: commit, artifact: buildManifest.artifact, sha256: buildManifest.sha256, sourceRef: 'refs/heads/main' },
    artifactBytes, artifactName: buildManifest.artifact, sbomBytes, sbomName: buildManifest.sbom, buildManifest, securityReview,
  }
  return input
}

test('Stable Gate accepts only exact main CI, verified provenance, and matching archive/SBOM inventories', () => {
  const report = evaluateStableGate(fixture())
  assert.equal(report.status, 'ELIGIBLE_FOR_RELEASE')
  assert.equal(report.fullGaReady, false)
  assert.equal(report.releaseAuthorization, 'EXTERNAL_GITHUB_WRITE_REQUIRED')
})

test('local signed flags do not replace cryptographic GitHub provenance', () => {
  const input = fixture()
  input.attestation = { ok: false, code: 'ATTESTATION_VERIFICATION_FAILED', sourceCommit: commit, artifact: input.artifactName, sha256: digest(input.artifactBytes), signed: true, sourceRef: 'refs/heads/main' }
  const report = evaluateStableGate(input)
  assert.equal(report.releasable, false)
  assert.ok(report.blockers.some((item) => item.id === 'GITHUB_OIDC_PROVENANCE'))
})

test('Stable Gate blocks a wrong source SHA, missing required CI job, or stale attestation run', () => {
  const input = fixture()
  input.ciRun.jobs.pop()
  input.attestationRun.headSha = 'c'.repeat(40)
  const report = evaluateStableGate(input)
  assert.ok(report.blockers.some((item) => item.id === 'EXACT_SHA_GITHUB_CI'))
  assert.ok(report.blockers.some((item) => item.id === 'EXACT_SHA_ATTESTATION_RUN'))
})

test('Stable Gate blocks modified archives, SBOM inventories, and an opened severe finding', () => {
  const input = fixture()
  input.artifactBytes = Buffer.from(input.artifactBytes)
  input.artifactBytes[input.artifactBytes.length - 10] ^= 0x01
  input.securityReview.findings.push({ id: 'NEW-HIGH', severity: 'HIGH', disposition: 'OPEN' })
  const report = evaluateStableGate(input)
  assert.ok(report.blockers.some((item) => item.id === 'ARTIFACT_SBOM_CONTENT'))
  assert.ok(report.blockers.some((item) => item.id === 'CURRENT_SHA_SECURITY_REVIEW'))
})

test('Stable Gate rejects omitted, forged, or incomplete SBOM package components', () => {
  const omitted = fixture()
  omitted.sbomBytes = Buffer.from(JSON.stringify({ ...JSON.parse(omitted.sbomBytes), components: [] }))
  omitted.buildManifest.sbomSha256 = digest(omitted.sbomBytes)
  assert.ok(evaluateStableGate(omitted).blockers.some((item) => item.id === 'ARTIFACT_SBOM_CONTENT'))

  const forged = fixture()
  const sbom = JSON.parse(forged.sbomBytes)
  sbom.components[0].name = '@attacker/fake'
  forged.sbomBytes = Buffer.from(JSON.stringify(sbom))
  forged.buildManifest.sbomSha256 = digest(forged.sbomBytes)
  assert.ok(evaluateStableGate(forged).blockers.some((item) => item.id === 'ARTIFACT_SBOM_CONTENT'))

  const incomplete = fixture()
  const incompleteSbom = JSON.parse(incomplete.sbomBytes)
  incompleteSbom.components[0].properties.find((item) => item.name === 'armorbreak:included-file-inventory').value = '[]'
  incompleteSbom.components[0].properties.find((item) => item.name === 'armorbreak:included-file-inventory-sha256').value = digest(Buffer.from('[]'))
  incomplete.sbomBytes = Buffer.from(JSON.stringify(incompleteSbom))
  incomplete.buildManifest.sbomSha256 = digest(incomplete.sbomBytes)
  assert.ok(evaluateStableGate(incomplete).blockers.some((item) => item.id === 'ARTIFACT_SBOM_CONTENT'))
})

test('Stable Gate refuses to rewrite legacy Full GA as passed', () => {
  const input = fixture()
  input.legacyReadiness.gaReady = true
  const report = evaluateStableGate(input)
  assert.equal(report.releasable, false)
  assert.ok(report.blockers.some((item) => item.id === 'LEGACY_FULL_GA_PRESERVED'))
})

test('Stable Gate verifies historical Full GA and RC readiness bytes remain unchanged', () => {
  const input = fixture()
  input.legacyReadinessBytes = Buffer.from('forged-full-ga-readiness')
  input.legacyReleaseReadinessBytes = Buffer.from('rewritten-rc-readiness')
  const report = evaluateStableGate(input)
  assert.equal(report.releasable, false)
  assert.ok(report.blockers.some((item) => item.id === 'LEGACY_FULL_GA_PRESERVED'))
})

test('Stable Gate blocks missing GitHub protections and untrusted release publishers', () => {
  const input = fixture()
  input.repositoryProtection.main.requiredStatusChecks.contexts.pop()
  input.repositoryProtection.tagRulesets[0].bypass_actors[0].actor_id = 42
  input.publisherIdentity.repositoryAdmin = false
  const report = evaluateStableGate(input)
  assert.ok(report.blockers.some((item) => item.id === 'PROTECTED_GITHUB_RELEASE_AUTHORITY'))
  const wrongApp = fixture()
  wrongApp.repositoryProtection.main.requiredStatusChecks.checks[0].app_id = -1
  assert.ok(evaluateStableGate(wrongApp).blockers.some((item) => item.id === 'PROTECTED_GITHUB_RELEASE_AUTHORITY'))
})

test('Stable Gate policy cannot omit its protected publisher and exact tag ruleset requirements', () => {
  const input = fixture()
  input.policy.stableGate.requiresLiveGitHubMainProtection = false
  const report = evaluateStableGate(input)
  assert.ok(report.blockers.some((item) => item.id === 'VERSIONED_STABLE_POLICY'))
  const providerPolicy = fixture()
  providerPolicy.policy.experimentalProviderIntegrations.providers['Gemini Native'] = 'LIVE_CERTIFIED'
  assert.ok(evaluateStableGate(providerPolicy).blockers.some((item) => item.id === 'VERSIONED_STABLE_POLICY'))
  const evidencePolicy = fixture()
  evidencePolicy.policy.securityReviewEvidence.codeqlAlertsMustAllBeTriaged = false
  assert.ok(evaluateStableGate(evidencePolicy).blockers.some((item) => item.id === 'VERSIONED_STABLE_POLICY'))
})

test('current-SHA scan results and finding closures require exact, verified evidence references', () => {
  const missingScanEvidence = fixture()
  missingScanEvidence.securityReview.toolRuns.codeql.triagedAlertCount = 1
  assert.ok(evaluateStableGate(missingScanEvidence).blockers.some((item) => item.id === 'CURRENT_SHA_SECURITY_REVIEW'))

  const unverifiedFinding = fixture()
  unverifiedFinding.securityReview.evidence[4].verified = false
  assert.ok(evaluateStableGate(unverifiedFinding).blockers.some((item) => item.id === 'CURRENT_SHA_SECURITY_REVIEW'))

  const falsePositive = fixture()
  falsePositive.securityReview.findings.push({
    id: 'CODEQL-HIGH-FP', severity: 'HIGH', disposition: 'FALSE_POSITIVE',
    rationale: 'The reported path is pinned to the opened file identity before the sensitive operation.',
    evidenceIds: ['codeql', 'linux-race'],
  })
  assert.equal(evaluateStableGate(falsePositive).releasable, true)

  const unsupportedFalsePositive = fixture()
  unsupportedFalsePositive.securityReview.findings.push({
    id: 'CODEQL-HIGH-FP', severity: 'HIGH', disposition: 'FALSE_POSITIVE',
    rationale: 'The report is believed to be a false positive, but has no evidence reference.',
  })
  assert.ok(evaluateStableGate(unsupportedFalsePositive).blockers.some((item) => item.id === 'CURRENT_SHA_SECURITY_REVIEW'))
})

test('maintainer risk acceptance is scoped to non-severe findings and must cite evidence', () => {
  const acceptedInfo = fixture()
  acceptedInfo.securityReview.findings.push({ id: 'INFO-1', severity: 'INFO', disposition: 'RISK_ACCEPTED' })
  acceptedInfo.securityReview.maintainerRiskAcceptances = [{
    findingId: 'INFO-1', acceptedBy: 'LYL-Z', rationale: 'The read-only loopback surface has no credentials or write capability.',
    evidenceIds: ['release-trust'],
  }]
  assert.equal(evaluateStableGate(acceptedInfo).releasable, true)

  const acceptedHigh = fixture()
  acceptedHigh.securityReview.findings.push({ id: 'HIGH-1', severity: 'HIGH', disposition: 'RISK_ACCEPTED' })
  acceptedHigh.securityReview.maintainerRiskAcceptances = [{
    findingId: 'HIGH-1', acceptedBy: 'LYL-Z', rationale: 'The owner accepted the remaining risk after review.', evidenceIds: ['release-trust'],
  }]
  assert.ok(evaluateStableGate(acceptedHigh).blockers.some((item) => item.id === 'CURRENT_SHA_SECURITY_REVIEW'))
})

test('security review must declare the exact source SHA instead of inheriting it from the runner', () => {
  const input = fixture()
  delete input.securityReview.sourceCommit
  const report = evaluateStableGate(input)
  assert.ok(report.blockers.some((item) => item.id === 'CURRENT_SHA_SECURITY_REVIEW'))
})
