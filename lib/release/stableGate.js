import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'

const SHA256_RE = /^[a-f0-9]{64}$/i
const COMMIT_RE = /^[a-f0-9]{40}$/i
const REQUIRED_CI_JOBS = Object.freeze([
  'Node 24 on ubuntu-latest',
  'Node 24 on windows-latest',
  'L0 offline boundary (static gate)',
  'L1 Docker integration (real daemon)',
  'Release evidence checks (commit-bound)',
])
const REQUIRED_RELEASE_TAG = 'refs/tags/v2.2.0'
const REQUIRED_RULESET_NAME = 'ArmorBreak V2.2 Stable release tag protection'
const REQUIRED_PUBLISHER = Object.freeze({ login: 'LYL-Z', id: 250811935 })
const REQUIRED_CHECK_APP_ID = 15368
const SEVERE = new Set(['P0', 'P1', 'CRITICAL', 'HIGH'])
const CLOSED_SEVERE = new Set(['FIXED', 'MITIGATED'])

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const within = (actual, expected) => String(actual ?? '').toLowerCase() === String(expected ?? '').toLowerCase()

function fail(code, detail) { return { code, detail } }

function parseOctal(bytes, label) {
  const raw = bytes.toString('ascii').replace(/\0.*$/s, '').trim()
  if (!/^[0-7]+$/.test(raw)) throw new Error(`invalid tar ${label}`)
  const value = Number.parseInt(raw, 8)
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`invalid tar ${label}`)
  return value
}

function archiveInventory(archiveBytes) {
  const tar = gunzipSync(archiveBytes, { maxOutputLength: 256 * 1024 * 1024 })
  const files = new Map()
  const packageManifests = new Map()
  let offset = 0
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '')
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '')
    const path = prefix ? `${prefix}/${name}` : name
    const size = parseOctal(header.subarray(124, 136), 'member size')
    const type = String.fromCharCode(header[156])
    if (!path || path.startsWith('/') || path.includes('\\') || path.split('/').some((part) => !part || part === '.' || part === '..')) {
      throw new Error('unsafe or non-canonical archive path')
    }
    if (type !== '0' && type !== '\0') throw new Error(`archive contains unsupported member type ${JSON.stringify(type)}: ${path}`)
    const dataStart = offset + 512
    const dataEnd = dataStart + size
    if (dataEnd > tar.length || files.has(path)) throw new Error(`invalid or duplicate archive member: ${path}`)
    const content = tar.subarray(dataStart, dataEnd)
    files.set(path, { path, size, sha256: sha256(content) })
    if (/^.+\/package\.json$/.test(path)) {
      let manifest
      try { manifest = JSON.parse(content.toString('utf8')) } catch { throw new Error(`invalid package manifest in release archive: ${path}`) }
      if (typeof manifest?.name !== 'string' || typeof manifest?.version !== 'string') {
        throw new Error(`package manifest lacks name/version in release archive: ${path}`)
      }
      packageManifests.set(path, { name: manifest.name, version: manifest.version })
    }
    offset = dataStart + Math.ceil(size / 512) * 512
  }
  if (files.size === 0) throw new Error('release archive is empty')
  return {
    files: [...files.values()].sort((left, right) => left.path.localeCompare(right.path)),
    packageManifests,
  }
}

function rootInventoryFromSbom(sbom) {
  const properties = sbom?.metadata?.component?.properties
  const property = Array.isArray(properties) ? properties.find((item) => item?.name === 'armorbreak:included-file-inventory') : null
  if (!property || typeof property.value !== 'string') throw new Error('SBOM does not contain the root included-file inventory')
  const inventory = JSON.parse(property.value)
  if (!Array.isArray(inventory)) throw new Error('SBOM root inventory is not an array')
  return inventory
}

function compareInventory(actual, expected) {
  if (!Array.isArray(expected) || actual.length !== expected.length) return false
  const byPath = new Map(expected.map((entry) => [entry.path, entry]))
  return actual.every((entry) => {
    const candidate = byPath.get(entry.path)
    return candidate && candidate.size === entry.size && within(candidate.sha256, entry.sha256)
  })
}

function verifyComponentInventories(sbom, rootInventory, packageManifests) {
  if (!Array.isArray(sbom?.components) || packageManifests.size === 0 || sbom.components.length !== packageManifests.size) return false
  const seenManifestPaths = new Set()
  const componentsOk = sbom.components.every((component) => {
    const properties = component?.properties
    const inventoryProperty = Array.isArray(properties) ? properties.find((item) => item?.name === 'armorbreak:included-file-inventory') : null
    const hashProperty = Array.isArray(properties) ? properties.find((item) => item?.name === 'armorbreak:included-file-inventory-sha256') : null
    if (!inventoryProperty || typeof inventoryProperty.value !== 'string' || !hashProperty) return false
    let inventory
    try { inventory = JSON.parse(inventoryProperty.value) } catch { return false }
    if (!Array.isArray(inventory) || !within(sha256(Buffer.from(JSON.stringify(inventory))), hashProperty.value)) return false
    const manifestPath = properties.find((item) => item?.name === 'armorbreak:package-manifest-path')?.value
    const actualManifest = packageManifests.get(manifestPath)
    if (typeof manifestPath !== 'string' || !actualManifest || seenManifestPaths.has(manifestPath) ||
        component.name !== actualManifest.name || component.version !== actualManifest.version ||
        !rootInventory.some((entry) => entry.path === manifestPath)) return false
    seenManifestPaths.add(manifestPath)
    const prefix = manifestPath.slice(0, -'package.json'.length)
    const expected = rootInventory.filter((entry) => entry.path.startsWith(prefix))
    return compareInventory(expected, inventory)
  })
  return componentsOk && seenManifestPaths.size === packageManifests.size
}

function add(checks, id, ok, detail) {
  checks.push({ id, status: ok ? 'PASS' : 'BLOCKED', detail })
}

function hasEvidenceIds(ids, evidenceById) {
  return Array.isArray(ids) && ids.length > 0 && ids.every((id) => typeof id === 'string' && evidenceById.has(id))
}

/** Pure, fail-closed evaluation. The CLI obtains CI and provenance from GitHub itself. */
export function evaluateStableGate({
  policy,
  packageManifest,
  packageLock,
  legacyReadiness,
  legacyScope,
  sourceCommit,
  branchName,
  remoteMainCommit,
  trackedWorktreeClean,
  pr18Merged,
  pr17Merged,
  ciRun,
  attestationRun,
  repositoryProtection,
  publisherIdentity,
  attestation,
  artifactBytes,
  artifactName,
  sbomBytes,
  sbomName,
  buildManifest,
  securityReview,
}) {
  const checks = []
  const block = (code, detail) => checks.push({ id: code, status: 'BLOCKED', detail })
  const policyOk = policy?.schemaVersion === 'armorbreak.v2.2-stable-scope/v1' &&
    policy?.channel === 'stable' && policy?.packageVersion === '2.2.0' && policy?.tag === 'v2.2.0' &&
    policy?.assurance?.reviewType === 'AI_ASSISTED_SECURITY_REVIEW' &&
    policy?.assurance?.independentHumanSecurityAuditRequired === false &&
    policy?.assurance?.aiReviewIsHumanCertification === false &&
    policy?.assurance?.fullHistoricalFourReviewerRepeatRequired === false &&
    policy?.assurance?.focusedCurrentShaImpactReviewRequired === true &&
    policy?.assurance?.maintainerRiskAcceptanceAllowed === true &&
    policy?.assurance?.unhandledP0P1OrHighBlocksStable === true &&
    policy?.experimentalProviderIntegrations?.status === 'EXPERIMENTAL' &&
    policy?.experimentalProviderIntegrations?.liveCertificationRequiredForStable === false &&
    ['OpenAI-compatible', 'OpenAI Responses', 'Anthropic Messages', 'Gemini Native'].every((provider) =>
      policy?.experimentalProviderIntegrations?.providers?.[provider] === 'LIVE_UNVERIFIED') &&
    policy?.provenance?.localEvidenceCanGrantPublishAuthority === false &&
    policy?.provenance?.acceptedMechanism === 'GitHub Actions OIDC/Sigstore build provenance' &&
    policy?.provenance?.isSecurityCertification === false &&
    policy?.legacyFullGa?.stableDoesNotSatisfyFullGa === true &&
    policy?.legacyFullGa?.mustRemainGaReadyFalseWhenBlockersRemain === true &&
    policy?.legacyFullGa?.gate === 'node scripts/v2/v2-readiness.mjs --require-ga --no-waivers' &&
    policy?.securityReviewEvidence?.exactSourceCommitRequired === true &&
    policy?.securityReviewEvidence?.toolRunsRequireSha256VerifiedEvidenceIds === true &&
    ['windows', 'linux'].every((platform) => policy.securityReviewEvidence.raceTestsRequired?.includes(platform)) &&
    policy?.securityReviewEvidence?.codeqlAlertsMustAllBeTriaged === true &&
    policy?.securityReviewEvidence?.severeFindingClosuresRequireEvidence === true &&
    policy?.securityReviewEvidence?.falsePositiveRequiresRationaleAndEvidence === true &&
    ['LOW', 'MEDIUM', 'INFO'].every((severity) => policy.securityReviewEvidence.maintainerRiskAcceptanceSeverities?.includes(severity)) &&
    policy?.securityReviewEvidence?.riskAcceptanceOwner?.login === REQUIRED_PUBLISHER.login &&
    Number(policy?.securityReviewEvidence?.riskAcceptanceOwner?.githubUserId) === REQUIRED_PUBLISHER.id &&
    policy?.securityReviewEvidence?.riskAcceptanceOwner?.minimumRationaleCharacters === 20 &&
    policy?.stableGate?.createsRelease === false &&
    policy?.stableGate?.requiresLiveGitHubMainProtection === true &&
    policy?.stableGate?.requiredStatusChecksMustBeFromGitHubActionsAppId === REQUIRED_CHECK_APP_ID &&
    Array.isArray(policy?.stableGate?.requiredCiJobs) &&
    REQUIRED_CI_JOBS.every((job) => policy.stableGate.requiredCiJobs.includes(job)) &&
    policy?.stableGate?.requiresReleaseTagRuleset?.name === REQUIRED_RULESET_NAME &&
    policy?.stableGate?.requiresReleaseTagRuleset?.tag === REQUIRED_RELEASE_TAG &&
    policy?.stableGate?.requiresReleaseTagRuleset?.allowedPublisher?.login === REQUIRED_PUBLISHER.login &&
    Number(policy?.stableGate?.requiresReleaseTagRuleset?.allowedPublisher?.githubUserId) === REQUIRED_PUBLISHER.id
  add(checks, 'VERSIONED_STABLE_POLICY', policyOk, 'versioned Stable scope and non-authorizing local gate')

  const sourceOk = COMMIT_RE.test(sourceCommit ?? '') && branchName === 'main' &&
    within(remoteMainCommit, sourceCommit) && trackedWorktreeClean === true
  add(checks, 'EXACT_CLEAN_MAIN_SOURCE', sourceOk, 'HEAD equals live origin/main on a clean tracked worktree')
  add(checks, 'PR18_MERGED', pr18Merged === true, 'security remediation PR is merged')
  add(checks, 'PR17_MERGED', pr17Merged === true, 'README V3 update is merged')

  const requiredContexts = repositoryProtection?.main?.requiredStatusChecks?.contexts
  const requiredChecks = repositoryProtection?.main?.requiredStatusChecks?.checks
  const mainProtectionOk = repositoryProtection?.main?.requiredStatusChecks?.strict === true &&
    repositoryProtection?.main?.enforceAdmins === true && Array.isArray(requiredContexts) &&
    REQUIRED_CI_JOBS.every((job) => requiredContexts.includes(job)) && Array.isArray(requiredChecks) &&
    REQUIRED_CI_JOBS.every((job) => requiredChecks.some((check) => check.context === job && Number(check.app_id) === REQUIRED_CHECK_APP_ID))
  const tagRuleset = repositoryProtection?.tagRulesets?.find((ruleset) => ruleset?.name === REQUIRED_RULESET_NAME)
  const tagInclude = tagRuleset?.conditions?.ref_name?.include
  const rules = Array.isArray(tagRuleset?.rules) ? tagRuleset.rules.map((rule) => rule.type) : []
  const bypassActors = tagRuleset?.bypass_actors
  const tagProtectionOk = tagRuleset?.target === 'tag' && tagRuleset?.enforcement === 'active' &&
    Array.isArray(tagInclude) && tagInclude.length === 1 && tagInclude[0] === REQUIRED_RELEASE_TAG &&
    ['creation', 'update', 'deletion'].every((rule) => rules.includes(rule)) && Array.isArray(bypassActors) &&
    bypassActors.length === 1 && bypassActors[0]?.actor_type === 'User' &&
    Number(bypassActors[0]?.actor_id) === REQUIRED_PUBLISHER.id && bypassActors[0]?.bypass_mode === 'always'
  const publisherOk = publisherIdentity?.login === REQUIRED_PUBLISHER.login &&
    Number(publisherIdentity?.id) === REQUIRED_PUBLISHER.id && publisherIdentity?.repositoryAdmin === true
  add(checks, 'PROTECTED_GITHUB_RELEASE_AUTHORITY', mainProtectionOk && tagProtectionOk && publisherOk,
    `main requires all ${REQUIRED_CI_JOBS.length} exact CI contexts with admin enforcement; only authenticated ${REQUIRED_PUBLISHER.login} can create or mutate ${REQUIRED_RELEASE_TAG}`)

  const packageOk = packageManifest?.version === policy?.packageVersion &&
    packageLock?.version === policy?.packageVersion && packageLock?.packages?.['']?.version === policy?.packageVersion
  add(checks, 'PACKAGE_VERSION', packageOk, 'package.json and package-lock use the Stable package version')

  const legacyOk = legacyReadiness?.gaReady === false && Array.isArray(legacyReadiness?.gaBlockers) &&
    legacyReadiness.gaBlockers.length > 0 && legacyScope?.v22FullGa?.status === 'BLOCKED_EXTERNAL'
  add(checks, 'LEGACY_FULL_GA_PRESERVED', legacyOk, 'historical Full GA remains blocked and is not rewritten')

  const ciJobs = new Map((Array.isArray(ciRun?.jobs) ? ciRun.jobs : []).map((job) => [job.name, job.conclusion ?? job.status]))
  const requiredJobsPass = REQUIRED_CI_JOBS.every((job) => ciJobs.get(job) === 'success')
  const ciOk = ciRun?.workflow === 'CI' && ciRun?.event === 'push' && ciRun?.branch === 'main' &&
    ciRun?.conclusion === 'success' && within(ciRun?.headSha, sourceCommit) && requiredJobsPass
  add(checks, 'EXACT_SHA_GITHUB_CI', ciOk, 'main push CI and all required Windows/Linux/Docker/L0/evidence jobs succeeded on exact SHA')

  const attRunOk = attestationRun?.workflow === 'Release attestation' && attestationRun?.event === 'push' &&
    attestationRun?.branch === 'main' && attestationRun?.conclusion === 'success' && within(attestationRun?.headSha, sourceCommit)
  add(checks, 'EXACT_SHA_ATTESTATION_RUN', attRunOk, 'main attestation workflow succeeded on exact source SHA')

  const actualArtifactSha = artifactBytes ? sha256(artifactBytes) : null
  const actualSbomSha = sbomBytes ? sha256(sbomBytes) : null
  let inventoryOk = false
  let inventoryDetail = 'artifact/SBOM/build inventory could not be verified'
  try {
    const archive = archiveInventory(artifactBytes)
    const actualInventory = archive.files
    const rootInventory = rootInventoryFromSbom(JSON.parse(sbomBytes.toString('utf8')))
    const manifestInventory = buildManifest?.contentManifest
    inventoryOk = compareInventory(actualInventory, rootInventory) && compareInventory(actualInventory, manifestInventory) &&
      verifyComponentInventories(JSON.parse(sbomBytes.toString('utf8')), rootInventory, archive.packageManifests)
    inventoryDetail = `archive=${actualInventory.length} members; root SBOM and component inventories ${inventoryOk ? 'match' : 'do not match'}`
  } catch (error) { inventoryDetail = error.message }
  const buildOk = buildManifest?.schemaVersion === 'armorbreak.release-build/v1' &&
    within(buildManifest?.commit, sourceCommit) && buildManifest?.version === policy?.packageVersion &&
    buildManifest?.artifact === artifactName && within(buildManifest?.sha256, actualArtifactSha) &&
    buildManifest?.bytes === artifactBytes?.length && buildManifest?.sbom === sbomName &&
    within(buildManifest?.sbomSha256, actualSbomSha) && inventoryOk
  add(checks, 'ARTIFACT_SBOM_CONTENT', buildOk, `${inventoryDetail}; artifact and SBOM digests match the exact build manifest`)

  const attestationOk = attestation?.ok === true && attestation?.code === 'ATTESTATION_VERIFIED' &&
    within(attestation?.sourceCommit, sourceCommit) && attestation?.artifact === artifactName &&
    within(attestation?.sha256, actualArtifactSha) && attestation?.sourceRef === 'refs/heads/main'
  add(checks, 'GITHUB_OIDC_PROVENANCE', attestationOk, 'GitHub cryptographic verification binds expected main workflow, source SHA, and artifact SHA-256')

  const reviewFindings = Array.isArray(securityReview?.findings) ? securityReview.findings : []
  const evidence = Array.isArray(securityReview?.evidence) ? securityReview.evidence : []
  const reviewEvidenceOk = evidence.length > 0 && evidence.every((item) => typeof item?.id === 'string' && item.id.length > 0 &&
    typeof item?.path === 'string' && SHA256_RE.test(item?.sha256 ?? '') && item.verified === true)
  const evidenceById = new Map(evidence.filter((item) => item?.verified === true && SHA256_RE.test(item?.sha256 ?? '')).map((item) => [item.id, item]))
  const maintainerAcceptances = Array.isArray(securityReview?.maintainerRiskAcceptances) ? securityReview.maintainerRiskAcceptances : []
  const riskAcceptancePolicy = policy?.securityReviewEvidence?.riskAcceptanceOwner
  const hasRiskAcceptance = (finding) => maintainerAcceptances.some((acceptance) => acceptance?.findingId === finding.id &&
    acceptance?.acceptedBy === riskAcceptancePolicy?.login && typeof acceptance?.rationale === 'string' &&
    acceptance.rationale.trim().length >= Number(riskAcceptancePolicy?.minimumRationaleCharacters) &&
    hasEvidenceIds(acceptance.evidenceIds, evidenceById))
  const dispositionIsDocumented = (finding) => {
    const disposition = String(finding?.disposition ?? '').toUpperCase()
    if (CLOSED_SEVERE.has(disposition)) return hasEvidenceIds(finding.evidenceIds, evidenceById)
    if (disposition === 'FALSE_POSITIVE') return typeof finding.rationale === 'string' && finding.rationale.trim().length >= 20 &&
      hasEvidenceIds(finding.evidenceIds, evidenceById)
    return policy?.securityReviewEvidence?.maintainerRiskAcceptanceSeverities?.includes(String(finding?.severity ?? '').toUpperCase()) &&
      disposition === 'RISK_ACCEPTED' && hasRiskAcceptance(finding)
  }
  const openSevere = reviewFindings.filter((finding) => SEVERE.has(String(finding?.severity ?? '').toUpperCase()) &&
    !dispositionIsDocumented(finding))
  const undocumentedFindings = reviewFindings.filter((finding) => !dispositionIsDocumented(finding))
  const semgrepOk = securityReview?.toolRuns?.semgrep?.status === 'PASS' &&
    within(securityReview?.toolRuns?.semgrep?.sourceCommit, sourceCommit) && securityReview.toolRuns.semgrep.exitCode === 0 &&
    Number.isInteger(securityReview.toolRuns.semgrep.findingsCount) && securityReview.toolRuns.semgrep.findingsCount >= 0 &&
    hasEvidenceIds(securityReview.toolRuns.semgrep.evidenceIds, evidenceById)
  const codeqlOk = securityReview?.toolRuns?.codeql?.status === 'REVIEWED' &&
    within(securityReview?.toolRuns?.codeql?.sourceCommit, sourceCommit) &&
    Number.isInteger(securityReview.toolRuns.codeql.alertCount) && securityReview.toolRuns.codeql.alertCount >= 0 &&
    securityReview.toolRuns.codeql.triagedAlertCount === securityReview.toolRuns.codeql.alertCount &&
    hasEvidenceIds(securityReview.toolRuns.codeql.evidenceIds, evidenceById)
  const trivyOk = securityReview?.toolRuns?.trivy?.status === 'PASS' &&
    within(securityReview?.toolRuns?.trivy?.sourceCommit, sourceCommit) && within(securityReview.toolRuns.trivy.artifactSha256, actualArtifactSha) &&
    Number.isInteger(securityReview.toolRuns.trivy.findingsCount) && securityReview.toolRuns.trivy.findingsCount >= 0 &&
    hasEvidenceIds(securityReview.toolRuns.trivy.evidenceIds, evidenceById)
  const windowsRaceOk = securityReview?.raceTests?.windows?.status === 'PASS' &&
    within(securityReview.raceTests.windows.sourceCommit, sourceCommit) && hasEvidenceIds(securityReview.raceTests.windows.evidenceIds, evidenceById)
  const linuxRaceOk = securityReview?.raceTests?.linux?.status === 'PASS' &&
    within(securityReview.raceTests.linux.sourceCommit, sourceCommit) && hasEvidenceIds(securityReview.raceTests.linux.evidenceIds, evidenceById)
  const releaseTrustOk = securityReview?.releaseTrust?.status === 'PASS' && within(securityReview.releaseTrust.sourceCommit, sourceCommit) &&
    securityReview.releaseTrust.localFabricationRejected === true && securityReview.releaseTrust.githubWriteRequired === true &&
    hasEvidenceIds(securityReview.releaseTrust.evidenceIds, evidenceById)
  const reviewOk = securityReview?.schemaVersion === 'armorbreak.v2.2-stable-security-review/v1' &&
    within(securityReview?.sourceCommit, sourceCommit) && securityReview?.overallVerdict === 'PASS' &&
    securityReview?.reviewType === 'AI_ASSISTED_SECURITY_REVIEW' && semgrepOk && codeqlOk && trivyOk && windowsRaceOk && linuxRaceOk && releaseTrustOk &&
    reviewEvidenceOk && openSevere.length === 0 && undocumentedFindings.length === 0
  add(checks, 'CURRENT_SHA_SECURITY_REVIEW', reviewOk,
    openSevere.length ? `unclosed severe findings: ${openSevere.map((item) => item.id).join(', ')}` :
      undocumentedFindings.length ? `findings without evidence-backed disposition: ${undocumentedFindings.map((item) => item.id).join(', ')}` :
        'current-SHA race, release-trust, scan summaries, and finding dispositions are evidence-bound')

  const blockers = checks.filter((check) => check.status !== 'PASS')
  return {
    schemaVersion: 'armorbreak.v2.2-stable-gate-result/v1',
    sourceCommit,
    stableScope: policy?.releaseName ?? null,
    status: blockers.length === 0 ? 'ELIGIBLE_FOR_RELEASE' : 'BLOCKED',
    releaseAuthorization: 'EXTERNAL_GITHUB_WRITE_REQUIRED',
    fullGaReady: false,
    checks,
    blockers,
    releasable: blockers.length === 0,
  }
}

export const stableGateRequiredCiJobs = REQUIRED_CI_JOBS
export const stableGateRequiredReleaseTag = REQUIRED_RELEASE_TAG
export const stableGateRequiredRulesetName = REQUIRED_RULESET_NAME
export const stableGateRequiredPublisher = REQUIRED_PUBLISHER
export const stableGateRequiredCheckAppId = REQUIRED_CHECK_APP_ID
