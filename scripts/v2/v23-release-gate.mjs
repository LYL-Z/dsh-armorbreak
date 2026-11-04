#!/usr/bin/env node
/** V2.3 PR and release gates have intentionally different contracts. */
import { createHash } from 'node:crypto'
import { lstatSync, readFileSync } from 'node:fs'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { execFileSync, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { findForbiddenPostSourcePaths, isFullCommitSha } from './v23-provenance.mjs'

export const AUTH_SCHEMA = 'armorbreak.v2.3-external-release-authorization/v2'
const REPOSITORY = 'LYL-Z/dsh-armorbreak'
const SIGNER_WORKFLOW = '.github/workflows/v2.3-main-gate.yml'
const REQUIRED_MAIN_JOBS = ['Node 22 / ubuntu-latest', 'Node 24 / ubuntu-latest', 'Node 22 / windows-latest', 'Node 24 / windows-latest']
const REQUIRED_RELEASE_GATES = ['securityReview', 'licenseReview', 'portableCleanroom', 'upgradeRollback', 'artifact', 'sbom', 'mainCi', 'attestation', 'maintainerAuthorization']
const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const repoRoot = resolve(process.env.V23_REPO_ROOT || process.cwd())

export function missingRequiredReleaseClaims(claims) {
  return REQUIRED_RELEASE_GATES.filter((key) => !claims?.[key] || typeof claims[key] !== 'object' || Array.isArray(claims[key]))
}

export function validateOwnerSelfReviewClaims(claims, expectedSha) {
  const blockers = []
  const missing = missingRequiredReleaseClaims(claims)
  if (missing.length) return { valid: false, blockers: missing.map((key) => `authorization claim ${key} is missing`) }
  if (claims.decision !== 'READY') blockers.push('detached authorization decision is not READY')
  if (claims.releaseModel !== 'OWNER_APPROVED_SELF_REVIEW') blockers.push('release model is not owner-approved self-review')
  for (const key of ['securityReview', 'licenseReview']) {
    const review = claims[key]
    if (review.reviewerType !== 'IMPLEMENTER_AI_SELF_REVIEW' || review.independentHumanReview !== 'NOT_PERFORMED' || review.conclusion !== 'OWNER_ACCEPTED_RISK') blockers.push(`${key} is not an explicitly owner-accepted AI self-review`)
    if (typeof review.evidencePath !== 'string' || !/^[a-f0-9]{64}$/i.test(review.evidenceSha256 ?? '')) blockers.push(`${key} evidence path or digest is invalid`)
  }
  if (claims.maintainerAuthorization.authorized !== true || claims.maintainerAuthorization.method !== 'OWNER_TAG_EVENT'
    || String(claims.maintainerAuthorization.actorId) !== '250811935' || String(claims.maintainerAuthorization.eventSenderId) !== '250811935') blockers.push('tag event is not an owner-authorized GitHub event')
  if (claims.upgradeRollback.kind !== 'REAL_CANDIDATE_PACKAGE' || claims.upgradeRollback.rollbackVerified !== true
    || claims.upgradeRollback.permissionsVerified !== true || claims.upgradeRollback.artifactSha256 !== claims.artifact.sha256
    || !/^[a-f0-9]{64}$/i.test(claims.upgradeRollback.evidenceSha256 ?? '')) blockers.push('real package rollback evidence is missing or mismatched')
  if (claims.mainCi.commit !== expectedSha || !/^[1-9][0-9]{4,20}$/.test(String(claims.mainCi.runId ?? ''))) blockers.push('exact-main CI claim is missing or mismatched')
  if (claims.attestation.kind !== 'GITHUB_OIDC_BUILD_PROVENANCE' || !/^[a-f0-9]{64}$/i.test(claims.attestation.evidenceSha256 ?? '')) blockers.push('GitHub build provenance evidence is missing')
  if (claims.portableCleanroom.status !== 'PASS_ACTUAL_CLEANROOM_ARCHIVE_EXECUTION' || claims.portableCleanroom.sourceCommit !== expectedSha
    || claims.portableCleanroom.artifactSha256 !== claims.artifact.sha256 || !/^[a-f0-9]{64}$/i.test(claims.portableCleanroom.evidenceSha256 ?? '')) blockers.push('exact-main portable clean-room execution evidence is missing or mismatched')
  if (claims.portableCleanroom.manifestCommit !== expectedSha || !/^[a-f0-9]{64}$/i.test(claims.portableCleanroom.manifestSha256 ?? '')) blockers.push('portable package manifest is not bound to the exact main SHA')
  if (!/^[a-f0-9]{64}$/i.test(claims.artifact.sha256 ?? '') || !/^[a-f0-9]{64}$/i.test(claims.sbom.sha256 ?? '')) blockers.push('artifact or SBOM digest is malformed')
  return { valid: blockers.length === 0, blockers }
}

function safeRepoPath(path) {
  if (typeof path !== 'string' || !path || isAbsolute(path)) throw new Error(`unsafe repository evidence path: ${path}`)
  const absolute = resolve(repoRoot, path)
  const rel = relative(repoRoot, absolute)
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error(`evidence path escapes repository: ${path}`)
  let cursor = repoRoot
  for (const segment of rel.split(sep)) {
    cursor = join(cursor, segment)
    const stat = lstatSync(cursor)
    if (stat.isSymbolicLink()) throw new Error(`evidence path contains a symlink: ${path}`)
  }
  const stat = lstatSync(absolute)
  if (!stat.isFile()) throw new Error(`evidence path is not a regular file: ${path}`)
  if (stat.nlink !== 1) throw new Error(`evidence path is hard-linked: ${path}`)
  return absolute
}

function readJson(path) { return JSON.parse(readFileSync(safeRepoPath(path), 'utf8')) }
function sha256(path) { return createHash('sha256').update(readFileSync(safeRepoPath(path))).digest('hex') }
function git(args) { return execFileSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim() }
function verifyDigest(path, expected, label) {
  if (!/^[a-f0-9]{64}$/i.test(expected ?? '')) throw new Error(`${label} SHA-256 is missing or malformed`)
  if (sha256(path) !== expected.toLowerCase()) throw new Error(`${label} SHA-256 does not match its signed claim`)
}

export function evaluatePrContract({ packageName, status, releaseState }) {
  const blockers = []
  if (packageName !== 'dsh-armorbreak') blockers.push('unexpected package identity')
  if (!['IN_PROGRESS', 'COMPLETE'].includes(status)) blockers.push('P0-H status must be IN_PROGRESS or COMPLETE')
  if (releaseState !== 'NOT_READY') blockers.push('PR candidate structured releaseState must remain NOT_READY')
  return { valid: blockers.length === 0, releaseReadiness: 'NOT_READY', blockers }
}

export function evaluateMainContract({ packageName, packageVersion, status, releaseState, expectedSha, head }) {
  const blockers = []
  if (packageName !== 'dsh-armorbreak') blockers.push('unexpected package identity')
  if (packageVersion !== '2.3.0') blockers.push(`package version must be 2.3.0, found ${packageVersion}`)
  if (status !== 'COMPLETE') blockers.push('P0-H candidate engineering and evidence must be COMPLETE before main')
  if (releaseState !== 'NOT_READY') blockers.push('frozen main candidate releaseState must remain NOT_READY until external tag authorization')
  if (!isFullCommitSha(expectedSha) || expectedSha !== head) blockers.push('exact main candidate SHA is required')
  return { valid: blockers.length === 0, releaseReadiness: 'NOT_READY', blockers }
}

export function evaluateReleaseContract({ packageName, packageVersion, status, releaseState, tag, expectedSha }) {
  const blockers = []
  if (packageName !== 'dsh-armorbreak') blockers.push('unexpected package identity')
  if (packageVersion !== '2.3.0') blockers.push(`package version must be 2.3.0, found ${packageVersion}`)
  if (status !== 'COMPLETE') blockers.push('P0-H matrix status is not COMPLETE')
  // The source tree is immutable after main CI. Final READY is an external,
  // tag-scoped authorization envelope attested by the actual release workflow.
  if (releaseState !== 'NOT_READY') blockers.push('frozen source tree releaseState must remain NOT_READY; final readiness is external')
  if (tag !== 'refs/tags/v2.3.0' && tag !== 'v2.3.0') blockers.push('release gate only accepts the exact v2.3.0 tag')
  if (!isFullCommitSha(expectedSha)) blockers.push('exact release commit SHA is required')
  return { valid: blockers.length === 0, blockers }
}

function loadCommon() {
  const pkg = readJson('package.json')
  const manifest = readJson('docs/v2.3/evidence/p0-h/acceptance-manifest.json')
  const matrix = readJson('docs/v2.3/compatibility-matrix.json')
  const milestone = matrix.milestones?.find((item) => item.id === 'P0-H')
  if (manifest.schemaVersion !== 'armorbreak.v2.3-acceptance-manifest/v1') throw new Error('acceptance manifest schema mismatch')
  if (manifest.baselineSha !== '66ec0017af4b9d636f09e45f7cf55eed060512ac') throw new Error('V2.3 evidence baseline is not the frozen M0 SHA')
  if (!isFullCommitSha(manifest.sourceCommit)) throw new Error('manifest sourceCommit must be a full Git SHA')
  const head = git(['rev-parse', 'HEAD'])
  git(['merge-base', '--is-ancestor', manifest.sourceCommit, head])
  const changed = git(['diff', '--name-only', '-z', `${manifest.sourceCommit}..${head}`]).split('\0').filter(Boolean)
  const forbidden = findForbiddenPostSourcePaths(changed)
  if (forbidden.length) throw new Error(`post-source changes escape evidence-only allowlist: ${forbidden.join(', ')}`)
  return { pkg, manifest, milestone, head }
}

function verifyExternalAuthorization({ expectedSha, sourceCommit, pkg }) {
  const envelopePath = process.env.V23_AUTH_ENVELOPE_PATH
  if (!envelopePath || !isAbsolute(envelopePath)) throw new Error('detached authorization envelope path is required (V23_AUTH_ENVELOPE_PATH)')
  const envelopeStat = lstatSync(envelopePath)
  if (!envelopeStat.isFile() || envelopeStat.isSymbolicLink() || envelopeStat.nlink !== 1 || envelopeStat.size > 2 * 1024 * 1024) throw new Error('detached authorization envelope must be a bounded singly-linked regular file')
  const envelope = JSON.parse(readFileSync(envelopePath, 'utf8'))
  const { claims } = envelope ?? {}
  if (!claims || claims.schemaVersion !== AUTH_SCHEMA) throw new Error('detached release authorization schema is invalid')
  const verifyEnvelope = spawnSync('gh', [
    'attestation', 'verify', envelopePath, '--repo', REPOSITORY,
    '--signer-workflow', `${REPOSITORY}/${SIGNER_WORKFLOW}`,
    '--source-ref', 'refs/tags/v2.3.0', '--source-digest', expectedSha, '--format', 'json',
  ], { cwd: repoRoot, encoding: 'utf8' })
  if (verifyEnvelope.status !== 0) throw new Error(`GitHub release-authorization attestation verification failed: ${(verifyEnvelope.stderr || verifyEnvelope.stdout).trim()}`)
  if (claims.repository !== REPOSITORY || claims.tag !== 'v2.3.0') throw new Error('authorization repository or tag scope is incorrect')
  if (claims.tagCommit !== expectedSha) throw new Error('authorization tagCommit does not match the exact tag commit')
  if (!isFullCommitSha(claims.sourceCommit) || claims.sourceCommit !== sourceCommit) throw new Error('authorization sourceCommit does not match the source commit named by the manifest')
  if (!isFullCommitSha(claims.evidenceCommit)) throw new Error('authorization evidenceCommit is not a full SHA')
  if (claims.packageVersion !== pkg.version) throw new Error('authorization package version mismatch')
  git(['merge-base', '--is-ancestor', claims.sourceCommit, claims.evidenceCommit])
  git(['merge-base', '--is-ancestor', claims.evidenceCommit, expectedSha])
  if (git(['rev-parse', `${claims.evidenceCommit}^{tree}`]) !== git(['rev-parse', `${expectedSha}^{tree}`])) throw new Error('tag commit tree differs from the signed evidence commit tree')
  const changed = git(['diff', '--name-only', '-z', `${claims.sourceCommit}..${claims.evidenceCommit}`]).split('\0').filter(Boolean)
  const forbidden = findForbiddenPostSourcePaths(changed)
  if (forbidden.length) throw new Error(`evidence commit contains source/workflow changes after sourceCommit: ${forbidden.join(', ')}`)

  const missingClaims = missingRequiredReleaseClaims(claims)
  if (missingClaims.length) throw new Error(`authorization claim ${missingClaims.join(', ')} is missing or malformed`)
  const claimValidation = validateOwnerSelfReviewClaims(claims, expectedSha)
  if (!claimValidation.valid) throw new Error(claimValidation.blockers.join('; '))
  for (const [key, part] of [
    ['securityReview', claims.securityReview],
    ['licenseReview', claims.licenseReview],
    ['portableCleanroom', claims.portableCleanroom],
    ['upgradeRollback', claims.upgradeRollback],
    ['attestation', claims.attestation],
  ]) {
    verifyDigest(part.evidencePath, part.evidenceSha256, key)
  }
  const portable = readJson(claims.portableCleanroom.evidencePath)
  if (portable.schemaVersion !== 'armorbreak.v2.3-portable-cleanroom/v1'
    || portable.status !== 'PASS_ACTUAL_CLEANROOM_ARCHIVE_EXECUTION'
    || portable.sourceCommit !== expectedSha
    || portable.artifact?.sha256 !== claims.artifact.sha256
    || portable.artifact?.manifestCommit !== expectedSha
    || portable.artifact?.manifestSha256 !== claims.portableCleanroom.manifestSha256
    || portable.checks?.sourceSymbolsJavaScriptAndTypeScript?.taskAndReportRead !== true
    || portable.checks?.l0Workflow?.taskAndReportRead !== true) throw new Error('clean-room execution record does not bind exact main source, archive manifest, JS/TS and L0 task/report results')
  const artifact = claims.artifact
  const sbom = claims.sbom
  verifyDigest(artifact.path, artifact.sha256, 'candidate artifact')
  verifyDigest(sbom.path, sbom.sha256, 'SBOM')
  const packageManifestPath = `${artifact.path}.manifest.json`
  verifyDigest(packageManifestPath, claims.portableCleanroom.manifestSha256, 'portable package manifest')
  const packageManifest = readJson(packageManifestPath)
  if (packageManifest.schemaVersion !== 'armorbreak.release-build/v1' || packageManifest.commit !== expectedSha
    || packageManifest.version !== pkg.version || packageManifest.reproducible !== true
    || packageManifest.sha256 !== artifact.sha256) throw new Error('portable package manifest does not match the exact tag source and artifact')
  const sbomDocument = readJson(sbom.path)
  const subject = sbomDocument.metadata?.component
  if (subject?.name !== pkg.name || subject?.version !== pkg.version || !subject.hashes?.some((item) => item.alg === 'SHA-256' && item.content === artifact.sha256)) throw new Error('CycloneDX SBOM subject/version/digest does not match the candidate artifact')
  if (claims.mainCi.commit !== expectedSha || !/^[1-9][0-9]{4,20}$/.test(String(claims.mainCi.runId ?? ''))) throw new Error('exact-main CI is not bound to the evidence/tag commit')

  const run = JSON.parse(execFileSync('gh', ['run', 'view', String(claims.mainCi.runId), '--repo', REPOSITORY, '--json', 'headSha,event,headBranch,status,conclusion,workflowName,jobs'], { cwd: repoRoot, encoding: 'utf8' }))
  if (run.workflowName !== 'V2.3 main and release gate' || run.event !== 'push' || run.headBranch !== 'main' || run.headSha !== expectedSha || run.status !== 'completed' || run.conclusion !== 'success') throw new Error('GitHub exact-main CI run is not successful on the exact main commit')
  const successfulJobs = new Set((run.jobs ?? []).filter((job) => job.conclusion === 'success').map((job) => job.name))
  const missing = REQUIRED_MAIN_JOBS.filter((name) => !successfulJobs.has(name))
  if (missing.length) throw new Error(`exact-main CI lacks successful matrix jobs: ${missing.join(', ')}`)

  const verifyAttestation = spawnSync('gh', [
    'attestation', 'verify', safeRepoPath(artifact.path), '--repo', REPOSITORY,
    '--signer-workflow', `${REPOSITORY}/${SIGNER_WORKFLOW}`,
    '--source-ref', 'refs/heads/main', '--source-digest', expectedSha, '--format', 'json',
  ], { cwd: repoRoot, encoding: 'utf8' })
  if (verifyAttestation.status !== 0) throw new Error(`GitHub artifact attestation verification failed: ${(verifyAttestation.stderr || verifyAttestation.stdout).trim()}`)
  const attestations = JSON.parse(verifyAttestation.stdout)
  if (!Array.isArray(attestations) || !attestations.length) throw new Error('GitHub CLI returned no verified artifact attestations')
  if (sha256(artifact.path) !== artifact.sha256) throw new Error('candidate artifact changed during attestation verification')
}

function main() {
  const args = new Set(process.argv.slice(2))
  const selected = ['--check-pr', '--check-main', '--release'].filter((arg) => args.has(arg))
  const mode = selected.length === 1 ? selected[0].slice(2) : null
  if (!mode || [...args].some((arg) => !['--release', '--check-pr', '--check-main'].includes(arg))) {
    console.error('Usage: node scripts/v2/v23-release-gate.mjs --check-pr | --check-main | --release')
    process.exitCode = 2
    return
  }
  try {
    const { pkg, manifest, milestone, head } = loadCommon()
    if (mode === 'check-pr') {
      const state = evaluatePrContract({ packageName: pkg.name, status: milestone?.status, releaseState: milestone?.releaseState ?? milestone?.releaseReadiness })
      if (!state.valid) throw new Error(state.blockers.join('; '))
      const expectedSha = process.env.V23_EXPECTED_SHA ?? null
      if (expectedSha && (!isFullCommitSha(expectedSha) || expectedSha !== head)) throw new Error('V23_EXPECTED_SHA must match the full validated HEAD SHA')
      const output = {
        schemaVersion: 'armorbreak.v2.3-pr-gate/v2', mode, gateConfiguration: 'VALIDATED',
        releaseReadiness: 'NOT_READY', sourceCommit: manifest.sourceCommit, head,
        blockers: [
          ...(milestone.status === 'COMPLETE' ? [] : ['P0-H closure']),
          ...(pkg.version === '2.3.0' ? [] : [`package version must be 2.3.0, found ${pkg.version}`]),
          'owner-approved self-review evidence and risk acceptance', 'single-principal configuration verification',
          'exact-main CI, immutable package/SBOM hashes and GitHub attestation', 'maintainer release authorization',
        ],
        note: 'PR validation proves the candidate check path only and never grants release approval.',
      }
      console.log(JSON.stringify(output, null, 2))
      return
    }

    if (mode === 'check-main') {
      const expectedSha = process.env.GITHUB_SHA ?? process.env.V23_EXPECTED_SHA ?? ''
      const state = evaluateMainContract({ packageName: pkg.name, packageVersion: pkg.version, status: milestone?.status, releaseState: milestone?.releaseState ?? milestone?.releaseReadiness, expectedSha, head })
      if (!state.valid) throw new Error(state.blockers.join('; '))
      console.log(JSON.stringify({ schemaVersion: 'armorbreak.v2.3-main-candidate-gate/v1', mode, gateConfiguration: 'VALIDATED', releaseReadiness: 'NOT_READY', sourceCommit: manifest.sourceCommit, head, blockers: ['main-run exact package/SBOM attestation', 'owner-authorized exact-tag event and release envelope'], note: 'main candidate validation does not grant release approval; the frozen tree remains NOT_READY and exact-tag evidence is evaluated later.' }, null, 2))
      return
    }

    const tag = process.env.GITHUB_REF ?? process.env.V23_TAG ?? ''
    const expectedSha = process.env.GITHUB_SHA ?? process.env.V23_EXPECTED_SHA ?? ''
    const state = evaluateReleaseContract({ packageName: pkg.name, packageVersion: pkg.version, status: milestone?.status, releaseState: milestone?.releaseState ?? milestone?.releaseReadiness, tag, expectedSha })
    if (!state.valid) throw new Error(state.blockers.join('; '))
    if (git(['rev-parse', 'refs/tags/v2.3.0^{commit}']) !== expectedSha) throw new Error('the exact v2.3.0 tag does not resolve to GITHUB_SHA')
    verifyExternalAuthorization({ expectedSha, sourceCommit: manifest.sourceCommit, pkg })
    console.log(JSON.stringify({ schemaVersion: 'armorbreak.v2.3-release-gate/v3', mode, tag, tagCommit: expectedSha, sourceCommit: manifest.sourceCommit, decision: 'READY', releaseModel: 'OWNER_APPROVED_SELF_REVIEW', verified: ['GitHub-attested detached release envelope sourced from exact v2.3.0 tag', 'source/evidence/tag ancestry and identical evidence/tag tree', 'self-review, license and rollback evidence hashes', 'owner identity on tag event', 'exact-main CI matrix', 'artifact and SBOM hashes', 'GitHub main-build provenance attestation'] }, null, 2))
  } catch (error) {
    console.log(JSON.stringify({ schemaVersion: mode === 'release' ? 'armorbreak.v2.3-release-gate/v2' : 'armorbreak.v2.3-pr-gate/v2', mode, decision: 'NOT_READY', blockers: [String(error?.message ?? error)] }, null, 2))
    process.exitCode = 1
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('v23-release-gate.mjs')) main()
