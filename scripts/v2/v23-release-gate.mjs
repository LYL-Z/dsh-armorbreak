#!/usr/bin/env node
/** V2.3 PR and release gates have intentionally different contracts. */
import { createHash, createPublicKey, verify } from 'node:crypto'
import { lstatSync, readFileSync } from 'node:fs'
import { isAbsolute, join, relative, resolve, sep } from 'node:path'
import { execFileSync, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { findForbiddenPostSourcePaths, isFullCommitSha } from './v23-provenance.mjs'

export const AUTH_SCHEMA = 'armorbreak.v2.3-external-release-authorization/v1'
const REPOSITORY = 'LYL-Z/dsh-armorbreak'
const SIGNER_WORKFLOW = '.github/workflows/v2.3-main-gate.yml'
const REQUIRED_MAIN_JOBS = ['Node 22 / ubuntu-latest', 'Node 24 / ubuntu-latest', 'Node 22 / windows-latest', 'Node 24 / windows-latest']
const REQUIRED_RELEASE_GATES = ['securityReview', 'licenseReview', 'upgradeRollback', 'artifact', 'sbom', 'mainCi', 'attestation', 'maintainerAuthorization']
const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const repoRoot = resolve(process.env.V23_REPO_ROOT || process.cwd())

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  return JSON.stringify(value)
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

export function evaluatePrContract({ packageName, status, report }) {
  const blockers = []
  if (packageName !== 'dsh-armorbreak') blockers.push('unexpected package identity')
  if (!['IN_PROGRESS', 'COMPLETE'].includes(status)) blockers.push('P0-H status must be IN_PROGRESS or COMPLETE')
  if (!/RELEASE READINESS/i.test(report) || !/\bNOT_READY\b/.test(report)) blockers.push('PR contract requires explicit RELEASE READINESS and NOT_READY markers')
  return { valid: blockers.length === 0, releaseReadiness: 'NOT_READY', blockers }
}

export function evaluateReleaseContract({ packageName, packageVersion, status, report, tag, expectedSha }) {
  const blockers = []
  if (packageName !== 'dsh-armorbreak') blockers.push('unexpected package identity')
  if (packageVersion !== '2.3.0') blockers.push(`package version must be 2.3.0, found ${packageVersion}`)
  if (status !== 'COMPLETE') blockers.push('P0-H matrix status is not COMPLETE')
  if (!/RELEASE READINESS/i.test(report) || !/(?:^|[^A-Z_])READY(?:[^A-Z_]|$)/.test(report) || /\bNOT_READY\b/.test(report)) blockers.push('release report does not declare READY or still contains NOT_READY')
  if (tag !== 'refs/tags/v2.3.0' && tag !== 'v2.3.0') blockers.push('release gate only accepts the exact v2.3.0 tag')
  if (!isFullCommitSha(expectedSha)) blockers.push('exact release commit SHA is required')
  return { valid: blockers.length === 0, blockers }
}

function loadCommon() {
  const pkg = readJson('package.json')
  const manifest = readJson('docs/v2.3/evidence/p0-h/acceptance-manifest.json')
  const matrix = readJson('docs/v2.3/compatibility-matrix.json')
  const milestone = matrix.milestones?.find((item) => item.id === 'P0-H')
  const report = readFileSync(safeRepoPath('docs/v2.3/acceptance-report.md'), 'utf8')
  if (manifest.schemaVersion !== 'armorbreak.v2.3-acceptance-manifest/v1') throw new Error('acceptance manifest schema mismatch')
  if (manifest.baselineSha !== '66ec0017af4b9d636f09e45f7cf55eed060512ac') throw new Error('V2.3 evidence baseline is not the frozen M0 SHA')
  if (!isFullCommitSha(manifest.sourceCommit)) throw new Error('manifest sourceCommit must be a full Git SHA')
  const head = git(['rev-parse', 'HEAD'])
  git(['merge-base', '--is-ancestor', manifest.sourceCommit, head])
  const changed = git(['diff', '--name-only', '-z', `${manifest.sourceCommit}..${head}`]).split('\0').filter(Boolean)
  const forbidden = findForbiddenPostSourcePaths(changed)
  if (forbidden.length) throw new Error(`post-source changes escape evidence-only allowlist: ${forbidden.join(', ')}`)
  return { pkg, manifest, milestone, report, head }
}

function verifySignature(claims, signature, envName, label) {
  const pem = process.env[envName]
  if (!pem) throw new Error(`${label} trust anchor ${envName} is unavailable`)
  if (!signature || typeof signature !== 'string') throw new Error(`${label} signature is missing`)
  const publicKey = createPublicKey(pem)
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error(`${label} trust anchor must be an Ed25519 public key`)
  if (!verify(null, Buffer.from(canonical(claims)), publicKey, Buffer.from(signature, 'base64'))) throw new Error(`${label} signature is invalid`)
}

function verifyExternalAuthorization({ expectedSha, sourceCommit, pkg }) {
  const envelopePath = process.env.V23_AUTH_ENVELOPE_PATH
  if (!envelopePath || !isAbsolute(envelopePath)) throw new Error('detached authorization envelope path is required (V23_AUTH_ENVELOPE_PATH)')
  const envelopeStat = lstatSync(envelopePath)
  if (!envelopeStat.isFile() || envelopeStat.isSymbolicLink() || envelopeStat.nlink !== 1 || envelopeStat.size > 2 * 1024 * 1024) throw new Error('detached authorization envelope must be a bounded singly-linked regular file')
  const envelope = JSON.parse(readFileSync(envelopePath, 'utf8'))
  const { claims, signatures } = envelope ?? {}
  if (!claims || claims.schemaVersion !== AUTH_SCHEMA || !signatures) throw new Error('detached release authorization schema is invalid')
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

  for (const key of REQUIRED_RELEASE_GATES) if (!claims[key]) throw new Error(`authorization claim ${key} is missing`)
  verifySignature(claims, signatures.securityReviewer, 'V23_SECURITY_REVIEWER_PUBLIC_KEY', 'independent security reviewer')
  verifySignature(claims, signatures.licenseReviewer, 'V23_LICENSE_REVIEWER_PUBLIC_KEY', 'independent license reviewer')
  verifySignature(claims, signatures.maintainer, 'V23_MAINTAINER_PUBLIC_KEY', 'maintainer')
  if (claims.securityReview.reviewerType !== 'INDEPENDENT_HUMAN' || claims.securityReview.conclusion !== 'ACCEPTED') throw new Error('security review is not an accepted independent human review')
  if (claims.licenseReview.reviewerType !== 'INDEPENDENT_HUMAN' || claims.licenseReview.conclusion !== 'ACCEPTED') throw new Error('license review is not an accepted independent human review')
  for (const [key, part] of [['securityReview', claims.securityReview], ['licenseReview', claims.licenseReview], ['upgradeRollback', claims.upgradeRollback]]) {
    verifyDigest(part.evidencePath, part.evidenceSha256, key)
  }
  if (claims.upgradeRollback.kind !== 'REAL_CANDIDATE_PACKAGE' || claims.upgradeRollback.rollbackVerified !== true || claims.upgradeRollback.permissionsVerified !== true || claims.upgradeRollback.artifactSha256 !== claims.artifact.sha256) throw new Error('real package rollback and permissions evidence is incomplete or bound to another candidate')
  if (!claims.maintainerAuthorization.authorized || claims.maintainerAuthorization.actorId !== claims.maintainer.actorId) throw new Error('explicit maintainer authorization is absent or mismatched')

  const artifact = claims.artifact
  const sbom = claims.sbom
  verifyDigest(artifact.path, artifact.sha256, 'candidate artifact')
  verifyDigest(sbom.path, sbom.sha256, 'SBOM')
  const sbomDocument = readJson(sbom.path)
  const subject = sbomDocument.metadata?.component
  if (subject?.name !== pkg.name || subject?.version !== pkg.version || !subject.hashes?.some((item) => item.alg === 'SHA-256' && item.content === artifact.sha256)) throw new Error('CycloneDX SBOM subject/version/digest does not match the candidate artifact')
  if (claims.mainCi.commit !== expectedSha || !claims.mainCi.runId) throw new Error('exact-main CI is not bound to the evidence/tag commit')

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
  const mode = args.has('--release') ? 'release' : args.has('--check-pr') ? 'check-pr' : null
  if (!mode || [...args].some((arg) => !['--release', '--check-pr'].includes(arg))) {
    console.error('Usage: node scripts/v2/v23-release-gate.mjs --check-pr | --release')
    process.exitCode = 2
    return
  }
  try {
    const { pkg, manifest, milestone, report, head } = loadCommon()
    if (mode === 'check-pr') {
      const state = evaluatePrContract({ packageName: pkg.name, status: milestone?.status, report })
      if (!state.valid) throw new Error(state.blockers.join('; '))
      const expectedSha = process.env.V23_EXPECTED_SHA ?? null
      if (expectedSha && (!isFullCommitSha(expectedSha) || expectedSha !== head)) throw new Error('V23_EXPECTED_SHA must match the full validated HEAD SHA')
      const output = {
        schemaVersion: 'armorbreak.v2.3-pr-gate/v2', mode, gateConfiguration: 'VALIDATED',
        releaseReadiness: 'NOT_READY', sourceCommit: manifest.sourceCommit, head,
        blockers: [
          ...(milestone.status === 'COMPLETE' ? [] : ['P0-H closure']),
          ...(pkg.version === '2.3.0' ? [] : [`package version must be 2.3.0, found ${pkg.version}`]),
          'independent human security and license review', 'real candidate package upgrade/rollback and OS permission drill',
          'exact-main CI, immutable package/SBOM hashes and GitHub attestation', 'maintainer release authorization',
        ],
        note: 'PR validation proves the candidate check path only and never grants release approval.',
      }
      console.log(JSON.stringify(output, null, 2))
      return
    }

    const tag = process.env.GITHUB_REF ?? process.env.V23_TAG ?? ''
    const expectedSha = process.env.GITHUB_SHA ?? process.env.V23_EXPECTED_SHA ?? ''
    const state = evaluateReleaseContract({ packageName: pkg.name, packageVersion: pkg.version, status: milestone?.status, report, tag, expectedSha })
    if (!state.valid) throw new Error(state.blockers.join('; '))
    if (git(['rev-parse', 'refs/tags/v2.3.0^{commit}']) !== expectedSha) throw new Error('the exact v2.3.0 tag does not resolve to GITHUB_SHA')
    verifyExternalAuthorization({ expectedSha, sourceCommit: manifest.sourceCommit, pkg })
    console.log(JSON.stringify({ schemaVersion: 'armorbreak.v2.3-release-gate/v2', mode, tag, tagCommit: expectedSha, sourceCommit: manifest.sourceCommit, decision: 'READY', verified: ['signed external authorization', 'source/evidence/tag ancestry and identical evidence/tag tree', 'review and rollback evidence hashes', 'exact-main CI matrix', 'artifact and SBOM hashes', 'GitHub build provenance attestation'] }, null, 2))
  } catch (error) {
    console.log(JSON.stringify({ schemaVersion: mode === 'release' ? 'armorbreak.v2.3-release-gate/v2' : 'armorbreak.v2.3-pr-gate/v2', mode, decision: 'NOT_READY', blockers: [String(error?.message ?? error)] }, null, 2))
    process.exitCode = 1
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('v23-release-gate.mjs')) main()
