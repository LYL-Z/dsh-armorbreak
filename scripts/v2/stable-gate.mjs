#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { basename, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyPortableArtifactAttestation } from '../../lib/release/artifactAttestation.js'
import { evaluateStableGate, stableGateRequiredRulesetName } from '../../lib/release/stableGate.js'
import { readSafeRepoFile, writeSafeRepoFile } from '../../lib/release/safeEvidenceFile.js'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const repository = 'LYL-Z/dsh-armorbreak'
const args = process.argv.slice(2)
const value = (name) => {
  const index = args.indexOf(name)
  return index >= 0 ? args[index + 1] : undefined
}
const readJson = (relativePath, prefix) => JSON.parse(readSafeRepoFile(root, relativePath, { requiredPrefix: prefix }).toString('utf8'))
const git = (gitArgs) => execFileSync('git', gitArgs, { cwd: root, encoding: 'utf8' }).trim()
const ghJson = (ghArgs) => JSON.parse(execFileSync('gh', ghArgs, { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }))
const runGitHubWorkflow = (workflowPath, expectedName, sourceCommit) => {
  const runs = ghJson(['run', 'list', '--repo', repository, '--workflow', workflowPath, '--branch', 'main', '--limit', '100', '--json', 'databaseId,workflowName,headSha,event,status,conclusion,headBranch,url'])
  const run = runs.find((item) => item.workflowName === expectedName && item.event === 'push' && item.headBranch === 'main' && item.headSha?.toLowerCase() === sourceCommit.toLowerCase())
  if (!run) return { workflow: expectedName, event: 'missing', branch: 'main', conclusion: 'missing', headSha: null, jobs: [] }
  const detail = ghJson(['run', 'view', String(run.databaseId), '--repo', repository, '--json', 'jobs'])
  return { ...run, workflow: run.workflowName, branch: run.headBranch, jobs: detail.jobs ?? [] }
}

function cleanTrackedWorktree() {
  const unstaged = spawnSync('git', ['diff', '--quiet', 'HEAD', '--'], { cwd: root })
  const staged = spawnSync('git', ['diff', '--cached', '--quiet'], { cwd: root })
  return unstaged.status === 0 && staged.status === 0
}

function readSecurityReview(relativePath, sourceCommit) {
  const review = readJson(relativePath, '.runtime/')
  if (!Array.isArray(review.evidence)) return review
  for (const item of review.evidence) {
    try {
      const bytes = readSafeRepoFile(root, item.path, { requiredPrefix: '.runtime/' })
      item.verified = bytes.length > 0 && createSha(bytes) === item.sha256?.toLowerCase()
    } catch { item.verified = false }
  }
  return review
}

const createSha = (bytes) => createHash('sha256').update(bytes).digest('hex')

function prMerged(number) {
  const pr = ghJson(['pr', 'view', String(number), '--repo', repository, '--json', 'state,mergedAt,mergeCommit'])
  return pr.state === 'MERGED' && Boolean(pr.mergedAt) && Boolean(pr.mergeCommit?.oid)
}

function main() {
  if (!args.includes('--release')) {
    console.error('Stable publication gate requires --release and complete exact-SHA evidence inputs.')
    process.exitCode = 2
    return
  }
  const artifactPath = value('--artifact')
  const sbomPath = value('--sbom')
  const buildManifestPath = value('--build-manifest')
  const securityReviewPath = value('--security-review')
  if (!artifactPath || !sbomPath || !buildManifestPath || !securityReviewPath) throw new Error('missing required --artifact, --sbom, --build-manifest, or --security-review input')
  const sourceCommit = git(['rev-parse', 'HEAD'])
  const branchName = git(['branch', '--show-current'])
  const remoteMainLine = git(['ls-remote', 'origin', 'refs/heads/main'])
  const remoteMainCommit = remoteMainLine.split(/\s+/)[0]
  const policy = readJson('docs/v2/release/v2.2-stable-scope-v1.json', 'docs/v2/release/')
  const packageManifest = readJson('package.json', undefined)
  const packageLock = readJson('package-lock.json', undefined)
  const legacyReadinessBytes = readSafeRepoFile(root, 'docs/v2/acceptance/v2.2-readiness.json', { requiredPrefix: 'docs/v2/acceptance/' })
  const legacyReadiness = JSON.parse(legacyReadinessBytes.toString('utf8'))
  const legacyReleaseReadinessBytes = readSafeRepoFile(root, 'docs/v2/release/readiness.json', { requiredPrefix: 'docs/v2/release/' })
  const legacyScope = readJson('docs/v2/acceptance/release-scope.json', 'docs/v2/acceptance/')
  const artifactBytes = readSafeRepoFile(root, artifactPath, { requiredPrefix: 'dist/' })
  const sbomBytes = readSafeRepoFile(root, sbomPath, { requiredPrefix: 'dist/' })
  const buildManifest = readJson(buildManifestPath, '.runtime/')
  const securityReview = readSecurityReview(securityReviewPath, sourceCommit)
  const artifactName = basename(artifactPath)
  const sbomName = basename(sbomPath)
  const artifactEvidence = { ...buildManifest, sourceCommit: buildManifest.commit }
  const attestation = verifyPortableArtifactAttestation({
    repoRoot: root,
    artifactPath,
    artifactEvidence,
    sourceCommit,
  })
  const ciRun = runGitHubWorkflow('.github/workflows/ci.yml', 'CI', sourceCommit)
  const attestationRun = runGitHubWorkflow('.github/workflows/attest.yml', 'Release attestation', sourceCommit)
  const mainProtection = ghJson(['api', `repos/${repository}/branches/main/protection`])
  const tagRulesets = ghJson(['api', `repos/${repository}/rulesets`])
  const releaseRuleset = tagRulesets.find((item) => item?.name === stableGateRequiredRulesetName)
  const identity = ghJson(['api', 'user'])
  const repositoryInfo = ghJson(['api', `repos/${repository}`])
  const report = evaluateStableGate({
    policy, packageManifest, packageLock, legacyReadiness, legacyReadinessBytes, legacyReleaseReadinessBytes, legacyScope,
    sourceCommit, branchName, remoteMainCommit, trackedWorktreeClean: cleanTrackedWorktree(),
    pr18Merged: prMerged(18), pr17Merged: prMerged(17),
    ciRun, attestationRun,
    repositoryProtection: {
      main: {
        requiredStatusChecks: {
          strict: mainProtection?.required_status_checks?.strict,
          contexts: mainProtection?.required_status_checks?.contexts,
          checks: mainProtection?.required_status_checks?.checks,
        },
        enforceAdmins: mainProtection?.enforce_admins?.enabled,
      },
      tagRulesets: releaseRuleset ? [releaseRuleset] : [],
    },
    publisherIdentity: {
      login: identity?.login,
      id: identity?.id,
      repositoryAdmin: repositoryInfo?.permissions?.admin === true,
    },
    attestation,
    artifactBytes, artifactName,
    sbomBytes, sbomName, buildManifest, securityReview,
  })
  const outputPath = value('--output')
  const output = `${JSON.stringify(report, null, 2)}\n`
  if (outputPath) writeSafeRepoFile(root, outputPath, output, { requiredPrefix: '.runtime/' })
  process.stdout.write(output)
  if (!report.releasable) process.exitCode = 1
}

try { main() }
catch (error) {
  process.stderr.write(`${error?.stack ?? error}\n`)
  process.exitCode = 1
}
