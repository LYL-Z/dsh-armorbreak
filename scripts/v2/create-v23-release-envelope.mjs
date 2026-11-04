#!/usr/bin/env node
/** Create the detached, tag-scoped authorization payload for GitHub attestation. */
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { relative, resolve, sep } from 'node:path'
import { execFileSync } from 'node:child_process'

const root = process.cwd()
const hash = (path) => createHash('sha256').update(readFileSync(resolve(root, path))).digest('hex')
const git = (args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim()
const requiredEnv = (name) => {
  const value = process.env[name]
  if (!value) throw new Error(`${name} is required`)
  return value
}
const tagCommit = requiredEnv('GITHUB_SHA')
const tagRef = requiredEnv('GITHUB_REF')
const actorId = requiredEnv('V23_EVENT_SENDER_ID')
const mainRunId = requiredEnv('V23_MAIN_RUN_ID')
if (tagRef !== 'refs/tags/v2.3.0') throw new Error('release envelope only supports refs/tags/v2.3.0')
if (actorId !== '250811935') throw new Error('tag event sender is not the repository owner')
const manifest = JSON.parse(readFileSync(resolve(root, 'docs/v2.3/evidence/p0-h/acceptance-manifest.json'), 'utf8'))
const evidenceCommit = git(['log', '-1', '--format=%H', '--', 'docs/v2.3/evidence/p0-h/acceptance-manifest.json'])
if (!/^[a-f0-9]{40}$/i.test(manifest.sourceCommit) || !/^[a-f0-9]{40}$/i.test(evidenceCommit)) throw new Error('source/evidence commit binding is invalid')
const artifactPath = 'dist/armorbreak-portable-2.3.0.tar.gz'
const sbomPath = `${artifactPath}.sbom.cdx.json`
const reviewPath = 'docs/v2.3/evidence/p0-h/self-review-final.json'
const licensePath = 'docs/v2.3/evidence/p0-h/license-review-final.json'
const portablePath = 'dist/v23-portable-cleanroom.json'
const rollbackPath = 'dist/latest-release-rollback.json'
const rollback = JSON.parse(readFileSync(resolve(root, rollbackPath), 'utf8'))
const portable = JSON.parse(readFileSync(resolve(root, portablePath), 'utf8'))
if (rollback.status !== 'PASS_ISOLATED_REAL_PACKAGE_DEPLOYMENT' || rollback.candidatePackage?.sha256 !== hash(artifactPath)) {
  throw new Error('tagged exact main artifact lacks a matching real Windows deployment/rollback drill')
}
const claims = {
  schemaVersion: 'armorbreak.v2.3-external-release-authorization/v2',
  decision: 'READY',
  releaseModel: 'OWNER_APPROVED_SELF_REVIEW',
  repository: 'LYL-Z/dsh-armorbreak',
  tag: 'v2.3.0',
  tagCommit,
  sourceCommit: manifest.sourceCommit,
  evidenceCommit,
  packageVersion: '2.3.0',
  securityReview: {
    reviewerType: 'IMPLEMENTER_AI_SELF_REVIEW', independentHumanReview: 'NOT_PERFORMED', conclusion: 'OWNER_ACCEPTED_RISK',
    evidencePath: reviewPath, evidenceSha256: hash(reviewPath),
  },
  licenseReview: {
    reviewerType: 'IMPLEMENTER_AI_SELF_REVIEW', independentHumanReview: 'NOT_PERFORMED', conclusion: 'OWNER_ACCEPTED_RISK',
    evidencePath: licensePath, evidenceSha256: hash(licensePath),
  },
  portableCleanroom: {
    status: portable.status, sourceCommit: portable.sourceCommit, artifactSha256: portable.artifact?.sha256,
    evidencePath: portablePath, evidenceSha256: hash(portablePath),
  },
  upgradeRollback: {
    kind: 'REAL_CANDIDATE_PACKAGE', rollbackVerified: true, permissionsVerified: true,
    evidencePath: rollbackPath, evidenceSha256: hash(rollbackPath), artifactSha256: hash(artifactPath),
  },
  artifact: { path: artifactPath, sha256: hash(artifactPath) },
  sbom: { path: sbomPath, sha256: hash(sbomPath) },
  mainCi: { commit: tagCommit, runId: mainRunId },
  attestation: { kind: 'GITHUB_OIDC_BUILD_PROVENANCE', evidencePath: 'dist/attestation-verification.json', evidenceSha256: hash('dist/attestation-verification.json') },
  maintainerAuthorization: {
    authorized: true, method: 'OWNER_TAG_EVENT', actorId, eventSenderId: actorId,
    workflowRunId: requiredEnv('GITHUB_RUN_ID'),
  },
}
const out = process.env.V23_AUTH_ENVELOPE_PATH
const tempRoot = resolve(process.env.RUNNER_TEMP ?? root)
const outputPath = out ? resolve(out) : ''
const outputRelative = out ? relative(tempRoot, outputPath) : ''
if (!out || !outputRelative || outputRelative === '..' || outputRelative.startsWith(`..${sep}`)) {
  throw new Error('V23_AUTH_ENVELOPE_PATH must be a child of runner temporary storage')
}
writeFileSync(outputPath, `${JSON.stringify({ claims }, null, 2)}\n`, { flag: 'wx' })
console.log(JSON.stringify({ status: 'ENVELOPE_CREATED_PENDING_GITHUB_ATTESTATION', tagCommit, sourceCommit: manifest.sourceCommit, evidenceCommit, mainRunId, decision: claims.decision, output: outputPath }, null, 2))
