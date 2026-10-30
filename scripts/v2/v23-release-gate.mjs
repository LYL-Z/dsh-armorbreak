#!/usr/bin/env node
/** Fail-closed V2.3-only pre-merge/release gate; does not publish artifacts. */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const args = new Set(process.argv.slice(2))
const mode = args.has('--release') ? 'release' : args.has('--check-pr') ? 'check-pr' : null
if (!mode || [...args].some((arg) => !['--release', '--check-pr'].includes(arg))) {
  console.error('Usage: node scripts/v2/v23-release-gate.mjs --check-pr | --release')
  process.exit(2)
}

const blockers = []
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'))
const packageJson = readJson('package.json')
const manifest = readJson('docs/v2.3/evidence/p0-h/acceptance-manifest.json')
const matrix = readJson('docs/v2.3/compatibility-matrix.json')
const p0h = matrix.milestones.find((item) => item.id === 'P0-H')
const report = readFileSync('docs/v2.3/acceptance-report.md', 'utf8')

if (packageJson.name !== 'dsh-armorbreak') blockers.push('unexpected package identity')
if (manifest?.baselineSha !== '66ec0017af4b9d636f09e45f7cf55eed060512ac') blockers.push('V2.3 evidence baseline is not the frozen M0 SHA')
if (p0h?.status !== 'IN_PROGRESS') blockers.push('P0-H matrix status must remain explicit')
if (!report.includes('NOT_READY')) blockers.push('acceptance report does not state NOT_READY')

if (mode === 'check-pr') {
  const expectedSha = process.env.V23_EXPECTED_SHA
  if (expectedSha && !/^[a-f0-9]{40}$/i.test(expectedSha)) blockers.push('V23_EXPECTED_SHA is not a full commit SHA')
  const result = {
    schemaVersion: 'armorbreak.v2.3-pr-gate/v1',
    mode,
    gateConfiguration: 'VALIDATED',
    releaseReadiness: 'NOT_READY',
    sourceCommit: manifest.sourceCommit,
    expectedSha: expectedSha ?? null,
    blockers: [
      ...(packageJson.version === '2.3.0' ? [] : [`package version must be 2.3.0, found ${packageJson.version}`]),
      'independent human security and license review',
      'isolated V2.2-to-V2.3 upgrade/rollback drill',
      'exact-main CI, immutable package hashes, SBOM and attestation',
      'maintainer release authorization',
    ],
    checks: blockers,
    note: 'This PR gate validates the V2.3-specific check path only; it is not release approval.',
  }
  console.log(JSON.stringify(result, null, 2))
  if (blockers.length) process.exitCode = 1
} else {
  if (packageJson.version !== '2.3.0') blockers.push(`package version must be 2.3.0, found ${packageJson.version}`)
  const authorizationPath = 'docs/v2.3/evidence/p0-h/release-authorization.json'
  const tag = process.env.GITHUB_REF ?? process.env.V23_TAG ?? ''
  const expectedSha = process.env.GITHUB_SHA ?? process.env.V23_EXPECTED_SHA ?? ''
  if (tag !== 'refs/tags/v2.3.0' && tag !== 'v2.3.0') blockers.push('release gate only accepts the exact v2.3.0 tag')
  if (!/^[a-f0-9]{40}$/i.test(expectedSha)) blockers.push('exact release commit SHA is required')
  if (!existsSync(authorizationPath)) blockers.push('independent review, drill, CI, artifact and owner authorization record is missing')
  else {
    const evidence = readJson(authorizationPath)
    if (evidence.schemaVersion !== 'armorbreak.v2.3-release-authorization/v1') blockers.push('release authorization schema mismatch')
    if (evidence.commit !== expectedSha) blockers.push('release authorization does not match the exact tag commit')
    if (evidence.reviewerType !== 'INDEPENDENT_HUMAN') blockers.push('independent human review is required')
    for (const key of ['securityReview', 'licenseReview', 'upgradeRollbackDrill', 'exactMainCi', 'artifactSha256', 'sbomSha256', 'attestation', 'maintainerAuthorization']) {
      if (!evidence[key] || evidence[key].status !== 'PASS') blockers.push(`${key} is not PASS`)
      if (evidence[key]?.path && !existsSync(resolve(evidence[key].path))) blockers.push(`${key} evidence path does not exist`)
      if (evidence[key]?.path && evidence[key]?.sha256) {
        const digest = createHash('sha256').update(readFileSync(resolve(evidence[key].path))).digest('hex')
        if (digest !== evidence[key].sha256) blockers.push(`${key} evidence SHA-256 mismatch`)
      }
    }
    if (evidence.maintainerAuthorization?.authorized !== true) blockers.push('explicit maintainer authorization is absent')
  }
  const result = { schemaVersion: 'armorbreak.v2.3-release-gate/v1', mode, tag, expectedSha: expectedSha || null, decision: blockers.length ? 'NOT_READY' : 'READY', blockers }
  console.log(JSON.stringify(result, null, 2))
  if (blockers.length) process.exitCode = 1
}
