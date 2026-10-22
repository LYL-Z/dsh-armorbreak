#!/usr/bin/env node
/**
 * V2.2 readiness gate. This is deliberately conservative: a task must be
 * TESTED/HOST_VERIFIED/RELEASED, host evidence must be explicit, and the
 * portable artifact must be signed before GA can be claimed.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const rank = { NOT_STARTED: 0, IN_PROGRESS: 1, IMPLEMENTED: 2, TESTED: 3, HOST_VERIFIED: 4, RELEASED: 5, BLOCKED: -1 }
const required = ["ABU-101","ABU-102","ABU-103","ABU-104","ABU-105","ABU-106","ABU-107","ABU-108","ABU-109","ABU-201","ABU-202","ABU-203","ABU-204","ABU-205","ABU-206","ABU-207","ABU-208","ABU-209","ABU-210","ABU-211","ABU-301","ABU-302","ABU-303","ABU-304","ABU-305","ABU-306","ABU-307","ABU-308","ABU-309","ABU-310","ABU-311","ABU-312","ABU-313","ABU-314","ABU-315","ABU-316","ABU-317","ABU-318","ABU-401","ABU-402","ABU-403","ABU-404","ABU-405","ABU-406","ABU-407","ABU-408","ABU-409"]
const taskStatus = {}
const taskRealEndpoint = {}
const taskIndependentReview = {}
const taskHostInstall = {}
const taskProductionSignature = {}
const blockers = []
for (const id of required) {
  try {
    const text = readFileSync(resolve(root, `docs/v2/tasks/${id}.md`), 'utf8')
    const status = /^status:\s*(\S+)/m.exec(text)?.[1] ?? 'NOT_STARTED'
    const realEndpoint = /^realEndpoint:\s*(\S+)/m.exec(text)?.[1] ?? null
    const independentReview = /^independentReview:\s*(\S+)/m.exec(text)?.[1] ?? null
    const hostInstall = /^hostInstall:\s*(\S+)/m.exec(text)?.[1] ?? null
    const productionSignature = /^productionSignature:\s*(\S+)/m.exec(text)?.[1] ?? null
    taskStatus[id] = status
    taskRealEndpoint[id] = realEndpoint
    taskIndependentReview[id] = independentReview
    taskHostInstall[id] = hostInstall
    taskProductionSignature[id] = productionSignature
    if (rank[status] === undefined || rank[status] < rank.TESTED) blockers.push({ code: `${id}_NOT_TESTED`, detail: `${id} status=${status}` })
  } catch {
    taskStatus[id] = 'MISSING'
    blockers.push({ code: `${id}_MISSING`, detail: 'task file missing' })
  }
}
let matrix
try {
  matrix = JSON.parse(readFileSync(resolve(root, 'docs/v2/acceptance/compatibility-matrix.json'), 'utf8'))
} catch {
  blockers.push({ code: 'HOST_MATRIX_MISSING', detail: 'compatibility matrix missing' })
}
if (matrix) {
  for (const host of ['DSH', 'Codex', 'Hermes Agent']) {
    const row = matrix.hosts.find((item) => item.host === host)
    if (!row || row.taskRunState !== 'L0_COMPLETED') blockers.push({ code: `HOST_${host}_NO_L0`, detail: `${host} has no L0 completion` })
  }
  for (const host of ['Claude Code', 'Cursor', 'WorkBuddy', 'ZCode', 'Pi', 'TRAE', 'Antigravity']) {
    const row = matrix.hosts.find((item) => item.host === host)
    if (!row || row.taskRunState !== 'L0_COMPLETED') blockers.push({ code: `HOST_${host}_NOT_VERIFIED`, detail: `${host} integration is not host-verified` })
  }
}
let artifact
try {
  artifact = JSON.parse(readFileSync(resolve(root, 'docs/v2/acceptance/portable-artifact.json'), 'utf8'))
  if (artifact.signed !== true) blockers.push({ code: 'ARTIFACT_UNSIGNED', detail: 'portable artifact has no production signature' })
  if (artifact.cleanRoom?.result !== 'PASS') blockers.push({ code: 'ARTIFACT_CLEANROOM', detail: 'clean-room check not PASS' })
} catch {
  blockers.push({ code: 'ARTIFACT_EVIDENCE_MISSING', detail: 'portable artifact evidence missing' })
}
let tags = []
try { tags = execFileSync('git', ['tag', '--list'], { cwd: root, encoding: 'utf8' }).trim().split(/\r?\n/).filter(Boolean) } catch { /* git may be absent in a source archive */ }
const releaseTag = tags.includes('v2.2.0')
const preReleaseTag = tags.includes('v2.2.0-owner-waiver')
const noWaivers = process.argv.includes('--no-waivers')
let waiverDoc = null
let waiverCodes = new Set()
if (!noWaivers) {
  try {
    waiverDoc = JSON.parse(readFileSync(resolve(root, 'docs/v2/release/waivers.json'), 'utf8'))
    const signoff = JSON.parse(readFileSync(resolve(root, 'docs/v2/acceptance/signoff.json'), 'utf8'))
    const ownerMatches = waiverDoc.approvedBy && signoff.signer === waiverDoc.approvedBy
    if (ownerMatches && signoff.independent === false && Array.isArray(waiverDoc.waivers)) {
      waiverCodes = new Set(waiverDoc.waivers.map((item) => item.code))
    } else {
      waiverDoc = null
    }
  } catch { waiverDoc = null }
}
const activeBlockers = blockers.filter((blocker) => !waiverCodes.has(blocker.code))
const waived = blockers.filter((blocker) => waiverCodes.has(blocker.code))
const realEndpointBlockers = Object.entries(taskRealEndpoint)
  .filter(([, value]) => value === 'BLOCKED_EXTERNAL')
  .map(([id]) => ({ code: `${id}_REAL_ENDPOINT_BLOCKED`, detail: `${id} real endpoint is BLOCKED_EXTERNAL` }))
const independentReviewBlockers = Object.entries(taskIndependentReview)
  .filter(([, value]) => value === 'BLOCKED_EXTERNAL')
  .map(([id]) => ({ code: `${id}_INDEPENDENT_REVIEW_BLOCKED`, detail: `${id} independent review is BLOCKED_EXTERNAL` }))
const hostInstallBlockers = Object.entries(taskHostInstall)
  .filter(([, value]) => value === 'BLOCKED_EXTERNAL')
  .map(([id]) => ({ code: `${id}_HOST_INSTALL_BLOCKED`, detail: `${id} real host install is BLOCKED_EXTERNAL` }))
const productionSignatureBlockers = Object.entries(taskProductionSignature)
  .filter(([, value]) => value === 'BLOCKED_EXTERNAL')
  .map(([id]) => ({ code: `${id}_PRODUCTION_SIGNATURE_BLOCKED`, detail: `${id} production signature is BLOCKED_EXTERNAL` }))
const gaBlockers = [...blockers, ...waived, ...realEndpointBlockers, ...independentReviewBlockers, ...hostInstallBlockers, ...productionSignatureBlockers]
if (artifact?.signed !== true) gaBlockers.push({ code: 'ARTIFACT_UNSIGNED', detail: 'portable artifact has no production signature' })
const uniqueGaBlockers = [...new Map(gaBlockers.map((item) => [item.code, item])).values()]
const preReleaseReady = activeBlockers.length === 0
const gaReady = uniqueGaBlockers.length === 0 && !releaseTag
const report = {
  schemaVersion: 'armorbreak.v2-readiness/v1',
  commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
  preReleaseReady,
  gaReady,
  ready: preReleaseReady,
  preReleaseTag,
  releaseTag,
  taskStatus,
  taskRealEndpoint,
  taskIndependentReview,
  taskHostInstall,
  taskProductionSignature,
  blockers: activeBlockers,
  gaBlockers: uniqueGaBlockers,
  waived,
  waiver: waiverDoc ? { approvedBy: waiverDoc.approvedBy, approvedAt: waiverDoc.approvedAt, independentReview: waiverDoc.independentReview, count: waived.length, ref: 'docs/v2/release/waivers.json' } : null,
  artifact: artifact ? { version: artifact.version, signed: artifact.signed, sha256: artifact.sha256 } : null,
}
console.log(JSON.stringify(report, null, 2))
if (process.argv.includes('--write')) {
  writeFileSync(resolve(root, 'docs/v2/acceptance/v2.2-readiness.json'), `${JSON.stringify(report, null, 2)}\n`)
}
if (process.argv.includes('--require-ready') && !report.preReleaseReady) process.exitCode = 1
if (process.argv.includes('--require-ga') && !report.gaReady) process.exitCode = 1
