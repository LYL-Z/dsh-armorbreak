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
const blockers = []
for (const id of required) {
  try {
    const text = readFileSync(resolve(root, `docs/v2/tasks/${id}.md`), 'utf8')
    const status = /^status:\s*(\S+)/m.exec(text)?.[1] ?? 'NOT_STARTED'
    taskStatus[id] = status
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
  for (const host of ['Claude Code', 'Cursor', 'WorkBuddy', 'ZCode', 'Pi', 'TRAE']) {
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
const report = {
  schemaVersion: 'armorbreak.v2-readiness/v1',
  commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
  ready: blockers.length === 0 && !releaseTag,
  releaseTag,
  taskStatus,
  blockers,
  artifact: artifact ? { version: artifact.version, signed: artifact.signed, sha256: artifact.sha256 } : null,
}
console.log(JSON.stringify(report, null, 2))
if (process.argv.includes('--write')) {
  writeFileSync(resolve(root, 'docs/v2/acceptance/v2.2-readiness.json'), `${JSON.stringify(report, null, 2)}\n`)
}
if (process.argv.includes('--require-ready') && !report.ready) process.exitCode = 1
