/**
 * ABU-002/003: evidence-driven release gates.
 *
 * A gate is PASS only when all of its evidence files are hash-pinned in the
 * current-commit manifest, the raw test TAP is intact, and the domain-specific
 * predicate holds. Missing evidence is REVIEW; a hash/count mismatch is FAIL.
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { classifyDocsBaseline, classifyEvidenceOnly } from './evidenceValidator.js'
import { readSafeRepoFile } from './safeEvidenceFile.js'

export const EVIDENCE_DIR = 'docs/v2/acceptance'
export const REQUIRED_M4 = ['AB2-M4-03.md', 'AB2-M4-04.md', 'AB2-M4-06.md', 'AB2-M4-07.md', 'AB2-M4-10.md', 'AB2-M4-11.md', 'AB2-M4-12.md']
export const REQUIRED_TEST_PATTERNS = ['policy', 'approval']

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

export function readJson(repoRoot, relativePath) {
  try { return JSON.parse(readSafeRepoFile(repoRoot, relativePath, { requiredPrefix: EVIDENCE_DIR + '/' }).toString('utf8').replace(/^\uFEFF/, '')) } catch { return null }
}

export function parseTap(tap) {
  const count = (name) => Number(new RegExp(`^# ${name} (\\d+)$`, 'm').exec(tap)?.[1] ?? -1)
  return { tests: count('tests'), pass: count('pass'), fail: count('fail'), skipped: count('skipped'), cancelled: count('cancelled'), todo: count('todo') }
}

export function docsOnlyGateReport({ commit, baseCommit, baseReport, now = new Date().toISOString(), validation } = {}) {
  const baseReleasable = baseReport?.releasable === true
  return {
    schemaVersion: 'armorbreak.release-gates/v2',
    generatedAt: now,
    commit,
    baseCommit,
    mode: 'docs-only',
    applicability: 'DOCS_ONLY_BASE_GATES',
    releasable: baseReleasable,
    reason: baseReleasable
      ? 'target base release gates pass; docs-only head does not change source or evidence'
      : 'target base release gates are not releasable; docs-only head cannot bypass them',
    gates: baseReport?.gates,
    testReport: baseReport?.testReport,
    evidenceValidation: {
      ok: validation?.ok === true,
      mode: validation?.mode ?? null,
      checked: validation?.checked ?? 0,
      issues: validation?.issues ?? [],
    },
  }
}

function combine(base, specific) {
  if (base.status === 'FAIL' || specific.status === 'FAIL') return { ...specific, status: 'FAIL', reason: `${base.reason}${specific.reason ? `; ${specific.reason}` : ''}` }
  if (base.status === 'REVIEW' || specific.status === 'REVIEW') return { ...specific, status: 'REVIEW', reason: `${base.reason}${specific.reason ? `; ${specific.reason}` : ''}` }
  return specific
}

export function computeReleaseGates({ repoRoot = process.cwd(), commit, now = new Date().toISOString(), allowEvidenceAncestor = false, allowDocsAncestor = false } = {}) {
  if (!commit) throw new Error('commit is required')
  const manifest = readJson(repoRoot, `${EVIDENCE_DIR}/evidence-manifest.json`)
  const evidenceCommit = manifest?.commit ?? null
  const ancestorEvidence = allowEvidenceAncestor && evidenceCommit && evidenceCommit !== commit
    ? (allowDocsAncestor
      ? classifyDocsBaseline({ repoRoot, base: evidenceCommit, head: commit }).ok
      : classifyEvidenceOnly({ repoRoot, base: evidenceCommit, head: commit, allowReadiness: true }).ok)
    : false
  const manifestValid = Boolean(manifest && manifest.schemaVersion === 'armorbreak.evidence-manifest/v1' &&
    typeof manifest.files === 'object' && manifest.files !== null && !Array.isArray(manifest.files) &&
    (manifest.commit === commit || ancestorEvidence))
  const manifestReason = !manifest
    ? 'evidence manifest missing'
    : !manifestValid
      ? `evidence manifest commit ${manifest.commit ?? 'unknown'} does not match ${commit}`
      : ancestorEvidence
        ? `evidence manifest source ${manifest.commit} is an ancestor; only acceptance evidence follows it`
        : 'evidence manifest matches current commit'
  const evidenceFor = (name) => {
    const rel = `${EVIDENCE_DIR}/${name}`
    let bytes
    try { bytes = readSafeRepoFile(repoRoot, rel, { requiredPrefix: `${EVIDENCE_DIR}/` }) } catch (error) {
      if (error?.code === 'ENOENT') return { available: false, status: 'REVIEW', reason: `${name} missing` }
      return { available: false, status: 'FAIL', reason: `${name} is unsafe: ${error?.message ?? 'read failed'}` }
    }
    if (!manifestValid) return { available: false, status: 'REVIEW', reason: manifestReason }
    const recorded = manifest.files?.[rel]
    if (!recorded) return { available: false, status: 'REVIEW', reason: `${name} is not pinned in the evidence manifest` }
    const actual = createHash('sha256').update(bytes).digest('hex')
    if (!Number.isSafeInteger(recorded.size) || recorded.size !== bytes.length || actual !== recorded.sha256) {
      return { available: false, status: 'FAIL', reason: `${name} size/hash mismatch (tampered or stale)` }
    }
    return { available: true, status: 'PASS', reason: `${name} pinned`, path: rel, sha256: actual, size: bytes.length }
  }
  const evidenceStatus = (files) => {
    const entries = files.map((name) => [name, evidenceFor(name)])
    const bad = entries.find(([, entry]) => entry.status !== 'PASS')
    return { entries, status: bad ? bad[1].status : 'PASS', reason: bad ? bad[1].reason : 'all evidence pinned' }
  }

  const reportFile = `${EVIDENCE_DIR}/test-report.json`
  const tapFile = `${EVIDENCE_DIR}/test-report.tap`
  let reportBytes = null
  let tapBytes = null
  let reportPathError = null
  try { reportBytes = readSafeRepoFile(repoRoot, reportFile, { requiredPrefix: `${EVIDENCE_DIR}/` }) } catch (error) { reportPathError = error }
  try { tapBytes = readSafeRepoFile(repoRoot, tapFile, { requiredPrefix: `${EVIDENCE_DIR}/` }) } catch (error) { if (!reportPathError) reportPathError = error }
  let testReport = null
  try { if (reportBytes) testReport = JSON.parse(reportBytes.toString('utf8').replace(/^\uFEFF/, '')) } catch { /* invalid report remains REVIEW below */ }
  let testStatus = 'PASS'
  let testReason = 'test report and raw TAP pinned'
  let counts = { tests: -1, pass: -1, fail: -1, skipped: -1, cancelled: -1, todo: -1 }
  let tap = ''
  if (!testReport) { testStatus = reportPathError?.code === 'EVIDENCE_PATH_UNSAFE' ? 'FAIL' : 'REVIEW'; testReason = reportPathError ? `test report missing or unsafe: ${reportPathError.message}` : 'test report missing or invalid' }
  else if (!tapBytes) { testStatus = reportPathError?.code === 'EVIDENCE_PATH_UNSAFE' ? 'FAIL' : 'REVIEW'; testReason = reportPathError ? `raw TAP missing or unsafe: ${reportPathError.message}` : 'raw TAP missing' }
  else if (testReport.commit !== commit && !ancestorEvidence) { testStatus = 'REVIEW'; testReason = `test report commit ${testReport.commit} is stale` }
  else if (testReport.schemaVersion !== 'armorbreak.test-report/v1' || testReport.exitCode !== 0) { testStatus = 'FAIL'; testReason = 'test report schema or process exit status is invalid' }
  else if (testReport.command !== 'node --test --test-reporter=tap --test-concurrency=1' || testReport.processError !== null || testReport.signal !== null) { testStatus = 'FAIL'; testReason = 'test report does not prove a normally completed Node test process' }
  else if (testReport.tapPath !== tapFile || testReport.tapSha256 !== createHash('sha256').update(tapBytes).digest('hex')) { testStatus = 'FAIL'; testReason = 'raw TAP path/hash does not match test report' }
  else {
    tap = tapBytes.toString('utf8')
    counts = parseTap(tap)
    const countKeys = ['tests', 'pass', 'fail', 'skipped', 'cancelled', 'todo']
    if (!testReport.counts || countKeys.some((key) => !Number.isSafeInteger(testReport.counts[key]) || testReport.counts[key] < 0) ||
        countKeys.some((key) => testReport.counts[key] !== counts[key])) {
      testStatus = 'FAIL'; testReason = 'test report counts do not match raw TAP'
    } else if (counts.tests <= 0 || counts.fail !== 0 || counts.cancelled !== 0 || counts.todo !== 0) {
      testStatus = 'FAIL'; testReason = `tests not green: ${JSON.stringify(counts)}`
    } else if (counts.skipped !== 0) {
      testStatus = 'REVIEW'; testReason = `tests skipped (${counts.skipped}); skipped tests cannot count as PASS`
    } else if (counts.pass !== counts.tests) {
      testStatus = 'FAIL'; testReason = `tests not fully passed: ${JSON.stringify(counts)}`
    } else if (!REQUIRED_TEST_PATTERNS.every((pattern) => tap.toLowerCase().includes(pattern))) {
      testStatus = 'REVIEW'; testReason = `required security tests not found in TAP: ${REQUIRED_TEST_PATTERNS.join(', ')}`
    }
  }
  const testEvidence = evidenceStatus(['test-report.json', 'test-report.tap'])
  const testBase = { status: testStatus, reason: testReason, evidence: [{ path: reportFile, ...(reportBytes ? { sha256: createHash('sha256').update(reportBytes).digest('hex') } : {}) }, { path: tapFile }] }

  const security = combine(testBase, { status: testEvidence.status, reason: testEvidence.reason })

  const offline = combine(testBase, (() => {
    const evidence = evidenceStatus(['airgap-container.json', 'offline-score.json'])
    if (evidence.status !== 'PASS') return evidence
    const airgap = readJson(repoRoot, `${EVIDENCE_DIR}/airgap-container.json`)
    const score = readJson(repoRoot, `${EVIDENCE_DIR}/offline-score.json`)
    const pass = airgap?.result === 'PASS' && score?.summary?.targetPass === 62
    return { status: pass ? 'PASS' : 'FAIL', reason: pass ? 'airgap + 62/62 offline target' : 'offline evidence predicates failed', evidence: evidence.entries.map(([, entry]) => entry) }
  })())

  const supplyChain = combine(testBase, (() => {
    const evidence = evidenceStatus(['supplychain-e2e.json', 'supplychain-live.json'])
    if (evidence.status !== 'PASS') return evidence
    const e2e = readJson(repoRoot, `${EVIDENCE_DIR}/supplychain-e2e.json`)
    const live = readJson(repoRoot, `${EVIDENCE_DIR}/supplychain-live.json`)
    const pass = e2e?.result === 'PASS' && live?.result === 'PASS'
    return { status: pass ? 'PASS' : 'FAIL', reason: pass ? 'signed index + installer rollback + live supply-chain' : 'supply-chain evidence predicates failed', evidence: evidence.entries.map(([, entry]) => entry) }
  })())

  const aiEvaluation = combine(testBase, (() => {
    const evidence = evidenceStatus(['garak-live.json', 'pyrit-live.json', 'jailbreak-live.json'])
    if (evidence.status !== 'PASS') return evidence
    const garak = readJson(repoRoot, `${EVIDENCE_DIR}/garak-live.json`)
    const pyrit = readJson(repoRoot, `${EVIDENCE_DIR}/pyrit-live.json`)
    const jailbreak = readJson(repoRoot, `${EVIDENCE_DIR}/jailbreak-live.json`)
    const pass = garak?.status === 'PASS' && pyrit?.result === 'PASS' && jailbreak?.result === 'PASS'
    return { status: pass ? 'PASS' : 'FAIL', reason: pass ? 'Garak/PyRIT/JailbreakBench evidence PASS; mock/local endpoint only' : 'AISEC evidence predicates failed', evidence: evidence.entries.map(([, entry]) => entry) }
  })())

  const compatibility = combine(testBase, (() => {
    const evidence = evidenceStatus(['desktop-e2e.json', 'desktop-analysis.json', 'desktop-e2e.md'])
    if (evidence.status !== 'PASS') return evidence
    const e2e = readJson(repoRoot, `${EVIDENCE_DIR}/desktop-e2e.json`)
    const analysis = readJson(repoRoot, `${EVIDENCE_DIR}/desktop-analysis.json`)
    const screenshots = Array.isArray(e2e?.screenshots) ? e2e.screenshots : []
    const badShot = screenshots.find((shot) => {
      const rel = shot.path
      if (typeof rel !== 'string' || rel.includes('\\') || !rel.startsWith(`${EVIDENCE_DIR}/`) || rel.split('/').includes('..')) return true
      try {
        const bytes = readSafeRepoFile(repoRoot, rel, { requiredPrefix: `${EVIDENCE_DIR}/` })
        return createHash('sha256').update(bytes).digest('hex') !== shot.sha256
      } catch { return true }
    })
    const pass = e2e?.result === 'PASS' && analysis?.result === 'PASS' && e2e?.l0Task?.reportSha256 && screenshots.length >= 3 && !badShot
    return { status: pass ? 'PASS' : 'FAIL', reason: pass ? 'real Desktop health + L0 report/screenshot hashes' : `desktop evidence predicates failed${badShot ? ` (${badShot.path})` : ''}`, evidence: evidence.entries.map(([, entry]) => entry) }
  })())

  const performance = combine(testBase, (() => {
    const evidence = evidenceStatus(['performance-compare.json'])
    if (evidence.status !== 'PASS') return evidence
    const compare = readJson(repoRoot, `${EVIDENCE_DIR}/performance-compare.json`)
    const pass = compare && Array.isArray(compare.regressionsOver10Percent) && compare.regressionsOver10Percent.length === 0
    return { status: pass ? 'PASS' : 'FAIL', reason: pass ? 'no >10% regression' : 'performance regression or missing comparison data', evidence: evidence.entries.map(([, entry]) => entry) }
  })())

  const mandatory = REQUIRED_M4.map((file) => {
    let status = 'MISSING'
    try { status = /^status:\s*(\S+)/m.exec(readSafeRepoFile(repoRoot, `docs/v2/tasks/${file}`, { requiredPrefix: 'docs/v2/tasks/' }).toString('utf8'))?.[1] ?? 'UNKNOWN' } catch { /* missing or unsafe */ }
    return { file, status }
  })
  const gates = { security, offline, supplyChain, aiEvaluation, compatibility, performance }
  const allPass = Object.values(gates).every((gate) => gate.status === 'PASS')
  const mandatoryDone = mandatory.every((task) => task.status === 'DONE')
  return {
    schemaVersion: 'armorbreak.release-gates/v2',
    generatedAt: now,
    commit,
    evidenceManifest: { commit: manifest?.commit ?? null, currentCommit: commit, valid: manifestValid, ancestorEvidence, reason: manifestReason },
    testReport: { ...counts, status: testStatus, reason: testReason },
    gates,
    mandatoryM4: mandatory,
    releasable: allPass && mandatoryDone,
    reason: allPass && mandatoryDone
      ? 'all gates are evidence-verified and mandatory M4 tasks are DONE'
      : `blocked: gates=${Object.entries(gates).filter(([, gate]) => gate.status !== 'PASS').map(([name]) => name).join(',')}; mandatory=${mandatory.filter((task) => task.status !== 'DONE').map((task) => task.file).join(',')}`,
  }
}
