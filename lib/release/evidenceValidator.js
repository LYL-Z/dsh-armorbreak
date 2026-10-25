/** ABU-006: validate pinned evidence, raw test TAP, and Desktop evidence references. */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readSafeRepoFile } from './safeEvidenceFile.js'

const sha = (buffer) => createHash('sha256').update(buffer).digest('hex')
const SHA256 = /^[a-f0-9]{64}$/i
const COMMIT_SHA = /^[a-f0-9]{40}$/i
const ACCEPTANCE = 'docs/v2/acceptance/'
const READINESS_PATHS = new Set(['docs/v2/release/readiness.json', 'docs/v2/release/stable-readiness.json'])

function readOptional(repoRoot, path, issues, label = path) {
  try {
    return readSafeRepoFile(repoRoot, path, { requiredPrefix: ACCEPTANCE })
  } catch (error) {
    if (error?.code === 'ENOENT') return null
    issues.push(`${label}: ${error?.message ?? 'unsafe path'}`)
    return null
  }
}

function parseTapCounts(buffer) {
  const text = buffer.toString('utf8')
  const count = (name) => {
    const match = new RegExp(`^# ${name} (\\d+)$`, 'm').exec(text)
    return match ? Number(match[1]) : null
  }
  return { tests: count('tests'), pass: count('pass'), fail: count('fail'), skipped: count('skipped'), cancelled: count('cancelled'), todo: count('todo') }
}

const PROTECTED_DOC_PREFIXES = [
  'docs/acceptance/',
  'docs/audit/',
  'docs/releases/',
  'docs/v2/acceptance/',
  'docs/v2/tasks/',
  'docs/v2/generated/',
  'docs/v2/security/',
]
const PROTECTED_DOC_FILES = new Set([
  'SECURITY.md',
  'docs/security-model.md',
  'docs/security-boundary-review.md',
  'docs/v2/threat-model.md',
  'docs/v2/aisec-threat-map.md',
  'docs/v2/aisec-worker-protocol.md',
  'docs/v2/provider-security.md',
])
const PROTECTED_DOC_PATTERNS = [/^docs\/acceptance(?:-.*)?\.md$/]

function git(repoRoot, args) {
  return execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim()
}

function isDocsOnlyPath(path) {
  if (path.includes('\\')) return false
  if (/^README(?:\.[A-Za-z0-9._-]+)?\.md$/.test(path)) return true
  if (!path.startsWith('docs/') || !path.endsWith('.md')) return false
  if (PROTECTED_DOC_PREFIXES.some((prefix) => path.startsWith(prefix))) return false
  if (PROTECTED_DOC_FILES.has(path)) return false
  if (PROTECTED_DOC_PATTERNS.some((pattern) => pattern.test(path))) return false
  if (path.startsWith('docs/v2/release/') && path !== 'docs/v2/release/user-guide.md') return false
  return true
}

function changedPaths(repoRoot, base, head) {
  const output = execFileSync('git', ['-C', repoRoot, 'diff', '--name-only', '--no-renames', '-z', `${base}..${head}`], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  })
  return output.split('\0').filter(Boolean)
}

function fileEntryKind(repoRoot, head, path) {
  try {
    const output = git(repoRoot, ['ls-tree', '-z', head, '--', path])
    if (!output) return 'missing'
    const mode = output.split('\0')[0].split(' ')[0]
    if (mode === '100644' || mode === '100755') return 'regular'
    if (mode === '120000') return 'symlink'
    if (mode === '160000') return 'gitlink'
    return 'other'
  } catch {
    return 'missing'
  }
}

function createCommittedFileResolver(repoRoot, commit) {
  let entriesByPath = null
  let blobs = null
  let changedPaths = null
  function load() {
    if (blobs) return
    if (!COMMIT_SHA.test(commit)) throw new Error('evidence source commit is invalid')
    const tree = execFileSync('git', ['-C', repoRoot, 'ls-tree', '-rz', '-r', '--full-tree', commit], {
      maxBuffer: 256 * 1024 * 1024,
    }).toString('utf8')
    const entries = new Map()
    for (const record of tree.split('\0')) {
      if (!record) continue
      const separator = record.indexOf('\t')
      if (separator < 0) throw new Error('pinned Git tree contains an invalid entry')
      const [mode, type, oid] = record.slice(0, separator).split(' ')
      entries.set(record.slice(separator + 1), { mode, type, oid })
    }
    changedPaths = new Set(execFileSync('git', ['-C', repoRoot, 'diff', '--name-only', '--no-renames', '-z', commit, '--'], {
      maxBuffer: 256 * 1024 * 1024,
    }).toString('utf8').split('\0').filter(Boolean))
    const oids = [...new Set([...entries.values()]
      .filter((entry) => entry.type === 'blob' && ['100644', '100755'].includes(entry.mode) && /^[a-f0-9]{40}$/i.test(entry.oid))
      .map((entry) => entry.oid))]
    const output = execFileSync('git', ['-C', repoRoot, 'cat-file', '--batch'], {
      input: `${oids.join('\n')}\n`,
      maxBuffer: 256 * 1024 * 1024,
    })
    blobs = new Map()
    let offset = 0
    for (const oid of oids) {
      const headerEnd = output.indexOf(0x0a, offset)
      if (headerEnd < 0) throw new Error('pinned Git blob response header is incomplete')
      const [actualOid, type, sizeText] = output.subarray(offset, headerEnd).toString('ascii').split(' ')
      const size = Number(sizeText)
      if (actualOid !== oid || type !== 'blob' || !Number.isSafeInteger(size) || size < 0) {
        throw new Error('pinned Git blob response metadata is invalid')
      }
      const start = headerEnd + 1
      const end = start + size
      if (end >= output.length || output[end] !== 0x0a) throw new Error('pinned Git blob response is truncated')
      blobs.set(oid, output.subarray(start, end))
      offset = end + 1
    }
    if (offset !== output.length) throw new Error('pinned Git blob response contains trailing bytes')
    entriesByPath = entries
  }
  return (path) => {
    load()
    const entry = entriesByPath.get(path)
    if (!entry || entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode) || !/^[a-f0-9]{40}$/i.test(entry.oid)) {
      throw new Error(`evidence source is not a regular file in its pinned commit: ${path}`)
    }
    if (changedPaths.has(path)) throw new Error(`evidence source differs from its pinned commit: ${path}`)
    const bytes = blobs.get(entry.oid)
    if (!bytes) throw new Error(`evidence source blob is missing from the pinned tree: ${path}`)
    return bytes
  }
}

const DIRECT_REFERENCE_KEYS = new Set([
  'audit', 'auditLog', 'committedCopy', 'evidence', 'evidenceId', 'evidencePath', 'path', 'report', 'source', 'tapPath',
])
const DERIVED_EVIDENCE_PATHS = new Set([
  `${ACCEPTANCE}evidence-manifest.json`,
  `${ACCEPTANCE}release-gates.json`,
  `${ACCEPTANCE}release-smoke.json`,
])

function looksLikeFileReference(value) {
  return typeof value === 'string' && value.length > 0 && !/\s/.test(value) && /\.[a-z0-9]{1,12}$/i.test(value)
}

function isExternalReference(value) {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value) || /^[a-z]:[\\/]/i.test(value) || value.startsWith('/') || value.startsWith('\\\\')
}

function validateEmbeddedReferences({ repoRoot, documentPath, document, manifest, committedFile, issues }) {
  const checked = new Set()

  function check(rawPath, label, embedded = {}) {
    if (typeof rawPath !== 'string' || !rawPath || isExternalReference(rawPath)) return
    const normalized = rawPath.replaceAll('\\', '/')
    if (normalized.startsWith(ACCEPTANCE)) {
      if (looksLikeFileReference(normalized)) checkCandidate(normalized, true, label, embedded)
      return
    }
    if (rawPath.includes('\\')) return
    if (!looksLikeFileReference(rawPath)) return
    const documentDirectory = documentPath.slice(0, documentPath.lastIndexOf('/'))
    const documentRelative = rawPath.startsWith('./') ? rawPath.slice(2) : rawPath
    const candidates = [...new Set([
      documentDirectory ? `${documentDirectory}/${documentRelative}` : documentRelative,
      `${ACCEPTANCE}${documentRelative}`,
      documentRelative,
    ])]
    for (let index = 0; index < candidates.length; index += 1) {
      const found = checkCandidate(candidates[index], candidates[index].startsWith(ACCEPTANCE), label, embedded, index < candidates.length - 1)
      if (found) return
    }
  }

  function checkCandidate(candidate, acceptancePath, label, embedded, fallback = false) {
    const key = `${label}\0${candidate}`
    if (checked.has(key)) return true
    checked.add(key)
    let bytes
    try {
      const worktreeBytes = readSafeRepoFile(repoRoot, candidate, acceptancePath ? { requiredPrefix: ACCEPTANCE } : {})
      bytes = !acceptancePath && (embedded.sha256 !== undefined || embedded.size !== undefined)
        ? committedFile(candidate)
        : worktreeBytes
    } catch (error) {
      if (error?.code === 'ENOENT' && fallback) return
      issues.push(`${documentPath}: referenced evidence path is missing or unsafe (${label}): ${candidate}: ${error?.message ?? 'read failed'}`)
      return true
    }

    if (acceptancePath) {
      const record = manifest.files?.[candidate]
      if (!record && !DERIVED_EVIDENCE_PATHS.has(candidate)) {
        issues.push(`${documentPath}: referenced acceptance file is not pinned in evidence-manifest.json: ${candidate}`)
      } else if (record && (!Number.isSafeInteger(record.size) || record.size !== bytes.length || typeof record.sha256 !== 'string' || sha(bytes) !== record.sha256.toLowerCase())) {
        issues.push(`${documentPath}: referenced acceptance file does not match its manifest record: ${candidate}`)
      }
    }
    if (embedded.sha256 !== undefined && (typeof embedded.sha256 !== 'string' || !SHA256.test(embedded.sha256) || sha(bytes) !== embedded.sha256.toLowerCase())) {
      issues.push(`${documentPath}: embedded SHA-256 mismatch for ${candidate}`)
    }
    if (embedded.size !== undefined && (!Number.isSafeInteger(embedded.size) || embedded.size !== bytes.length)) {
      issues.push(`${documentPath}: embedded byte size mismatch for ${candidate}`)
    }
    return true
  }

  function walk(value, key = '') {
    if (typeof value === 'string') {
      if ((value.startsWith(ACCEPTANCE) && looksLikeFileReference(value)) || (DIRECT_REFERENCE_KEYS.has(key) && looksLikeFileReference(value))) {
        check(value, key || 'reference')
      }
      return
    }
    if (!value || typeof value !== 'object') return
    if (Array.isArray(value)) {
      for (const item of value) walk(item, key)
      return
    }

    if (typeof value.path === 'string') check(value.path, 'path', { sha256: value.sha256, size: value.size })
    if (typeof value.evidencePath === 'string') check(value.evidencePath, 'evidencePath', { sha256: value.sha256, size: value.size })
    if (value.files && typeof value.files === 'object' && !Array.isArray(value.files)) {
      for (const [filePath, metadata] of Object.entries(value.files)) {
        if (looksLikeFileReference(filePath) && metadata && typeof metadata === 'object' && (metadata.sha256 !== undefined || metadata.size !== undefined)) {
          check(filePath, 'files', { sha256: metadata.sha256, size: metadata.size })
        }
      }
    }
    for (const [childKey, child] of Object.entries(value)) {
      if (childKey === 'path' || childKey === 'evidencePath' || childKey === 'sha256' || childKey === 'size' || childKey === 'files') continue
      walk(child, childKey)
    }
  }

  walk(document)
}

/**
 * A docs-only change may reuse a pinned evidence baseline only when every path
 * changed between the evidence commit and the target is an allowed Markdown
 * document. This is path-based: PR titles, labels, and commit messages are not
 * trusted. Git replace refs are rejected because they can rewrite history.
 */
export function classifyDocsOnly({ repoRoot = process.cwd(), base, head } = {}) {
  const issues = []
  const changed = []
  if (!base || !head) return { ok: false, base: base ?? null, head: head ?? null, changed, issues: ['base and head are required'] }
  try {
    if (process.env.GIT_REPLACE_REF_BASE) {
      issues.push('custom GIT_REPLACE_REF_BASE is not allowed for docs-only classification')
    }
    const replaceRefs = git(repoRoot, ['for-each-ref', '--format=%(refname)', 'refs/replace/'])
    if (replaceRefs) issues.push('git replace refs are not allowed for docs-only classification')
    git(repoRoot, ['rev-parse', '--verify', `${base}^{commit}`])
    git(repoRoot, ['rev-parse', '--verify', `${head}^{commit}`])
    git(repoRoot, ['merge-base', '--is-ancestor', base, head])
    changed.push(...changedPaths(repoRoot, base, head))
    if (changed.length === 0) issues.push('no changed files; docs-only classification requires at least one document change')
    for (const path of changed) {
      if (!isDocsOnlyPath(path)) {
        issues.push(`non-doc change is not eligible for docs-only evidence reuse: ${path}`)
      } else {
        const kind = fileEntryKind(repoRoot, head, path)
        if (kind === 'symlink' || kind === 'gitlink' || kind === 'other') {
          issues.push(`non-regular document entry is not eligible for docs-only reuse: ${path} (${kind})`)
        }
      }
    }
  } catch {
    issues.push('unable to classify docs-only change from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

/**
 * An evidence-only append is allowed only when every path changed after the
 * manifest's source commit is acceptance evidence or readiness metadata. The
 * source commit itself must remain the manifest baseline, and Git replace refs
 * are rejected just as in docs-only mode.
 */
export function classifyEvidenceOnly({ repoRoot = process.cwd(), base, head, allowReadiness = false } = {}) {
  const issues = []
  const changed = []
  if (!base || !head) return { ok: false, base: base ?? null, head: head ?? null, changed, issues: ['base and head are required'] }
  try {
    if (process.env.GIT_REPLACE_REF_BASE) {
      issues.push('custom GIT_REPLACE_REF_BASE is not allowed for evidence-only classification')
    }
    const replaceRefs = git(repoRoot, ['for-each-ref', '--format=%(refname)', 'refs/replace/'])
    if (replaceRefs) issues.push('git replace refs are not allowed for evidence-only classification')
    git(repoRoot, ['rev-parse', '--verify', `${base}^{commit}`])
    git(repoRoot, ['rev-parse', '--verify', `${head}^{commit}`])
    git(repoRoot, ['merge-base', '--is-ancestor', base, head])
    changed.push(...changedPaths(repoRoot, base, head))
    if (changed.length === 0) issues.push('no changed files; evidence-only append requires at least one evidence change')
    for (const path of changed) {
      if (!path.startsWith('docs/v2/acceptance/') && !(allowReadiness && READINESS_PATHS.has(path))) {
        issues.push(`non-evidence change is not eligible for evidence-only reuse: ${path}`)
      } else if (fileEntryKind(repoRoot, head, path) !== 'regular') {
        issues.push(`non-regular evidence entry is not eligible for evidence-only reuse: ${path}`)
      }
    }
  } catch {
    issues.push('unable to classify evidence-only change from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

/**
 * A target base may contain evidence commits and previously merged docs-only
 * changes, but no source/CI/build/security change after the manifest source.
 * This is the baseline condition for docs-only reuse.
 */
export function classifyDocsBaseline({ repoRoot = process.cwd(), base, head } = {}) {
  const issues = []
  const changed = []
  if (!base || !head) return { ok: false, base: base ?? null, head: head ?? null, changed, issues: ['base and head are required'] }
  try {
    if (process.env.GIT_REPLACE_REF_BASE) issues.push('custom GIT_REPLACE_REF_BASE is not allowed for docs baseline classification')
    if (git(repoRoot, ['for-each-ref', '--format=%(refname)', 'refs/replace/'])) issues.push('git replace refs are not allowed for docs baseline classification')
    git(repoRoot, ['rev-parse', '--verify', `${base}^{commit}`])
    git(repoRoot, ['rev-parse', '--verify', `${head}^{commit}`])
    git(repoRoot, ['merge-base', '--is-ancestor', base, head])
    changed.push(...changedPaths(repoRoot, base, head))
    for (const path of changed) {
      if (path.startsWith('docs/v2/acceptance/') || READINESS_PATHS.has(path)) {
        // readiness is generated acceptance metadata on the target branch;
        // docs-only gate evaluation still evaluates the base release gates.
        if (fileEntryKind(repoRoot, head, path) !== 'regular') issues.push(`non-regular acceptance metadata in target base: ${path}`)
        continue
      }
      if (!isDocsOnlyPath(path)) {
        issues.push(`target base has non-doc change after evidence: ${path}`)
        continue
      }
      const kind = fileEntryKind(repoRoot, head, path)
      if (kind === 'symlink' || kind === 'gitlink' || kind === 'other') issues.push(`non-regular document entry in target base: ${path} (${kind})`)
    }
  } catch {
    issues.push('unable to classify target-base changes from git history')
  }
  return { ok: issues.length === 0, base, head, changed, issues }
}

export function validateEvidence({ repoRoot = process.cwd(), commit, base, allowEvidenceAncestor = false, allowDocsOnly = false, allowReadiness = false, requireClean = false } = {}) {
  const issues = []
  if (requireClean) {
    try {
      if (git(repoRoot, ['status', '--porcelain'])) issues.push('working tree is dirty; evidence must be validated from a clean committed tree')
    } catch {
      issues.push('unable to verify clean working tree')
    }
  }

  const manifestPath = `${ACCEPTANCE}evidence-manifest.json`
  const manifestBytes = readOptional(repoRoot, manifestPath, issues)
  if (!manifestBytes) return { ok: false, issues: [...issues, 'evidence-manifest.json missing or unsafe'], checked: 0, mode: 'missing', docsOnly: null }
  let manifest
  try { manifest = JSON.parse(manifestBytes.toString('utf8')) } catch { return { ok: false, issues: [...issues, 'evidence-manifest.json is not valid JSON'], checked: 0, mode: 'invalid', docsOnly: null } }
  if (manifest.schemaVersion !== 'armorbreak.evidence-manifest/v1') issues.push('manifest schemaVersion is invalid')
  if (typeof manifest.commit !== 'string' || !COMMIT_SHA.test(manifest.commit)) issues.push('manifest commit is not a full Git commit SHA')
  if (!manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files)) issues.push('manifest files must be an object')
  for (const required of [`${ACCEPTANCE}test-report.json`, `${ACCEPTANCE}test-report.tap`]) {
    if (!manifest.files?.[required]) issues.push(`manifest missing required evidence: ${required}`)
  }

  const evidenceOnly = allowEvidenceAncestor && commit && manifest.commit !== commit
    ? classifyEvidenceOnly({ repoRoot, base: manifest.commit, head: commit, allowReadiness })
    : null
  const evidenceOnlyAccepted = evidenceOnly?.ok === true
  let readiness = null
  const appendedReadinessPath = evidenceOnly?.changed.find((path) => READINESS_PATHS.has(path))
  if (allowReadiness && appendedReadinessPath) {
    try {
      const bytes = readSafeRepoFile(repoRoot, appendedReadinessPath, { requiredPrefix: 'docs/v2/release/' })
      readiness = JSON.parse(bytes.toString('utf8'))
    } catch (error) {
      issues.push(`release readiness metadata is missing, invalid, or unsafe: ${error?.message ?? 'read failed'}`)
    }
  }
  const docsOnly = allowDocsOnly && commit && manifest.commit !== commit && !evidenceOnlyAccepted
    ? (base
      ? classifyDocsOnly({ repoRoot, base, head: commit })
      : { ok: false, base: null, head: commit, changed: [], issues: ['target branch base is required for docs-only evidence reuse'] })
    : null
  let docsOnlyAccepted = docsOnly?.ok === true
  let docsOnlyBase = null
  if (docsOnlyAccepted) {
    docsOnlyBase = manifest.commit === base
      ? { ok: true, base, changed: [], issues: [] }
      : classifyDocsBaseline({ repoRoot, base: manifest.commit, head: base })
    if (!docsOnlyBase.ok) {
      docsOnlyAccepted = false
      docsOnly.ok = false
      docsOnly.issues.push('target base contains source/security changes after the evidence baseline')
      issues.push('docs-only base is not evidence-backed: target base has unbound changes after the manifest source commit')
    }
  }
  const acceptedBaseline = manifest.commit === commit || evidenceOnlyAccepted || docsOnlyAccepted
  if (commit && manifest.commit !== commit && !acceptedBaseline) issues.push(`manifest commit ${manifest.commit} does not match ${commit}`)
  if (evidenceOnly && !evidenceOnly.ok && !docsOnlyAccepted) issues.push(...evidenceOnly.issues.map((issue) => `evidence-only: ${issue}`))
  if (docsOnly && !docsOnly.ok && !evidenceOnlyAccepted) issues.push(...docsOnly.issues.map((issue) => `docs-only: ${issue}`))

  let checked = 0
  const committedFile = createCommittedFileResolver(repoRoot, manifest.commit)
  const readFiles = new Map([[manifestPath, manifestBytes]])
  for (const [rel, record] of Object.entries(manifest.files ?? {})) {
    let bytes
    try {
      bytes = readSafeRepoFile(repoRoot, rel, { requiredPrefix: ACCEPTANCE })
    } catch (error) {
      issues.push(`${rel} is missing or unsafe: ${error?.message ?? 'read failed'}`)
      continue
    }
    readFiles.set(rel, bytes)
    if (!record || !Number.isSafeInteger(record.size) || record.size < 0 || typeof record.sha256 !== 'string' || !SHA256.test(record.sha256)) {
      issues.push(`${rel} has an invalid manifest record`)
      continue
    }
    if (bytes.length !== record.size) { issues.push(`${rel} size mismatch`); continue }
    if (sha(bytes) !== record.sha256.toLowerCase()) { issues.push(`${rel} hash mismatch`); continue }
    checked += 1
  }

  for (const [rel, bytes] of readFiles) {
    if (!rel.startsWith(ACCEPTANCE) || !rel.endsWith('.json') || rel === manifestPath) continue
    try {
      validateEmbeddedReferences({
        repoRoot,
        documentPath: rel,
        document: JSON.parse(bytes.toString('utf8')),
        manifest,
        committedFile,
        issues,
      })
    } catch {
      // Other evidence schemas may contain non-JSON or legacy JSON payloads;
      // dedicated validators remain responsible for their parsing rules.
    }
  }

  const reportPath = `${ACCEPTANCE}test-report.json`
  const tapPath = `${ACCEPTANCE}test-report.tap`
  const reportBytes = readFiles.get(reportPath) ?? readOptional(repoRoot, reportPath, issues)
  const tapBytes = readFiles.get(tapPath) ?? readOptional(repoRoot, tapPath, issues)
  if (!reportBytes || !tapBytes) issues.push('test report/TAP missing or unsafe')
  else {
    let report = null
    try { report = JSON.parse(reportBytes.toString('utf8')) } catch { issues.push('test report is not valid JSON') }
    if (report) {
      if (report.schemaVersion !== 'armorbreak.test-report/v1') issues.push('test report schemaVersion is invalid')
      if (typeof report.commit !== 'string' || !COMMIT_SHA.test(report.commit)) issues.push('test report commit is not a full Git commit SHA')
      if (report.exitCode !== 0) issues.push('test report exitCode is not zero')
      if (report.command !== 'node --test --test-reporter=tap --test-concurrency=1' || report.processError !== null || report.signal !== null) {
        issues.push('test report does not prove a normally completed Node test process')
      }
      if (report.tapPath !== tapPath) issues.push('test report tapPath does not name the pinned TAP file')
      if (typeof report.tapSha256 !== 'string' || !SHA256.test(report.tapSha256) || report.tapSha256.toLowerCase() !== sha(tapBytes)) {
        issues.push('test report TAP hash mismatch')
      }
      const names = ['tests', 'pass', 'fail', 'skipped', 'cancelled', 'todo']
      const counts = report.counts
      if (!counts || names.some((name) => !Number.isSafeInteger(counts[name]) || counts[name] < 0)) {
        issues.push('test report counts are incomplete or invalid')
      } else {
        const tapCounts = parseTapCounts(tapBytes)
        for (const name of names) if (tapCounts[name] !== counts[name]) issues.push(`test report ${name} count does not match raw TAP`)
        if (counts.fail !== 0 || counts.cancelled !== 0 || counts.todo !== 0 || counts.skipped !== 0 || counts.pass !== counts.tests) {
          issues.push('test report includes failed, skipped, cancelled, todo, or unpassed tests; these cannot count as PASS')
        }
        if (readiness) {
          if (readiness.schemaVersion !== 'armorbreak.release-readiness/v1') issues.push('release readiness schemaVersion is invalid')
          if (readiness.commit !== manifest.commit || readiness.evidence?.manifestCommit !== manifest.commit || readiness.evidence?.testReportCommit !== manifest.commit) {
            issues.push('release readiness metadata does not identify the pinned test source commit')
          }
          if (readiness.evaluatedAtCommit !== commit && readiness.evaluatedAtCommit !== manifest.commit) {
            issues.push('release readiness was evaluated against an unrelated commit')
          }
          if (readiness.evidence?.current !== true || readiness.evidence?.checks?.manifestValid !== true ||
              readiness.evidence?.checks?.evidenceLineage !== true || readiness.evidence?.checks?.testsPassed !== true ||
              readiness.evidence?.checks?.gatesValid !== true || names.some((name) => readiness.evidence?.testCounts?.[name] !== counts[name])) {
            issues.push('release readiness evidence checks do not match the pinned test report')
          }
          if (typeof readiness.ready !== 'boolean' || !Array.isArray(readiness.incomplete) || typeof readiness.sbom !== 'boolean') {
            issues.push('release readiness status fields are incomplete')
          }
        }
      }
      const reportAncestor = report.commit === commit ||
        ((evidenceOnlyAccepted || docsOnlyAccepted) && report.commit === manifest.commit)
      if (commit && report.commit !== commit && !reportAncestor) issues.push('test report commit is stale')
    }
  }

  const desktopPath = `${ACCEPTANCE}desktop-e2e.json`
  const desktopBytes = readOptional(repoRoot, desktopPath, issues)
  if (desktopBytes) {
    let desktop = null
    try { desktop = JSON.parse(desktopBytes.toString('utf8')) } catch { issues.push('desktop E2E evidence is not valid JSON') }
    if (desktop) {
      if (desktop.screenshots !== undefined && !Array.isArray(desktop.screenshots)) issues.push('desktop screenshots must be an array')
      for (const shot of desktop.screenshots ?? []) {
        const rel = shot.path
        if (typeof rel !== 'string') { issues.push('desktop screenshot path is invalid'); continue }
        let bytes
        try { bytes = readSafeRepoFile(repoRoot, rel, { requiredPrefix: ACCEPTANCE }) } catch (error) {
          issues.push(`desktop screenshot missing or unsafe: ${rel}: ${error?.message ?? 'read failed'}`)
          continue
        }
        if (typeof shot.sha256 !== 'string' || !SHA256.test(shot.sha256) || sha(bytes) !== shot.sha256.toLowerCase()) {
          issues.push(`desktop screenshot hash mismatch: ${rel}`)
        }
      }
      const copy = `${ACCEPTANCE}desktop-l0-report.md`
      if (desktop.l0Task?.reportSha256) {
        const reportCopy = readOptional(repoRoot, copy, issues, 'desktop L0 report copy')
        if (!reportCopy) issues.push('desktop L0 report copy missing or unsafe')
        else if (typeof desktop.l0Task.reportSha256 !== 'string' || !SHA256.test(desktop.l0Task.reportSha256) || sha(reportCopy) !== desktop.l0Task.reportSha256.toLowerCase()) {
          issues.push('desktop L0 report hash mismatch')
        }
      }
    }
  }
  const mode = docsOnlyAccepted ? 'docs-only' : evidenceOnlyAccepted ? 'evidence-only' : (manifest.commit === commit ? 'commit-bound' : 'legacy-evidence')
  return { ok: issues.length === 0, issues, checked, mode, docsOnly, docsOnlyBase, evidenceOnly }
}
