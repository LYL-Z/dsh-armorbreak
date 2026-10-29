/**
 * Offline correlator for an explicitly supplied, local security evidence bundle.
 * It does not execute samples, fetch advisories, or turn observations into proof.
 */
import { canonicalJson, redactDeep, redactText, sanitizeText, sha256 } from '../../../packages/core/src/util.js'

export const EVIDENCE_BUNDLE_SCHEMA = 'armorbreak.security-evidence-bundle/v1'
const HASH_RE = /^[a-f0-9]{64}$/i
const SEVERITY = Object.freeze({ critical: 6, high: 5, error: 5, medium: 3, moderate: 3, warning: 3, low: 2, note: 1, info: 1, informational: 1 })
const MAX_SOURCES = 50
const MAX_FINDINGS = 200
const MAX_FINDING_BYTES = 2 * 1024
const MAX_ARTIFACT_BYTES = 900 * 1024
const ABSOLUTE_PATH_TEXT = /\b[A-Za-z]:[\\/][^\s"'<>|]+|\\\\[^\\/\s]+[\\/][^\s"'<>|]+|\/(?:Users|home|tmp|var|opt|workspace|private|mnt|root)\/[^\s"'<>|]+/gi

function clean(value, max = 500) {
  return redactText(sanitizeText(String(value ?? ''), max))
    .replace(ABSOLUTE_PATH_TEXT, (path) => `[REDACTED_PATH:${sha256(path.toLowerCase()).slice(0, 12)}]`)
    .replace(/[\r\n\t ]+/g, ' ').trim()
}

function severityOf(value) {
  const valueText = String(value ?? '').toLowerCase()
  if (valueText === 'critical') return 'critical'
  if (valueText === 'high' || valueText === 'error') return 'high'
  if (valueText === 'warning' || valueText === 'medium' || valueText === 'moderate') return 'medium'
  if (valueText === 'low') return 'low'
  if (valueText === 'info' || valueText === 'informational' || valueText === 'note') return 'info'
  return 'info'
}

function severityRank(value) {
  return SEVERITY[String(value ?? '').toLowerCase()] ?? 0
}

function bestSeverity(items) {
  return items.map((item) => severityOf(item.severity)).sort((a, b) => severityRank(b) - severityRank(a))[0] ?? 'info'
}

function normalizeCwe(value) {
  const text = String(value ?? '').match(/CWE-?\d+/i)?.[0]
  return text ? text.toUpperCase().replace(/^CWE(\d)/, 'CWE-$1') : null
}

function normalizeLocationPath(value) {
  let path = redactText(sanitizeText(String(value ?? ''), 1000)).replace(/[\r\n\t ]+/g, ' ').trim().replace(/\\/g, '/')
  if (!path) return null
  // Treat file:// URLs (including UNC authorities) as absolute paths.
  path = path.replace(/^file:\/\//i, '/').replace(/%20/gi, ' ')
  path = path.replace(/^\.\//, '').replace(/\/{2,}/g, '/')
  if (/^(?:[a-z]:\/|\/|unc\/)/i.test(path)) {
    // Absolute paths can contain usernames, workspace names, or customer data.
    // Do not expose even the basename in reports; keep only a stable opaque ID.
    return `external/${sha256(path.toLowerCase()).slice(0, 16)}`
  }
  return clean(path, 500)
}

function parseTarget(target) {
  const value = String(target ?? '')
  const match = /^(.*?):(\d+)(?::(\d+))?$/.exec(value)
  if (!match) return { uri: normalizeLocationPath(value), startLine: null, startColumn: null }
  const line = Number(match[2])
  const column = match[3] ? Number(match[3]) : null
  return {
    uri: normalizeLocationPath(match[1]),
    startLine: Number.isSafeInteger(line) && line > 0 ? line : null,
    startColumn: Number.isSafeInteger(column) && column > 0 ? column : null,
  }
}

function sanitizeOriginalRecord(value, key = '', depth = 0) {
  if (depth > 8) return '[depth-limit]'
  if (Array.isArray(value)) return value.slice(0, 200).map((item) => sanitizeOriginalRecord(item, key, depth + 1))
  if (value && typeof value === 'object') {
    const output = {}
    for (const [childKey, child] of Object.entries(value)) output[childKey] = sanitizeOriginalRecord(child, childKey, depth + 1)
    return output
  }
  if (typeof value !== 'string') return value
  const normalizedKey = key.toLowerCase().replace(/[_-]/g, '')
  if (['path', 'filepath', 'uri', 'target', 'pkgpath'].includes(normalizedKey)) {
    if (normalizedKey === 'target') {
      const location = parseTarget(value)
      return location.uri ? `${location.uri}${location.startLine ? `:${location.startLine}` : ''}${location.startColumn ? `:${location.startColumn}` : ''}` : null
    }
    return normalizeLocationPath(value)
  }
  return clean(value, 800)
}

function locationOf(path, line, column) {
  const uri = normalizeLocationPath(path)
  const startLine = Number.isSafeInteger(Number(line)) && Number(line) > 0 ? Number(line) : null
  const startColumn = Number.isSafeInteger(Number(column)) && Number(column) > 0 ? Number(column) : null
  return { uri, startLine, startColumn }
}

function cweFromTags(tags = []) {
  for (const tag of tags) {
    const cwe = normalizeCwe(tag)
    if (cwe) return cwe
  }
  return null
}

function firstSarifLocation(result) {
  const physical = result?.locations?.[0]?.physicalLocation
  return locationOf(physical?.artifactLocation?.uri, physical?.region?.startLine, physical?.region?.startColumn)
}

function sarifRelated(result) {
  return (Array.isArray(result?.relatedLocations) ? result.relatedLocations : []).slice(0, 20).map((item) => {
    const physical = item?.physicalLocation
    return {
      ...locationOf(physical?.artifactLocation?.uri, physical?.region?.startLine, physical?.region?.startColumn),
      message: clean(item?.message?.text, 1000),
    }
  })
}

function sourceFamily(source, inferred) {
  const family = clean(source.sourceFamily ?? source.family ?? inferred, 120).toLowerCase()
  return family || 'unknown'
}

function evidenceContext(raw, fallback = '') {
  const evidence = Array.isArray(raw?.evidence) ? raw.evidence : []
  const snippets = evidence.map((item) => typeof item === 'string' ? item : item?.excerpt ?? item?.message ?? '').filter(Boolean)
  const value = raw?.evidenceContext ?? raw?.codeSnippet ?? raw?.extra?.lines ?? snippets.join('\n') ?? fallback
  const normalized = clean(value, 2000).toLowerCase()
  return normalized || null
}

function normalizeArmorBreak(source, artifactHash) {
  const findings = Array.isArray(source.findings) ? source.findings : []
  if (findings.length > MAX_FINDINGS) throw new Error(`source ${source.id} exceeds ${MAX_FINDINGS} findings; split the local evidence bundle`)
  return findings.map((raw) => {
    const location = parseTarget(raw?.target)
    return {
      raw,
      rule: normalizeCwe(raw?.cwe) ?? clean(raw?.ruleId ?? raw?.id, 200),
      cwe: normalizeCwe(raw?.cwe),
      location,
      severity: severityOf(raw?.severity),
      evidenceContext: evidenceContext(raw),
      message: clean(raw?.title ?? raw?.message ?? raw?.description, 1000),
      declaredEvidenceStatus: ['observed', 'hypothesis', 'corroborated', 'unverified'].includes(raw?.verification) ? raw.verification : 'unverified',
      declaredVulnerabilityStatus: ['unverified', 'confirmed', 'refuted', 'not_tested'].includes(raw?.vulnerabilityStatus) ? raw.vulnerabilityStatus : null,
      impact: raw?.impactScope,
      reachability: raw?.reachability,
      artifactHash: HASH_RE.test(String(raw?.artifactHash ?? '')) ? String(raw.artifactHash).toLowerCase() : artifactHash,
      related: [],
    }
  })
}

function normalizeSarif(source, artifactHash) {
  const document = source.document ?? source.sarif
  if (document?.version !== '2.1.0' || !Array.isArray(document?.runs)) throw new Error(`source ${source.id} is not SARIF 2.1.0`)
  const records = []
  for (const run of document.runs.slice(0, 20)) {
    const driver = run?.tool?.driver ?? {}
    const rules = new Map((Array.isArray(driver.rules) ? driver.rules : []).map((item) => [item.id, item]))
    const runResults = Array.isArray(run?.results) ? run.results : []
    if (records.length + runResults.length > MAX_FINDINGS) throw new Error(`source ${source.id} exceeds ${MAX_FINDINGS} findings; split the local evidence bundle`)
    for (const raw of runResults) {
      const rule = rules.get(raw?.ruleId) ?? {}
      const cwe = normalizeCwe(raw?.properties?.cwe) ?? cweFromTags([...(rule.properties?.tags ?? []), ...(raw?.properties?.tags ?? [])])
      const location = firstSarifLocation(raw)
      records.push({
        raw,
        rule: cwe ?? clean(raw?.ruleId, 200),
        cwe,
        location,
        severity: severityOf(raw?.properties?.severity ?? raw?.level),
        evidenceContext: evidenceContext({ evidenceContext: raw?.properties?.evidenceContext ?? raw?.properties?.codeSnippet ?? raw?.message?.text }),
        message: clean(raw?.message?.text ?? rule.shortDescription?.text ?? raw?.ruleId, 1000),
        declaredEvidenceStatus: ['observed', 'hypothesis', 'corroborated', 'unverified'].includes(raw?.properties?.evidenceStatus) ? raw.properties.evidenceStatus : 'unverified',
        declaredVulnerabilityStatus: ['unverified', 'confirmed', 'refuted', 'not_tested'].includes(raw?.properties?.vulnerabilityStatus) ? raw.properties.vulnerabilityStatus : null,
        impact: raw?.properties?.impactScope,
        reachability: raw?.properties?.reachability,
        artifactHash: artifactHash,
        related: sarifRelated(raw),
      })
    }
  }
  return records
}

function normalizeSemgrep(source, artifactHash) {
  const document = source.document ?? source.semgrep
  const results = document?.results
  if (!Array.isArray(results)) throw new Error(`source ${source.id} is not Semgrep JSON with results[]`)
  if (results.length > MAX_FINDINGS) throw new Error(`source ${source.id} exceeds ${MAX_FINDINGS} findings; split the local evidence bundle`)
  return results.map((raw) => {
    const extra = raw?.extra ?? {}
    const metadata = extra.metadata ?? {}
    const cwe = normalizeCwe(metadata.cwe) ?? cweFromTags(metadata.cwe ?? [])
    return {
      raw,
      rule: cwe ?? clean(raw?.check_id, 200),
      cwe,
      location: locationOf(raw?.path, raw?.start?.line, raw?.start?.col),
      severity: severityOf(extra.severity),
      evidenceContext: evidenceContext({ evidenceContext: extra.lines ?? raw?.message }),
      message: clean(extra.message ?? raw?.message ?? raw?.check_id, 1000),
      declaredEvidenceStatus: 'hypothesis',
      declaredVulnerabilityStatus: null,
      impact: metadata.impactScope,
      reachability: metadata.reachability,
      artifactHash,
      related: [],
    }
  })
}

function normalizeTrivy(source, artifactHash) {
  const document = source.document ?? source.trivy
  if (!Array.isArray(document?.Results)) throw new Error(`source ${source.id} is not Trivy JSON with Results[]`)
  const records = []
  for (const result of document.Results.slice(0, 1000)) {
    const vulnerabilities = Array.isArray(result?.Vulnerabilities) ? result.Vulnerabilities : []
    if (records.length + vulnerabilities.length > MAX_FINDINGS) throw new Error(`source ${source.id} exceeds ${MAX_FINDINGS} findings; split the local evidence bundle`)
    for (const raw of vulnerabilities) {
      const packageName = clean(raw?.PkgName, 200)
      const version = clean(raw?.InstalledVersion, 100)
      const advisory = clean(raw?.VulnerabilityID, 200)
      records.push({
        raw,
        rule: advisory,
        cwe: normalizeCwe(raw?.CweIDs?.[0]),
        location: locationOf(result?.Target || raw?.PkgPath || `dependency/${packageName}`, null, null),
        severity: severityOf(raw?.Severity),
        evidenceContext: clean(`${packageName}@${version}`, 1000).toLowerCase() || null,
        message: clean(`${advisory} affects ${packageName}@${version}; fixed version ${raw?.FixedVersion || 'unknown'}`, 1000),
        declaredEvidenceStatus: 'observed',
        declaredVulnerabilityStatus: null,
        impact: null,
        reachability: null,
        artifactHash,
        related: [],
      })
    }
  }
  return records
}

function normalizeOsvMatches(source, artifactHash) {
  const document = source.document ?? source.osv
  if (!Array.isArray(document?.matches)) throw new Error(`source ${source.id} is not an explicit OSV match record with matches[]`)
  if (document.matches.length > MAX_FINDINGS) throw new Error(`source ${source.id} exceeds ${MAX_FINDINGS} findings; split the local evidence bundle`)
  return document.matches.map((raw) => {
    const pkg = raw?.package ?? raw?.affected?.package ?? {}
    const version = raw?.version ?? raw?.installedVersion ?? ''
    const id = raw?.vulnerability?.id ?? raw?.id ?? raw?.vulnerabilityId
    return {
      raw,
      rule: clean(id, 200),
      cwe: normalizeCwe(raw?.cwe),
      location: locationOf(raw?.location ?? raw?.target ?? `dependency/${pkg.name ?? pkg.purl ?? 'unknown'}`, null, null),
      severity: severityOf(raw?.severity),
      evidenceContext: clean(`${pkg.name ?? pkg.purl ?? ''}@${version}`, 1000).toLowerCase() || null,
      message: clean(raw?.summary ?? `OSV advisory ${id ?? 'unknown'} matched a supplied component record`, 1000),
      declaredEvidenceStatus: 'observed',
      declaredVulnerabilityStatus: null,
      impact: null,
      reachability: raw?.reachability,
      artifactHash,
      related: [],
    }
  })
}

function normalizeSource(source, artifactHash) {
  const kind = clean(source.kind ?? source.format, 80).toLowerCase()
  if (kind === 'armorbreak' || kind === 'armorbreak-findings') return normalizeArmorBreak(source, artifactHash)
  if (kind === 'sarif' || kind === 'sarif-2.1.0') return normalizeSarif(source, artifactHash)
  if (kind === 'semgrep-json') return normalizeSemgrep(source, artifactHash)
  if (kind === 'trivy-json') return normalizeTrivy(source, artifactHash)
  if (kind === 'osv-match' || kind === 'osv-match-json') return normalizeOsvMatches(source, artifactHash)
  if (kind === 'sbom-cyclonedx' || kind === 'sbom-spdx') return []
  throw new Error(`unsupported evidence source kind: ${kind || '(missing)'}`)
}

function severityAggregate(records) {
  return bestSeverity(records)
}

function impactAggregate(records) {
  const accepted = new Set(['high', 'medium', 'low'])
  const values = records.map((item) => String(item.impact ?? '').toLowerCase()).filter((item) => accepted.has(item))
  return values.includes('high') ? 'high' : values.includes('medium') ? 'medium' : values.includes('low') ? 'low' : 'unknown'
}

function reachabilityAggregate(records) {
  const accepted = new Set(['reachable', 'conditional', 'unreachable'])
  const values = records.map((item) => String(item.reachability ?? '').toLowerCase()).filter((item) => accepted.has(item))
  if (values.includes('reachable')) return 'reachable'
  if (values.includes('conditional')) return 'conditional'
  if (values.length && values.every((item) => item === 'unreachable')) return 'unreachable'
  return 'unknown'
}

function triagePriority(severity, impact, reachability, evidenceStatus) {
  if (reachability === 'unreachable') return 'P4'
  if ((severity === 'critical' || severity === 'high') && reachability === 'reachable' && evidenceStatus === 'corroborated') return 'P1'
  if ((severity === 'critical' || severity === 'high') && reachability !== 'unknown') return 'P2'
  if (severity === 'medium' && reachability === 'reachable') return 'P2'
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || impact !== 'unknown') return 'P3'
  if (severity === 'low') return 'P4'
  return 'UNRANKED'
}

function recordEvidenceStatus(records, independentFamilies) {
  if (independentFamilies.size > 1) return 'corroborated'
  const declared = records.map((item) => item.declaredEvidenceStatus)
  if (declared.includes('hypothesis')) return 'hypothesis'
  if (declared.length && declared.every((value) => value === 'observed')) return 'observed'
  return 'unverified'
}

function parseDatabaseSnapshots(input, assessmentDate) {
  const snapshots = Array.isArray(input) ? input.slice(0, 100) : []
  return snapshots.map((item) => {
    const snapshotDate = /^\d{4}-\d{2}-\d{2}$/.test(String(item?.snapshotDate ?? '')) ? String(item.snapshotDate) : null
    const retrievedAt = Number.isFinite(Date.parse(item?.retrievedAt)) ? new Date(item.retrievedAt).toISOString() : null
    let staleStatus = 'unknown'
    if (snapshotDate && assessmentDate) {
      const ageDays = Math.floor((Date.parse(`${assessmentDate}T00:00:00Z`) - Date.parse(`${snapshotDate}T00:00:00Z`)) / 86_400_000)
      staleStatus = ageDays > 90 ? 'stale' : ageDays >= 0 ? 'current' : 'unknown'
    }
    return {
      id: clean(item?.id ?? item?.name ?? 'unnamed-database', 120),
      source: clean(item?.source, 300) || null,
      retrievedAt,
      snapshotDate,
      assessmentDate,
      staleStatus,
      sha256: HASH_RE.test(String(item?.sha256 ?? '')) ? String(item.sha256).toLowerCase() : null,
    }
  })
}

function makeSarif(groups, artifactPath = 'security-evidence.json') {
  artifactPath = normalizeLocationPath(artifactPath) || 'security-evidence.json'
  const rules = new Map()
  const results = groups.map((group, index) => {
    const ruleId = group.rule || `armorbreak/uncategorized-${index + 1}`
    if (!rules.has(ruleId)) rules.set(ruleId, {
      id: ruleId,
      name: ruleId.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 80) || 'ArmorBreakFinding',
      shortDescription: { text: group.title },
      fullDescription: { text: group.description },
      properties: { tags: ['security', ...(group.cwe ? [`external/cwe/${group.cwe.toLowerCase()}`] : [])] },
    })
    const primary = group.location?.uri
      ? [{ physicalLocation: { artifactLocation: { uri: group.location.uri }, ...(group.location.startLine ? { region: { startLine: group.location.startLine, ...(group.location.startColumn ? { startColumn: group.location.startColumn } : {}) } } : {}) } }]
      : [{ physicalLocation: { artifactLocation: { uri: artifactPath } } }]
    const relatedLocations = group.sources.map((source, sourceIndex) => ({
      id: sourceIndex + 1,
      message: { text: `Imported evidence from ${source.sourceFamily} (${source.sourceId}); vulnerability status remains ${group.vulnerabilityStatus}.` },
      physicalLocation: {
        artifactLocation: { uri: source.location?.uri || group.location?.uri || artifactPath },
        ...(source.location?.startLine ? { region: { startLine: source.location.startLine, ...(source.location.startColumn ? { startColumn: source.location.startColumn } : {}) } } : {}),
      },
    }))
    return {
      ruleId,
      level: group.severity === 'critical' || group.severity === 'high' ? 'error' : group.severity === 'medium' ? 'warning' : 'note',
      message: { text: `${group.title}. Evidence status: ${group.evidenceStatus}; vulnerability status: ${group.vulnerabilityStatus}; triage ${group.triagePriority}. ${group.description}` },
      locations: primary,
      relatedLocations,
      properties: {
        findingId: group.id,
        artifactHash: group.artifactHash,
        evidenceStatus: group.evidenceStatus,
        vulnerabilityStatus: group.vulnerabilityStatus,
        triagePriority: group.triagePriority,
        reachability: group.reachability,
        impactScope: group.impactScope,
        sourceFamilies: group.sourceFamilies,
        sourceFindingIds: group.sourceFindingIds,
        cvss: null,
      },
    }
  })
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'ArmorBreak Evidence Correlator', informationUri: 'https://github.com/LYL-Z/dsh-armorbreak', rules: [...rules.values()] } },
      results,
    }],
  }
}

/** Parse, redact, normalize, and deterministically correlate a local bundle. */
export function correlateEvidenceBundle(buffer, options = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new Error('security evidence bundle must be a non-empty JSON file')
  const maxBytes = Math.min(8 * 1024 * 1024, Math.max(1024, Number(options.maxBytes) || 8 * 1024 * 1024))
  if (buffer.length > maxBytes) throw new Error(`security evidence bundle exceeds ${maxBytes} bytes`)
  let bundle
  try { bundle = JSON.parse(buffer.toString('utf8')) } catch { throw new Error('security evidence bundle is not valid UTF-8 JSON') }
  if (!bundle || bundle.schema !== EVIDENCE_BUNDLE_SCHEMA) throw new Error(`security evidence bundle schema must be ${EVIDENCE_BUNDLE_SCHEMA}`)
  if (!Array.isArray(bundle.sources) || bundle.sources.length === 0 || bundle.sources.length > MAX_SOURCES) throw new Error(`security evidence bundle sources must contain 1-${MAX_SOURCES} entries`)
  const artifactHash = HASH_RE.test(String(bundle.artifact?.sha256 ?? '')) ? String(bundle.artifact.sha256).toLowerCase() : null
  if (!artifactHash) throw new Error('security evidence bundle artifact.sha256 must be a 64-character SHA-256 hex digest')
  const sourceIds = new Set()
  const records = []
  const preservedSources = []
  for (const source of bundle.sources) {
    const sourceId = clean(source?.id, 120)
    if (!sourceId || sourceIds.has(sourceId)) throw new Error('every evidence source requires a unique non-empty id')
    sourceIds.add(sourceId)
    const kind = clean(source.kind ?? source.format, 80).toLowerCase()
    const inferredFamily = kind === 'sarif' || kind === 'sarif-2.1.0'
      ? source.document?.runs?.[0]?.tool?.driver?.name ?? source.sarif?.runs?.[0]?.tool?.driver?.name ?? 'sarif'
      : kind.replace(/-json$/, '')
    const family = sourceFamily(source, inferredFamily)
    const sourceDigest = sha256(canonicalJson(sanitizeOriginalRecord(source)))
    const normalized = normalizeSource(source, artifactHash)
    if (records.length + normalized.length > MAX_FINDINGS) throw new Error(`bundle exceeds ${MAX_FINDINGS} findings; split it into smaller local evidence bundles`)
    preservedSources.push({
      id: sourceId,
      kind,
      sourceFamily: family,
      formatVersion: clean(source.formatVersion ?? source.schemaVersion ?? kind, 120),
      originalRecordCount: normalized.length,
      redactedSourceRecordSha256: sourceDigest,
    })
    for (let sourceIndex = 0; sourceIndex < normalized.length; sourceIndex += 1) {
      const item = normalized[sourceIndex]
      const rawOriginal = sanitizeOriginalRecord(redactDeep(item.raw))
      const originalJson = canonicalJson(rawOriginal)
      if (Buffer.byteLength(originalJson) > MAX_FINDING_BYTES) {
        item.raw = { truncated: true, originalSha256: sha256(originalJson), preview: originalJson.slice(0, MAX_FINDING_BYTES - 128) }
      } else {
        item.raw = rawOriginal
      }
      records.push({
        ...item,
        sourceId,
        sourceFindingId: `${sourceId}:${sourceIndex + 1}`,
        sourceFamily: family,
        sourceKind: kind,
        sourceFormat: clean(source.formatVersion ?? source.schemaVersion ?? kind, 120),
        sourceClaimedStatus: item.declaredVulnerabilityStatus,
      })
    }
  }
  const groupsByKey = new Map()
  const ungrouped = []
  for (let index = 0; index < records.length; index += 1) {
    const item = records[index]
    // Correlate at file/line granularity: tools often disagree on whether a
    // column is present, while the source context hash disambiguates evidence.
    const locationKey = item.location?.uri ? `${item.location.uri}:${item.location.startLine ?? ''}` : ''
    const contextHash = item.evidenceContext ? sha256(item.evidenceContext) : ''
    const complete = Boolean(item.artifactHash && locationKey && item.rule && contextHash)
    const key = complete ? `${item.artifactHash}\n${locationKey}\n${item.rule}\n${contextHash}` : null
    if (!key) {
      ungrouped.push({ ...item, uniqueIndex: index })
      continue
    }
    const group = groupsByKey.get(key) ?? []
    group.push(item)
    groupsByKey.set(key, group)
  }
  const groupedRecords = [...groupsByKey.entries()].map(([key, items]) => ({ key, items }))
  for (const item of ungrouped) groupedRecords.push({ key: `ungrouped\n${item.sourceId}\n${item.uniqueIndex}`, items: [item] })
  groupedRecords.sort((a, b) => a.key.localeCompare(b.key))
  const correlations = groupedRecords.map(({ key, items }) => {
    const sourceFamilies = [...new Set(items.map((item) => item.sourceFamily))].sort()
    const evidenceStatus = recordEvidenceStatus(items, new Set(sourceFamilies))
    const primary = items[0]
    const severity = severityAggregate(items)
    const impactScope = impactAggregate(items)
    const reachability = reachabilityAggregate(items)
    const id = `corr-${sha256(key).slice(0, 20)}`
    const sources = items.map((item) => ({
      sourceId: item.sourceId,
      sourceFamily: item.sourceFamily,
      sourceKind: item.sourceKind,
      sourceFormat: item.sourceFormat,
      location: item.location,
      evidenceStatus: item.declaredEvidenceStatus,
      sourceClaimedVulnerabilityStatus: item.sourceClaimedStatus,
      originalFinding: item.raw,
      related: item.related,
    }))
    const title = `${primary.rule}: ${primary.message || 'security observation'}`.slice(0, 300)
    const priority = triagePriority(severity, impactScope, reachability, evidenceStatus)
    const description = `关联 ${items.length} 条原始来源记录（${sourceFamilies.join(', ') || 'unknown'}）。evidenceStatus=${evidenceStatus}; vulnerabilityStatus=not_tested。来源记录不能单独证明漏洞可利用。`
    const target = primary.location?.uri ? `${primary.location.uri}${primary.location.startLine ? `:${primary.location.startLine}` : ''}` : null
    return {
      id,
      artifactHash: primary.artifactHash,
      location: primary.location,
      rule: primary.rule,
      cwe: items.find((item) => item.cwe)?.cwe ?? null,
      title,
      description,
      severity,
      cvss: null,
      evidenceStatus,
      verification: evidenceStatus,
      vulnerabilityStatus: 'not_tested',
      triagePriority: priority,
      impactScope,
      reachability,
      sourceFamilies,
      sourceFindingIds: items.map((item) => item.sourceFindingId).sort(),
      target,
      evidence: items.map((item) => ({
        title: `${item.sourceFamily} / ${item.sourceId}`,
        excerpt: clean(item.message || item.evidenceContext || 'Imported finding; source excerpt not present.', 2000),
        meta: {
          sourceId: item.sourceId,
          sourceFamily: item.sourceFamily,
          sourceKind: item.sourceKind,
          sourceFormat: item.sourceFormat,
          artifactHash: item.artifactHash,
          location: item.location,
          related: item.related,
        },
      })),
      sources,
      grouping: { completeKey: !key.startsWith('ungrouped\n'), evidenceContextSha256: primary.evidenceContext ? sha256(primary.evidenceContext) : null },
    }
  })
  const assessmentDate = /^\d{4}-\d{2}-\d{2}$/.test(String(bundle.assessmentDate ?? options.asOfDate ?? '')) ? String(bundle.assessmentDate ?? options.asOfDate) : null
  const databaseSnapshots = parseDatabaseSnapshots(bundle.databaseSnapshots, assessmentDate)
  const sbomSources = bundle.sources.filter((source) => ['sbom-cyclonedx', 'sbom-spdx'].includes(String(source.kind ?? source.format).toLowerCase()))
  for (const source of sbomSources) {
    const document = source.document ?? source.sbom
    if (!document || typeof document !== 'object' || Array.isArray(document)) throw new Error(`SBOM source ${source.id} must include an object document`)
    if (String(source.kind ?? source.format).toLowerCase() === 'sbom-cyclonedx' && document.bomFormat !== 'CycloneDX') throw new Error(`SBOM source ${source.id} declares CycloneDX but document.bomFormat differs`)
    if (String(source.kind ?? source.format).toLowerCase() === 'sbom-spdx' && typeof document.spdxVersion !== 'string') throw new Error(`SBOM source ${source.id} declares SPDX but document.spdxVersion is missing`)
  }
  const supplyChain = {
    sboms: sbomSources.map((source) => ({
      sourceId: clean(source.id, 120),
      format: String(source.kind ?? source.format).toLowerCase() === 'sbom-spdx' ? 'SPDX' : 'CycloneDX',
      documentVersion: source.document?.specVersion ?? source.document?.spdxVersion ?? source.sbom?.specVersion ?? null,
      componentCount: Array.isArray(source.document?.components) ? source.document.components.length : Array.isArray(source.document?.packages) ? source.document.packages.length : null,
      declaredSha256: HASH_RE.test(String(source.sha256 ?? '')) ? String(source.sha256).toLowerCase() : null,
      documentRecordSha256: sha256(canonicalJson(sanitizeOriginalRecord(source.document ?? source.sbom))),
    })),
    databaseSnapshots,
    advisorySources: preservedSources.filter((source) => ['osv-match', 'osv-match-json'].includes(String(source.kind ?? source.format).toLowerCase())),
    networkAccess: 'none',
  }
  const sarif = makeSarif(correlations, bundle.artifact?.path ?? 'security-evidence.json')
  const correlationReport = {
    schema: 'armorbreak.security-correlation/v1',
    artifactHash,
    assessmentDate,
    inputSha256: sha256(buffer),
    counts: { inputSources: bundle.sources.length, sourceFindings: records.length, correlationGroups: correlations.length, incompleteKeys: ungrouped.length },
    evidenceSemantics: { observed: 'directly reported source fact', hypothesis: 'source inference requiring review', corroborated: 'distinct source families reported the same normalized evidence key; this is not vulnerability reproduction', vulnerabilityStatus: 'not_tested unless an independent verification workflow records evidence' },
    sources: preservedSources,
    correlations,
    supplyChain,
    limitations: ['Only declared local input formats are parsed.', 'CVE/OSV records are not fetched or version-range matched by this capability.', 'SBOM documents are summarized by declared format, version, component count, and a redacted-document digest; full SBOM documents are not copied into the report or converted.', 'Source findings are retained as redacted, bounded records; sensitive values and absolute path components may be removed.', 'No active test, exploit, or sample execution occurs.', 'Cross-source corroboration does not set confirmed/refuted.'],
  }
  const json = JSON.stringify(correlationReport, null, 2)
  const sarifJson = JSON.stringify(sarif, null, 2)
  if (Buffer.byteLength(json) > MAX_ARTIFACT_BYTES || Buffer.byteLength(sarifJson) > MAX_ARTIFACT_BYTES) throw new Error(`correlation report exceeds ${MAX_ARTIFACT_BYTES} bytes; split the local evidence bundle`)
  const findings = correlations.map((group) => ({
    title: group.title,
    severity: group.severity,
    description: group.description,
    verification: group.evidenceStatus,
    vulnerabilityStatus: 'not_tested',
    method: 'offline-evidence-correlation',
    cwe: group.cwe,
    cvss: null,
    remediation: '人工复核各原始来源、可达性、适用配置和安全前置条件；独立验证前不得标记漏洞已确认。',
    target: group.target,
    evidence: group.evidence,
    evidenceStatus: group.evidenceStatus,
    triagePriority: group.triagePriority,
    artifactHash: group.artifactHash,
  }))
  return {
    summary: `离线关联 ${records.length} 条原始发现为 ${correlations.length} 组；证据完整性不足而未合并 ${ungrouped.length} 条；漏洞状态全部为 not_tested。`,
    findings,
    evidence: [{ title: 'Security evidence bundle', kind: 'security-evidence-bundle', excerpt: `inputSha256=${sha256(buffer)} sources=${bundle.sources.length} findings=${records.length} groups=${correlations.length}`, meta: { artifactHash, inputSha256: sha256(buffer), networkAccess: 'none' } }],
    data: correlationReport,
    artifacts: [
      { name: 'security-correlation.json', contentType: 'application/json', content: json },
      { name: 'security-correlation.sarif.json', contentType: 'application/sarif+json', content: sarifJson },
    ],
    meta: { domain: 'security', capability: 'security.correlate', inputSha256: sha256(buffer), networkAccess: 'none', sourceAdapters: [...new Set(bundle.sources.map((item) => String(item.kind ?? item.format).toLowerCase()))].sort(), correlationGroups: correlations.length, incompleteKeys: ungrouped.length },
  }
}

export default { correlateEvidenceBundle }
