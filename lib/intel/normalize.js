/**
 * AB2-M2-05/06 vulnerability-intelligence normalization.
 *
 * Pure functions: no network, no automatic CVE string concatenation. Every
 * record keeps its source URI, license, retrieval time and TTL; merged records
 * retain all sources and report conflicts instead of silently choosing one.
 */
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000

function s(value, max = 2000) {
  return typeof value === 'string' ? value.trim().slice(0, max) : ''
}

function arr(value) {
  return Array.isArray(value) ? value : []
}

function sourceOf(input, fallback = {}) {
  return {
    uri: s(input?.uri ?? fallback.uri ?? '', 1000),
    license: s(input?.license ?? fallback.license ?? '', 300),
    retrievedAt: s(input?.retrievedAt ?? fallback.retrievedAt ?? '', 60),
  }
}

function fresh(source, now, ttlMs) {
  const at = Date.parse(source.retrievedAt)
  if (!Number.isFinite(at)) return false
  return now - at <= ttlMs
}

/** CISA KEV fixture/feed -> normalized records. */
export function normalizeKev(input, source = {}, options = {}) {
  const now = options.now ?? Date.now()
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  const provenance = sourceOf(source)
  const records = []
  const skipped = []
  for (const raw of arr(input?.vulnerabilities ?? input)) {
    const cveId = s(raw?.cveID ?? raw?.cveId ?? '', 40).toUpperCase()
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) { skipped.push({ reason: 'invalid-cve', value: raw?.cveID ?? null }); continue }
    records.push({
      schemaVersion: 'armorbreak.intel/v1',
      cveId,
      type: 'kev',
      vendor: s(raw?.vendorProject ?? raw?.vendor, 200),
      product: s(raw?.product, 200),
      name: s(raw?.vulnerabilityName ?? raw?.name, 300),
      description: s(raw?.shortDescription ?? raw?.description, 2000),
      dateAdded: s(raw?.dateAdded, 40),
      dueDate: s(raw?.dueDate, 40),
      requiredAction: s(raw?.requiredAction, 1000),
      knownRansomware: /known/i.test(s(raw?.knownRansomwareCampaignUse, 100)),
      source: provenance,
      stale: !fresh(provenance, now, ttlMs),
    })
  }
  return { records, skipped, provenance, stale: !fresh(provenance, now, ttlMs) }
}

/** FIRST EPSS data array -> normalized scores. */
export function normalizeEpss(input, source = {}, options = {}) {
  const now = options.now ?? Date.now()
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  const provenance = sourceOf(source)
  const records = []
  const skipped = []
  for (const raw of arr(input?.data ?? input)) {
    const cveId = s(raw?.cve ?? raw?.cveId ?? '', 40).toUpperCase()
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) { skipped.push({ reason: 'invalid-cve', value: raw?.cve ?? null }); continue }
    const score = Number(raw?.epss)
    const percentile = Number(raw?.percentile)
    if (!Number.isFinite(score) || score < 0 || score > 1 || !Number.isFinite(percentile) || percentile < 0 || percentile > 1) {
      skipped.push({ reason: 'invalid-score', value: cveId })
      continue
    }
    records.push({ schemaVersion: 'armorbreak.intel/v1', cveId, type: 'epss', epss: score, percentile, date: s(raw?.date, 40), source: provenance, stale: !fresh(provenance, now, ttlMs) })
  }
  return { records, skipped, provenance, stale: !fresh(provenance, now, ttlMs) }
}

/** OSV batch/list response -> normalized advisories. */
export function normalizeOsv(input, source = {}, options = {}) {
  const now = options.now ?? Date.now()
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS
  const provenance = sourceOf(source)
  const candidates = []
  if (Array.isArray(input?.results)) for (const result of input.results) candidates.push(...arr(result?.vulns))
  else if (Array.isArray(input?.vulns)) candidates.push(...input.vulns)
  else if (Array.isArray(input)) candidates.push(...input)
  const records = []
  const skipped = []
  for (const raw of candidates) {
    const id = s(raw?.id, 100)
    if (!id) { skipped.push({ reason: 'invalid-id' }); continue }
    const aliases = arr(raw?.aliases).map((alias) => s(alias, 40)).filter(Boolean)
    const cves = [id, ...aliases].filter((value) => /^CVE-\d{4}-\d{4,}$/i.test(value)).map((value) => value.toUpperCase())
    records.push({
      schemaVersion: 'armorbreak.intel/v1',
      id,
      cveId: cves[0] ?? null,
      aliases,
      type: 'osv',
      summary: s(raw?.summary, 500),
      details: s(raw?.details, 4000),
      published: s(raw?.published, 40),
      modified: s(raw?.modified, 40),
      affected: arr(raw?.affected).map((item) => ({ package: s(item?.package?.name, 200), ecosystem: s(item?.package?.ecosystem, 100), ranges: arr(item?.ranges).slice(0, 20) })),
      references: arr(raw?.references).map((ref) => ({ type: s(ref?.type, 40), url: s(ref?.url, 1000) })).slice(0, 20),
      source: provenance,
      stale: !fresh(provenance, now, ttlMs),
    })
  }
  return { records, skipped, provenance, stale: !fresh(provenance, now, ttlMs) }
}

/**
 * Join KEV/EPSS/OSV by CVE without string concatenation. Each output records all
 * contributing sources; conflicts are surfaced, not resolved silently.
 */
export function mergeVulnerabilityIntel({ kev = [], epss = [], osv = [] } = {}) {
  const byCve = new Map()
  const ensure = (cveId) => {
    if (!byCve.has(cveId)) byCve.set(cveId, { cveId, kev: null, epss: null, osv: [], sources: [], conflicts: [] })
    return byCve.get(cveId)
  }
  for (const record of kev) {
    const entry = ensure(record.cveId)
    if (entry.kev) entry.conflicts.push({ field: 'kev', values: [entry.kev.source?.uri, record.source?.uri] })
    else entry.kev = record
    if (!entry.sources.some((source) => source.uri === record.source?.uri)) entry.sources.push(record.source)
  }
  for (const record of epss) {
    const entry = ensure(record.cveId)
    if (entry.epss && entry.epss.epss !== record.epss) entry.conflicts.push({ field: 'epss', values: [entry.epss.epss, record.epss] })
    else if (!entry.epss) entry.epss = record
    if (!entry.sources.some((source) => source.uri === record.source?.uri)) entry.sources.push(record.source)
  }
  for (const record of osv) {
    const cves = [record.cveId, ...(record.aliases ?? [])].filter((value) => /^CVE-\d{4}-\d{4,}$/i.test(value ?? ''))
    for (const cveId of new Set(cves.map((value) => value.toUpperCase()))) {
      const entry = ensure(cveId)
      entry.osv.push(record)
      if (!entry.sources.some((source) => source.uri === record.source?.uri)) entry.sources.push(record.source)
    }
  }
  return { schemaVersion: 'armorbreak.intel-merged/v1', records: [...byCve.values()].sort((a, b) => a.cveId.localeCompare(b.cveId)), conflicts: [...byCve.values()].filter((entry) => entry.conflicts.length > 0) }
}
