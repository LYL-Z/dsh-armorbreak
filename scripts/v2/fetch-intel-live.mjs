#!/usr/bin/env node
/**
 * AB2-M2-05 live read-only intel collection (opt-in network run).
 * No raw feed is committed; only hashes, counts, provenance and a few examples.
 */
import { writeFile } from 'node:fs/promises'
import { ResourceFetcher } from '../../lib/connectivity/resourceFetcher.js'
import { mergeVulnerabilityIntel, normalizeEpss, normalizeKev, normalizeOsv } from '../../lib/intel/normalize.js'

const fetcher = new ResourceFetcher({ allowNetwork: true })
const report = { schemaVersion: 'armorbreak.intel-live/v1', generatedAt: new Date().toISOString(), sources: {}, merged: null, result: 'FAIL' }
const fetched = {}
for (const connector of ['cisa-kev', 'first-epss', 'osv']) {
  try {
    const result = await fetcher.fetch(connector)
    fetched[connector] = result
    report.sources[connector] = { status: 'FETCHED', bytes: result.bytes, sha256: result.sha256, etag: result.etag, fetchedAt: result.fetchedAt, license: result.license, contentType: result.contentType, activeTesting: result.activeTesting }
  } catch (error) {
    report.sources[connector] = { status: 'FAILED', error: String(error?.message ?? error).slice(0, 300) }
  }
}
function source(connector) {
  const result = fetched[connector]
  return { uri: result ? new URL(connector === 'cisa-kev' ? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' : connector === 'first-epss' ? 'https://api.first.org/data/v1/epss' : 'https://api.osv.dev/v1/vulns/OSV-2020-111').toString() : '', license: result?.license ?? '', retrievedAt: result?.fetchedAt ?? '' }
}
const kev = fetched['cisa-kev'] ? normalizeKev(fetched['cisa-kev'].data, source('cisa-kev')) : { records: [], skipped: [], stale: true }
const epss = fetched['first-epss'] ? normalizeEpss(fetched['first-epss'].data, source('first-epss')) : { records: [], skipped: [], stale: true }
const osv = fetched.osv ? normalizeOsv({ vulns: [fetched.osv.data] }, source('osv')) : { records: [], skipped: [], stale: true }
report.sources['cisa-kev'] = { ...report.sources['cisa-kev'], records: kev.records.length, skipped: kev.skipped.length, stale: kev.stale }
report.sources['first-epss'] = { ...report.sources['first-epss'], records: epss.records.length, skipped: epss.skipped.length, stale: epss.stale }
report.sources.osv = { ...report.sources.osv, records: osv.records.length, skipped: osv.skipped.length, stale: osv.stale }
const merged = mergeVulnerabilityIntel({ kev: kev.records, epss: epss.records, osv: osv.records })
report.merged = { records: merged.records.length, conflicts: merged.conflicts.length, examples: merged.records.slice(0, 3).map((item) => ({ cveId: item.cveId, kev: Boolean(item.kev), epss: item.epss?.epss ?? null, osv: item.osv.length, sources: item.sources.length })) }
report.result = ['cisa-kev', 'first-epss', 'osv'].every((connector) => report.sources[connector]?.status === 'FETCHED') ? 'PASS' : 'FAIL'
await writeFile('docs/v2/acceptance/intel-live.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify({ result: report.result, sources: report.sources, merged: report.merged }, null, 2))
if (report.result !== 'PASS') process.exitCode = 1
