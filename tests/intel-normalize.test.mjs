import assert from 'node:assert/strict'
import test from 'node:test'
import { mergeVulnerabilityIntel, normalizeEpss, normalizeKev, normalizeOsv } from '../lib/intel/normalize.js'

const now = Date.parse('2026-10-21T00:00:00Z')
const source = { uri: 'https://fixture.example/feed.json', license: 'test-only', retrievedAt: '2026-10-20T23:00:00Z' }

test('KEV/EPSS/OSV normalize with provenance and reject malformed CVEs', () => {
  const kev = normalizeKev({ vulnerabilities: [{ cveID: 'CVE-2024-0001', vendorProject: 'Acme', product: 'Edge', vulnerabilityName: 'RCE', knownRansomwareCampaignUse: 'Known' }, { cveID: 'not-a-cve' }] }, source, { now })
  assert.equal(kev.records.length, 1)
  assert.equal(kev.records[0].knownRansomware, true)
  assert.equal(kev.records[0].source.uri, source.uri)
  assert.equal(kev.skipped.length, 1)
  const epss = normalizeEpss({ data: [{ cve: 'CVE-2024-0001', epss: '0.42', percentile: '0.9', date: '2026-10-20' }, { cve: 'CVE-2024-0001', epss: '2', percentile: '0.1' }] }, source, { now })
  assert.equal(epss.records.length, 1)
  assert.equal(epss.records[0].epss, 0.42)
  const osv = normalizeOsv({ results: [{ vulns: [{ id: 'OSV-2024-1', aliases: ['CVE-2024-0001'], summary: 'bug', affected: [{ package: { name: 'pkg', ecosystem: 'npm' } }] }] }] }, source, { now })
  assert.equal(osv.records[0].cveId, 'CVE-2024-0001')
  assert.equal(osv.records[0].affected[0].package, 'pkg')
})

test('100 synthetic CVE mappings merge without wrong CVE concatenation', () => {
  const kev = []
  const epss = []
  const osv = []
  for (let i = 0; i < 50; i += 1) {
    const cve = `CVE-2025-${String(1000 + i)}`
    kev.push({ cveId: cve, type: 'kev', source })
    epss.push({ cveId: cve, type: 'epss', epss: i / 100, percentile: i / 100, source })
    if (i % 2 === 0) osv.push({ id: `OSV-${i}`, cveId: cve, aliases: [cve], source, osv: [] })
  }
  const merged = mergeVulnerabilityIntel({ kev, epss, osv })
  assert.equal(merged.records.length, 50)
  for (const record of merged.records) {
    assert.match(record.cveId, /^CVE-\d{4}-\d{4,}$/)
    assert.equal(record.kev.cveId, record.cveId)
    assert.equal(record.epss.cveId, record.cveId)
    assert.ok(record.sources.length >= 1)
  }
})

test('stale source is marked and conflicts are surfaced', () => {
  const staleSource = { ...source, retrievedAt: '2026-10-01T00:00:00Z' }
  const kev = normalizeKev({ vulnerabilities: [{ cveID: 'CVE-2024-0001' }] }, staleSource, { now, ttlMs: 60_000 })
  assert.equal(kev.stale, true)
  assert.equal(kev.records[0].stale, true)
  const merged = mergeVulnerabilityIntel({
    kev: [{ cveId: 'CVE-2024-0001', source: { uri: 'a' } }, { cveId: 'CVE-2024-0001', source: { uri: 'b' } }],
    epss: [{ cveId: 'CVE-2024-0001', epss: 0.1, source: { uri: 'a' } }],
  })
  assert.equal(merged.conflicts.length, 1)
  assert.equal(merged.records[0].sources.length, 2)
})
