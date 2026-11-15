/** Offline imported observations only. No DNS, sockets, scanner or upstream code execution. */
import { isIP } from 'node:net'
import { createHash } from 'node:crypto'
import { canonicalConfig } from './configOverlay.js'
const SHA = /^[a-f0-9]{64}$/
const fail = () => { throw new Error('invalid or excessive offline asset observations') }
function object(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail()
}
function domain(value) {
  if (typeof value !== 'string' || value.length > 253 || !value.includes('.') || isIP(value)) fail()
  const name = value.toLowerCase().replace(/\.$/, '')
  if (!name.split('.').every(part => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))) fail()
  return name
}
function ip(value) { if (typeof value !== 'string' || !isIP(value)) fail(); return value.toLowerCase() }
function ipv4(value) { if (isIP(value) !== 4) fail(); return value.split('.').reduce((n, octet) => (n << 8n) + BigInt(octet), 0n) }
function segment(value) {
  if (typeof value !== 'string' || !/^\d+\.\d+\.\d+\.\d+\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(value)) fail()
  const [address, bits] = value.split('/'), n = ipv4(address), mask = (0xffffffffn << BigInt(32 - Number(bits))) & 0xffffffffn
  if ((n & mask) !== n) fail() // No silent host-bit masking.
  return { label: value, contains: target => isIP(target) === 4 && (ipv4(target) & mask) === n }
}
const id = (type, label) => `${type}:${createHash('sha256').update(type + '\0' + label).digest('hex')}`

export function correlateAssets(buffer) {
  let input
  try {
    if (!Buffer.isBuffer(buffer) || buffer.length > 1024 * 1024) fail()
    input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer))
    canonicalConfig(input)
    object(input, ['schema', 'observations', 'segments'])
    if (input.schema !== 'armorbreak.offline-assets/v1' || !Array.isArray(input.observations) || !input.observations.length || input.observations.length > 1000 || !Array.isArray(input.segments) || input.segments.length > 128) fail()
  } catch { fail() }
  const nodes = new Map(), edges = new Map(), sources = new Set(), records = new Map(), addressRecords = new Map()
  const segments = [...new Set(input.segments)].map(segment)
  const node = (type, label) => { const key = id(type, label); nodes.set(key, { id: key, type, label }); return key }
  const edge = (type, from, to, recordId) => {
    const record = records.get(recordId)
    const key = `${type}:${from}:${to}`, row = edges.get(key) ?? { type, from, to, sourceIds: [], confidence: 'IMPORTED_CLAIM_NOT_VERIFIED',
      provenance: { kind: 'IMPORTED_RECORD', observationRecordIds: [] } }
    if (!row.sourceIds.includes(record.sourceId)) row.sourceIds.push(record.sourceId)
    if (!row.provenance.observationRecordIds.includes(recordId)) row.provenance.observationRecordIds.push(recordId)
    edges.set(key, row)
  }
  const register = (row, address) => {
    // Content identity is namespaced separately from untrusted sourceId. The
    // source remains an imported claim; neither the digest nor rule authenticates it.
    const recordId = id('observation', canonicalConfig(row))
    records.set(recordId, { recordId, sourceId: row.sourceId, type: row.type, claim: JSON.parse(canonicalConfig(row)), confidence: 'IMPORTED_CLAIM_NOT_VERIFIED' })
    if (address) {
      if (!addressRecords.has(address)) addressRecords.set(address, new Set())
      addressRecords.get(address).add(recordId)
    }
    return recordId
  }
  for (const row of input.observations) {
    if (!row || !/^[a-zA-Z0-9_-]{1,64}$/.test(row.sourceId ?? '')) fail()
    sources.add(row.sourceId)
    if (row.type === 'dns') {
      object(row, ['type', 'sourceId', 'domain', 'ip'])
      const name = domain(row.domain), address = ip(row.ip)
      edge('resolves', node('domain', name), node('ip', address), register({ ...row, domain: name, ip: address }, address))
    } else if (row.type === 'service') {
      object(row, ['type', 'sourceId', 'ip', 'port', 'transport'])
      if (!Number.isInteger(row.port) || row.port < 1 || row.port > 65535 || !['tcp', 'udp'].includes(row.transport)) fail()
      const address = ip(row.ip)
      edge('exposes', node('ip', address), node('endpoint', `${address}|${row.transport}|${row.port}`), register({ ...row, ip: address }, address))
    } else if (row.type === 'certificate') {
      object(row, ['type', 'sourceId', 'sha256', 'sans'])
      if (!SHA.test(row.sha256 ?? '') || !Array.isArray(row.sans) || !row.sans.length || row.sans.length > 100) fail()
      const cert = node('certificate-claim', row.sha256), sans = [...new Set(row.sans.map(domain))].sort()
      const recordId = register({ ...row, sans })
      for (const san of sans) edge('shares_cert', node('domain', san), cert, recordId)
    } else fail()
  }
  for (const n of [...nodes.values()]) if (n.type === 'ip') for (const s of segments) if (s.contains(n.label)) {
    const from = node('ipv4-segment', s.label), recordIds = [...addressRecords.get(n.label)]
    for (const recordId of recordIds) edge('contains', from, n.id, recordId)
    edges.get(`contains:${from}:${n.id}`).provenance = { kind: 'DERIVED', rule: 'IPV4_CIDR_CONTAINMENT', observationRecordIds: recordIds,
      segment: { kind: 'INPUT_SEGMENT_DECLARATION', recordId: id('segment-declaration', s.label), cidr: s.label, sourceId: null, confidence: 'IMPORTED_CLAIM_NOT_VERIFIED' } }
  }
  const sort = (a, b) => a < b ? -1 : a > b ? 1 : 0
  const data = { schema: 'armorbreak.offline-asset-graph/v1', mode: 'OFFLINE_DATA_ONLY',
    nodes: [...nodes.values()].sort((a, b) => sort(a.id, b.id)),
    edges: [...edges.values()].map(e => ({ ...e, sourceIds: e.sourceIds.sort(sort), provenance: { ...e.provenance, observationRecordIds: e.provenance.observationRecordIds.sort(sort) } })).sort((a, b) => sort(`${a.type}:${a.from}:${a.to}`, `${b.type}:${b.from}:${b.to}`)),
    observationRecords: [...records.values()].sort((a, b) => sort(a.recordId, b.recordId)),
    networkUsed: false, importedSourceCount: sources.size, certificateAuthentication: 'NOT_PERFORMED', ownership: 'NOT_VERIFIED',
    limitations: ['Imported DNS/service/SAN claims are not active observations, authenticated certificates or target authorization.', 'IPv4 CIDR containment only. IPv6 addresses are exact imported strings; no subnet inference or equivalent-text normalization.', 'Graph labels are public imported asset identifiers; never submit credentials or private configuration.'] }
  const artifact = JSON.stringify(data, null, 2), artifactSha256 = createHash('sha256').update(artifact).digest('hex')
  return { summary: `Offline asset graph: ${data.nodes.length} nodes, ${data.edges.length} edges; claims unverified`, data,
    findings: [], evidence: [{ kind: 'offline-asset-lineage', title: 'CIDR derivation provenance; full graph in hashed artifact',
      excerpt: JSON.stringify({ rule: 'IPV4_CIDR_CONTAINMENT', artifact: 'offline-assets.json', artifactSha256, sourceRecords: records.size, confidence: 'IMPORTED_CLAIM_NOT_VERIFIED', reportExcerptMayBeTruncated: true }) },
    { kind: 'offline-asset-graph', title: 'Imported relationships, not verified observations', excerpt: JSON.stringify(data) }],
    artifacts: [{ name: 'offline-assets.json', contentType: 'application/json', content: artifact }],
    meta: { inputCompleteness: 'complete', runtimeVerified: false, sourceAuthority: 'UNTRUSTED_IMPORTED_CLAIMS' } }
}
