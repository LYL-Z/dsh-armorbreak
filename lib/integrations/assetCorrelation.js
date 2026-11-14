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
  const nodes = new Map(), edges = new Map(), sources = new Set(), segments = input.segments.map(segment)
  const node = (type, label) => { const key = id(type, label); nodes.set(key, { id: key, type, label }); return key }
  const edge = (type, from, to, source) => {
    const key = `${type}:${from}:${to}`, row = edges.get(key) ?? { type, from, to, sourceIds: [], confidence: 'IMPORTED_CLAIM_NOT_VERIFIED' }
    if (!row.sourceIds.includes(source)) row.sourceIds.push(source)
    edges.set(key, row)
  }
  for (const row of input.observations) {
    if (!row || !/^[a-zA-Z0-9_-]{1,64}$/.test(row.sourceId ?? '')) fail()
    sources.add(row.sourceId)
    if (row.type === 'dns') {
      object(row, ['type', 'sourceId', 'domain', 'ip'])
      edge('resolves', node('domain', domain(row.domain)), node('ip', ip(row.ip)), row.sourceId)
    } else if (row.type === 'service') {
      object(row, ['type', 'sourceId', 'ip', 'port', 'transport'])
      if (!Number.isInteger(row.port) || row.port < 1 || row.port > 65535 || !['tcp', 'udp'].includes(row.transport)) fail()
      const address = ip(row.ip)
      edge('exposes', node('ip', address), node('endpoint', `${address}|${row.transport}|${row.port}`), row.sourceId)
    } else if (row.type === 'certificate') {
      object(row, ['type', 'sourceId', 'sha256', 'sans'])
      if (!SHA.test(row.sha256 ?? '') || !Array.isArray(row.sans) || !row.sans.length || row.sans.length > 100) fail()
      const cert = node('certificate-claim', row.sha256)
      for (const san of row.sans) edge('shares_cert', node('domain', domain(san)), cert, row.sourceId)
    } else fail()
  }
  for (const n of [...nodes.values()]) if (n.type === 'ip') for (const s of segments) if (s.contains(n.label)) edge('contains', node('ipv4-segment', s.label), n.id, 'derived-from-imported-address')
  const sort = (a, b) => a < b ? -1 : a > b ? 1 : 0
  const data = { schema: 'armorbreak.offline-asset-graph/v1', mode: 'OFFLINE_DATA_ONLY',
    nodes: [...nodes.values()].sort((a, b) => sort(a.id, b.id)),
    edges: [...edges.values()].map(e => ({ ...e, sourceIds: e.sourceIds.sort(sort) })).sort((a, b) => sort(`${a.type}:${a.from}:${a.to}`, `${b.type}:${b.from}:${b.to}`)),
    networkUsed: false, importedSourceCount: sources.size, certificateAuthentication: 'NOT_PERFORMED', ownership: 'NOT_VERIFIED',
    limitations: ['Imported DNS/service/SAN claims are not active observations, authenticated certificates or target authorization.', 'IPv4 CIDR containment only. IPv6 addresses are exact imported strings; no subnet inference or equivalent-text normalization.', 'Graph labels are public imported asset identifiers; never submit credentials or private configuration.'] }
  return { summary: `Offline asset graph: ${data.nodes.length} nodes, ${data.edges.length} edges; claims unverified`, data,
    findings: [], evidence: [{ kind: 'offline-asset-graph', title: 'Imported relationships, not verified observations', excerpt: JSON.stringify(data) }],
    artifacts: [{ name: 'offline-assets.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }],
    meta: { inputCompleteness: 'complete', runtimeVerified: false, sourceAuthority: 'UNTRUSTED_IMPORTED_CLAIMS' } }
}
