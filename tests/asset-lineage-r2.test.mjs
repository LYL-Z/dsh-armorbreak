import test from 'node:test'
import assert from 'node:assert/strict'
import { correlateAssets } from '../lib/integrations/assetCorrelation.js'
const observation = sourceId => ({ type: 'dns', sourceId, domain: 'example.test', ip: '192.0.2.5' })
const graph = observations => correlateAssets(Buffer.from(JSON.stringify({ schema: 'armorbreak.offline-assets/v1', segments: ['192.0.2.0/24'], observations }))).data

test('F04 derived containment keeps the actual imported source when the source changes', () => {
  const a = graph([observation('SOURCE_A')]), b = graph([observation('SOURCE_B')])
  assert.deepEqual(a.edges.find(e => e.type === 'contains').sourceIds, ['SOURCE_A'])
  assert.deepEqual(b.edges.find(e => e.type === 'contains').sourceIds, ['SOURCE_B'])
  assert.notDeepEqual(a.edges.find(e => e.type === 'contains'), b.edges.find(e => e.type === 'contains'))
})
test('F04 multi-source derivation distinguishes input records, the rule and segment declaration', () => {
  const value = graph([observation('SOURCE_A'), observation('SOURCE_B'), { type: 'service', sourceId: 'SOURCE_A', ip: '192.0.2.5', port: 443, transport: 'tcp' }])
  const edge = value.edges.find(e => e.type === 'contains')
  assert.deepEqual(edge.sourceIds, ['SOURCE_A', 'SOURCE_B'])
  assert.equal(edge.provenance.kind, 'DERIVED')
  assert.equal(edge.provenance.rule, 'IPV4_CIDR_CONTAINMENT')
  assert.equal(edge.provenance.observationRecordIds.length, 3)
  assert.equal(edge.provenance.segment.kind, 'INPUT_SEGMENT_DECLARATION')
  assert.equal(edge.provenance.segment.sourceId, null)
  for (const id of edge.provenance.observationRecordIds) assert.ok(value.observationRecords.some(r => r.recordId === id))
  assert.equal(edge.confidence, 'IMPORTED_CLAIM_NOT_VERIFIED')
})
test('F04 duplicate and reversed multi-source observations have byte-identical lineage', () => {
  const a = [observation('SOURCE_A'), observation('SOURCE_B')]
  assert.equal(JSON.stringify(graph(a)), JSON.stringify(graph([...a].reverse().concat(a))))
})
test('F04 an imported source named like the former marker remains a typed imported source', () => {
  const value = graph([observation('derived-from-imported-address'), observation('IPV4_CIDR_CONTAINMENT')])
  const edge = value.edges.find(e => e.type === 'contains')
  assert.deepEqual(edge.sourceIds, ['IPV4_CIDR_CONTAINMENT', 'derived-from-imported-address'])
  assert.equal(edge.provenance.kind, 'DERIVED')
  assert.ok(edge.provenance.observationRecordIds.every(id => id.startsWith('observation:') && !edge.sourceIds.includes(id)))
  assert.equal(value.observationRecords.length, 2)
})
test('F04 artifact and evidence serialize the same fully traceable graph', () => {
  const result = correlateAssets(Buffer.from(JSON.stringify({ schema: 'armorbreak.offline-assets/v1', segments: ['192.0.2.0/24'], observations: [observation('SOURCE_A')] })))
  assert.deepEqual(JSON.parse(result.artifacts[0].content), result.data)
  assert.deepEqual(JSON.parse(result.evidence.find(e => e.kind === 'offline-asset-graph').excerpt), result.data)
  assert.equal(result.data.edges.find(e => e.type === 'contains').provenance.kind, 'DERIVED')
})
