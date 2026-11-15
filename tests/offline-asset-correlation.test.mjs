import test from 'node:test'
import assert from 'node:assert/strict'
import { correlateAssets } from '../lib/integrations/assetCorrelation.js'
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { createMcpServer } from '../packages/mcp-server/index.js'
const dns = { type: 'dns', sourceId: 'import_1', domain: 'Example.test.', ip: '192.0.2.5' }
const input = () => ({ schema: 'armorbreak.offline-assets/v1', segments: ['192.0.2.0/24'], observations: [
  dns, { ...dns, sourceId: 'import_2' }, { type: 'service', sourceId: 'import_1', ip: '192.0.2.5', port: 443, transport: 'tcp' },
  { type: 'certificate', sourceId: 'import_1', sha256: 'a'.repeat(64), sans: ['example.test', 'other.test'] },
] })
const run = value => correlateAssets(Buffer.from(JSON.stringify(value))).data
test('four relationship types, shared SAN certificate, CIDR containment and source deduplication are real offline graph operations', () => {
  const graph = run(input())
  assert.deepEqual([...new Set(graph.edges.map(e => e.type))].sort(), ['contains', 'exposes', 'resolves', 'shares_cert'])
  assert.equal(graph.edges.filter(e => e.type === 'shares_cert').length, 2)
  assert.deepEqual(graph.edges.find(e => e.type === 'resolves').sourceIds, ['import_1', 'import_2'])
  assert.equal(graph.nodes.filter(n => n.type === 'domain' && n.label === 'example.test').length, 1)
  assert.equal(graph.networkUsed, false)
  assert.ok(graph.edges.every(e => e.confidence === 'IMPORTED_CLAIM_NOT_VERIFIED'))
  assert.equal(graph.ownership, 'NOT_VERIFIED'); assert.equal(graph.certificateAuthentication, 'NOT_PERFORMED')
})
test('reordering and repeating identical imported observations produces identical graph bytes', () => {
  const a = input(), b = input(); b.observations.reverse(); b.observations.push(...b.observations)
  assert.equal(JSON.stringify(run(a)), JSON.stringify(run(b)))
})
test('CIDR boundaries, zero prefix and IPv6 exact observations never infer out-of-range membership', () => {
  const value = { ...input(), segments: ['192.0.2.4/31'], observations: [dns, { ...dns, domain: 'outside.test', ip: '192.0.2.6' }, { ...dns, domain: 'v6.test', ip: '2001:db8::1' }] }
  assert.equal(run(value).edges.filter(e => e.type === 'contains').length, 1)
  value.segments = ['0.0.0.0/0']; assert.equal(run(value).edges.filter(e => e.type === 'contains').length, 2)
})
for (const [name, mutate] of [
  ['invalid IP', v => { v.observations[0] = { ...dns, ip: '999.2.3.4' } }],
  ['hostname URL', v => { v.observations[0] = { ...dns, domain: 'https://secret.test/path' } }],
  ['host bits in segment', v => { v.segments = ['192.0.2.5/24'] }],
  ['unsupported IPv6 segment', v => { v.segments = ['2001:db8::/32'] }],
  ['out of range port', v => { v.observations[2].port = 65536 }],
  ['execution option', v => { v.execute = true }],
  ['claimed trust', v => { v.observations[0] = { ...dns, verified: true } }],
  ['unknown operation', v => { v.observations[0] = { type: 'scan', sourceId: 'fake', command: 'untrusted' } }],
  ['invalid certificate digest', v => { v.observations[3].sha256 = 'MIT' }],
  ['excessive observations', v => { v.observations = Array(1001).fill(dns) }],
]) test(`offline asset import rejects ${name} without execution or echoed sensitive input`, () => {
  const value = input(); mutate(value)
  assert.throws(() => run(value), e => e.message === 'invalid or excessive offline asset observations')
})
test('CLI/MCP execute current Core entry, persist reports/evidence and reject workspace escapes and active options', async t => {
  const root = await mkdtemp(join(tmpdir(), 'ab-asset-lab-')); t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace'); await mkdir(workspace)
  const file = join(workspace, 'assets.json'), outside = join(root, 'outside.json')
  await writeFile(file, JSON.stringify(input())); await writeFile(outside, JSON.stringify(input()))
  const { server, engine } = await createMcpServer({ principal: { id: 'offline-asset-fixture', kind: 'local-user', workspaces: [workspace] }, workspaceId: workspace, stateRoot: join(root, 'state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  let id = 1
  const call = async (name, args) => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } }))).result
  const result = await call('armorbreak_analyze', { capability: 'assessment.assets', target: file })
  assert.equal(result.isError, false)
  const value = JSON.parse(result.content[0].text)
  assert.deepEqual(value.data, run(input()))
  assert.ok(value.evidenceIds.length)
  const report = JSON.parse((await call('armorbreak_report', { taskId: value.taskId })).content[0].text)
  assert.ok(report.markdown)
  assert.match(report.markdown, /IPV4_CIDR_CONTAINMENT/)
  async function filesAt(dir) {
    const files = []
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name)
      files.push(...(entry.isDirectory() ? await filesAt(path) : [path]))
    }
    return files
  }
  // Core task evidence and artifacts live in the authorized workspace;
  // stateRoot holds engine policy/session state, not task outputs.
  const files = await filesAt(join(workspace, '.armorbreak'))
  const artifact = files.find(path => path.endsWith('offline-assets.json'))
  assert.ok(artifact, 'actual persisted graph artifact required')
  assert.deepEqual(JSON.parse(await readFile(artifact, 'utf8')), value.data)
  const evidenceFiles = files.filter(path => path.includes('evidence'))
  const evidenceText = (await Promise.all(evidenceFiles.map(path => readFile(path, 'utf8')))).join('\n')
  assert.match(evidenceText, /IPV4_CIDR_CONTAINMENT/)
  assert.equal((await call('armorbreak_analyze', { capability: 'assessment.assets', target: outside })).isError, true)
  assert.equal((await call('armorbreak_analyze', { capability: 'assessment.assets', target: file, options: { scan: true } })).isError, true)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'assessment', 'assets', '--bundle', file, '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_STATE_ROOT: join(root, 'cli-state') } })
  assert.equal(cli.status, 0, cli.stderr); assert.deepEqual(JSON.parse(cli.stdout).data, value.data)
})
