import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { reviewAssessment } from '../lib/integrations/assessmentReview.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
const hash = value => createHash('sha256').update(value).digest('hex')
function document() {
  const content = 'Authorization: Bearer SYNTHETIC_PRIVATE_TOKEN; C:\\Users\\Private\\file; curl https://example.invalid'
  return { schema: 'armorbreak.assessment-review-input/v1', artifactSha256: 'a'.repeat(64),
    evidence: [{ id: 'source-record', confidence: 'observed', authority: 'tool-output', content, sha256: hash(content), supportingIds: [] }],
    findings: [{ id: 'claim', ruleId: 'CWE-79', severity: 'high', evidenceIds: ['source-record'] }] }
}
const run = value => reviewAssessment(Buffer.from(JSON.stringify(value)))
test('offline review binds hashes without promoting caller-declared observations and never exposes raw content', () => {
  const input = document(), result = run(input)
  assert.equal(result.data.executionAllowed, false)
  assert.equal(result.data.evidence[0].sourceDeclaredConfidence, 'observed')
  assert.equal(result.data.evidence[0].verification, 'UNVERIFIED_INPUT')
  assert.equal(result.data.vulnerabilityStatus, 'not_tested')
  assert.equal(result.data.findingCount, 1)
  assert.equal(result.data.correlation.counts.sourceFindings, 1)
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE_TOKEN|Private|curl |example.invalid|source-record/)
  assert.deepEqual(result, run(input))
})
test('tampering, missing and cyclic references, duplicate findings and execution hooks fail closed', () => {
  let input = document(); input.evidence[0].content += 'tamper'
  assert.throws(() => run(input), /hash mismatch/)
  input = document(); input.evidence[0].supportingIds = ['missing']
  assert.throws(() => run(input), /reference missing/)
  input = document(); input.evidence[0].supportingIds = ['source-record']
  assert.throws(() => run(input), /cycle/)
  input = document(); input.findings.push(input.findings[0])
  assert.throws(() => run(input), /invalid finding/)
  input = document(); input.findings[0].evidenceIds = ['missing']
  assert.throws(() => run(input), /missing evidence reference/)
  input = document(); input.command = 'shell'
  assert.throws(() => run(input), /shape/)
  input = document(); input.evidence[0].authority = 'independent-certification'
  assert.throws(() => run(input), /evidence/)
  assert.throws(() => reviewAssessment(Buffer.alloc(1024 * 1024 + 1)), /1 MiB/)
  assert.throws(() => reviewAssessment(Buffer.from([0xff, 0xfe])), /encoded|encoding/i)
})
test('Core, MCP, independent CLI and report share one read-only bounded workspace chain', async t => {
  const root = await mkdtemp(join(tmpdir(), 'abm-assessment-')), workspace = join(root, 'workspace')
  await mkdir(workspace); t.after(() => rm(root, { recursive: true, force: true }))
  const target = join(workspace, 'review.json'), bytes = JSON.stringify(document())
  await writeFile(target, bytes)
  const principal = { id: 'assessment-test', kind: 'local-user', workspaces: [workspace] }
  const { engine, server } = await createMcpServer({ principal, workspaceId: workspace, stateRoot: join(root, 'state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const call = async file => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'assessment.review', target: file } } })))
  const reply = await call(target); assert.equal(reply.result.isError, false)
  const result = JSON.parse(reply.result.content[0].text)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'assessment', 'review', '--bundle', target, '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_STATE_ROOT: join(root, 'cli-state') } })
  assert.equal(cli.status, 0, cli.stderr); assert.deepEqual(JSON.parse(cli.stdout).data, result.data)
  const report = await engine.getReport({ principal, workspaceId: workspace, requestId: 'r', traceId: 'r', connectionId: server.connectionId }, result.taskId)
  assert.match(report.markdown, /Offline assessment review/)
  assert.doesNotMatch(JSON.stringify(report), /SYNTHETIC_PRIVATE_TOKEN|curl |Private/)
  assert.equal(await readFile(target, 'utf8'), bytes)
  const external = join(root, 'outside'); await mkdir(external); await writeFile(join(external, 'review.json'), bytes)
  await symlink(external, join(workspace, 'link'), process.platform === 'win32' ? 'junction' : 'dir')
  const refusal = await call(join(workspace, 'link', 'review.json')); assert.equal(refusal.result.isError, true)
  assert.match(refusal.result.content[0].text, /PATH_ESCAPE|escape|outside/)
})
