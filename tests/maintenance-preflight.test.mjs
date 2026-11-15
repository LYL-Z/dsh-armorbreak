import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { createEngine } from '../packages/engine-node/index.js'
import { maintenancePath } from '../packages/installer/maintenancePlan.js'
import { TransactionalInstaller } from '../lib/install/installer.js'
import { ApprovalAuthority } from '../lib/control/approvalAuthority.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
import { spawnSync } from 'node:child_process'
const hash = value => createHash('sha256').update(value).digest('hex')
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'abm-maintenance-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const host = join(root, 'host'); await mkdir(host)
  await writeFile(join(host, 'config.json'), '{"unknown":false}')
  const request = { schema: 'armorbreak.maintenance-request/v1', operation: 'update', files: [{ path: 'config.json', expectedSha256: hash('{"unknown":false}'), candidateSha256: hash('candidate') }] }
  const save = () => writeFile(join(host, 'armorbreak-maintenance.json'), JSON.stringify(request))
  await save()
  const principal = { id: 'maintenance-test', kind: 'local-user', workspaces: [host] }
  const engine = await createEngine({ stateRoot: join(root, 'state'), principals: [principal] }); t.after(() => engine.close())
  const run = () => engine.analyze({ principal, workspaceId: host, requestId: 'preflight', traceId: 'fixture' }, { capability: 'maintenance.plan', target: host })
  return { root, host, request, save, run }
}
test('preflight verifies actual files, is deterministic and never mutates source', async t => {
  const f = await fixture(t), a = await f.run(), b = await f.run()
  assert.equal(a.data.planSha256, b.data.planSha256)
  assert.equal(a.data.executable, false)
  assert.equal(a.data.hostModified, false)
  assert.equal(await readFile(join(f.host, 'config.json'), 'utf8'), '{"unknown":false}')
  assert.ok(a.evidenceIds.length)
})
test('drift, duplicate case paths and unrequested scripts fail closed', async t => {
  const f = await fixture(t)
  await writeFile(join(f.host, 'config.json'), 'drift')
  await assert.rejects(f.run, /source drift/)
  await writeFile(join(f.host, 'config.json'), '{"unknown":false}')
  f.request.files.push({ ...f.request.files[0], path: 'CONFIG.JSON' }); await f.save()
  await assert.rejects(f.run, /case-colliding/)
  f.request.files.pop(); f.request.command = 'shell'; await f.save()
  await assert.rejects(f.run, /schema/)
})
test('maintenance paths reject traversal, absolute, ADS, aliases and Windows reserved names', () => {
  for (const path of ['../escape', '/etc/passwd', 'C:/x', 'a\\b', 'file:ads', 'a/../b', 'NUL.txt', 'a.', 'a//b']) assert.throws(() => maintenancePath(path), /invalid/)
  assert.deepEqual(maintenancePath('profiles/web.json'), ['profiles', 'web.json'])
})
test('Core rejects a maintenance source redirected through a junction', async t => {
  const f = await fixture(t), outside = join(f.root, 'outside')
  await mkdir(outside); await writeFile(join(outside, 'config.json'), '{"unknown":false}')
  await symlink(outside, join(f.host, 'link'), process.platform === 'win32' ? 'junction' : 'dir')
  f.request.files[0].path = 'link/config.json'; await f.save()
  await assert.rejects(f.run, /PATH_ESCAPE|escapes|outside|escaped/)
})

test('CLI and generic MCP preflight use Core, refuse caller options and create task reports without a host write', async t => {
  const f = await fixture(t), principal = { id: 'maintenance-mcp', kind: 'local-user', workspaces: [f.host] }
  const { server, engine } = await createMcpServer({ principal, workspaceId: f.host, stateRoot: join(f.root, 'mcp-state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const call = async options => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'maintenance.plan', target: f.host, options } } })))
  const response = await call({})
  assert.equal(response.result.isError, false)
  const result = JSON.parse(response.result.content[0].text)
  assert.equal(result.data.status, 'PREFLIGHT_ONLY')
  assert.ok(result.taskId && result.evidenceIds.length && result.reportPath)
  assert.equal((await call({ apply: true })).result.isError, true)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'maintenance', 'plan', '--root', f.host, '--json'], { encoding: 'utf8', env: { ...process.env, ARMORBREAK_STATE_ROOT: join(f.root, 'cli-state'), ARMORBREAK_WORKSPACE: f.host }, timeout: 30000 })
  assert.equal(cli.status, 0, cli.stderr)
  assert.deepEqual(JSON.parse(cli.stdout).data, result.data)
  assert.equal(await readFile(join(f.host, 'config.json'), 'utf8'), '{"unknown":false}')
})
test('existing installer performs fixture-only staged upgrade and exact rollback, denies unapproved activation and corrupt artifacts', async t => {
  const f = await fixture(t), artifact = join(f.root, 'inert.bin')
  const authority = new ApprovalAuthority({ stateRoot: join(f.root, 'authority') })
  const installer = new TransactionalInstaller({ root: join(f.root, 'isolated-install'), approvalAuthority: authority })
  const stage = async version => {
    await writeFile(artifact, version)
    const plan = await installer.plan({ artifactPath: artifact, version, repo: 'self-authored-fixture', commit: 'a'.repeat(40), license: 'MIT', components: [{ name: 'inert', version, license: 'MIT', commit: 'a'.repeat(40), digest: `sha256:${hash(version)}`, scripts: {} }] })
    assert.equal(plan.status, 'PLANNED', JSON.stringify(plan.assessment))
    const staged = await installer.stage(plan)
    const verified = await installer.verify(staged)
    await assert.rejects(() => installer.activate(verified), /explicit approval/)
    const approvalToken = authority.issue({ id: `install:${plan.planId}`, riskLevel: 'L2', taskId: plan.planId, target: plan.planHash, operator: 'fixture-owner' }).token
    return installer.approve(verified, { approvalToken, operator: 'fixture-owner' })
  }
  const first = await installer.activate(await stage('1.0.0'))
  const pointer = await readFile(installer.activePointer)
  const firstBytes = await readFile(join(first.installedDir, 'artifact.bin'))
  const second = await installer.activate(await stage('2.0.0'))
  await installer.rollback(second)
  assert.deepEqual(await readFile(installer.activePointer), pointer)
  assert.equal(hash(await readFile(join(first.installedDir, 'artifact.bin'))), hash(firstBytes))
  const corrupt = await stage('3.0.0')
  await writeFile(join(installer.staging, corrupt.planId, 'artifact.bin'), 'corrupt')
  await assert.rejects(() => installer.activate(corrupt), /changed before activation/)
  assert.deepEqual(await readFile(installer.activePointer), pointer)
})
