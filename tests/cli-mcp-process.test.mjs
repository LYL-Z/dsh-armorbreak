import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

const exec = promisify(execFile)

async function cliFixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-cli-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-cli-ws-'))
  await writeFile(join(workspace, 'sample.txt'), 'cli l0 sample\n')
  const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'cli-tester' }
  const run = async (...args) => {
    const { stdout, stderr } = await exec(process.execPath, ['packages/cli/index.js', ...args], { cwd: process.cwd(), env, timeout: 60_000 })
    return { stdout, stderr }
  }
  return { stateRoot, workspace, env, run }
}

test('CLI capabilities, analyze and task status work without DSH', async () => {
  const f = await cliFixture()
  const caps = JSON.parse((await f.run('capabilities', '--json')).stdout)
  assert.equal(caps.length, 46)
  const analyzed = JSON.parse((await f.run('analyze', '--capability', 'forensics.hash', '--target', join(f.workspace, 'sample.txt'), '--json')).stdout)
  assert.equal(analyzed.state, 'COMPLETED')
  assert.match(analyzed.targetSha256, /^[a-f0-9]{64}$/)
  const task = JSON.parse((await f.run('task', 'status', analyzed.taskId, '--json')).stdout)
  assert.equal(task.id, analyzed.taskId)
  const report = JSON.parse((await f.run('report', analyzed.taskId, '--json')).stdout)
  assert.match(report.markdown, /ArmorBreak/)
  const tasks = JSON.parse((await f.run('task', 'list', '--json')).stdout)
  assert.ok(tasks.some((item) => item.id === analyzed.taskId))
  const workflows = JSON.parse((await f.run('workflow', 'list', '--json')).stdout)
  assert.ok(workflows.length >= 9)
  const { createEngine } = await import('../packages/engine-node/index.js')
  const direct = await createEngine({ stateRoot: f.stateRoot, principals: [{ id: 'cli-tester', kind: 'local-user', workspaces: [f.workspace] }] })
  const pending = await direct.createTask({ principal: { id: 'cli-tester', kind: 'local-user' }, workspaceId: f.workspace, requestId: 'cli-cancel', traceId: 'cli-cancel' }, { title: 'cancel me', targetKind: 'none' })
  await direct.close()
  const cancelled = JSON.parse((await f.run('workflow', 'cancel', pending.id, '--json')).stdout)
  assert.equal(cancelled.state, 'CANCELLED')
})

test('MCP server process emits only JSON-RPC frames on stdout', async () => {
  const f = await cliFixture()
  const child = spawn(process.execPath, ['packages/mcp-server/index.js'], { cwd: process.cwd(), env: f.env, stdio: ['pipe', 'pipe', 'pipe'] })
  let out = ''
  let err = ''
  child.stdout.on('data', (chunk) => { out += chunk })
  child.stderr.on('data', (chunk) => { err += chunk })
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }) + '\n')
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_capabilities', arguments: {} } }) + '\n')
  const deadline = Date.now() + 20_000
  while ((out.match(/\n/g) ?? []).length < 2 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100))
  child.kill()
  await new Promise((resolve) => child.once('exit', resolve))
  const lines = out.trim().split(/\r?\n/).filter(Boolean)
  assert.equal(lines.length, 2)
  for (const line of lines) assert.doesNotThrow(() => JSON.parse(line))
  const second = JSON.parse(lines[1])
  const payload = JSON.parse(second.result.content[0].text)
  assert.equal(payload.length, 46)
  assert.equal(err.trim(), '')
})
