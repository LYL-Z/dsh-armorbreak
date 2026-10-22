import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'abm-generic-'))
  const config = join(root, 'mcp.json')
  await writeFile(config, `${JSON.stringify({ mcpServers: { other: { command: 'node', args: ['other.js'] } } })}\n`)
  const env = {
    ...process.env,
    ARMORBREAK_STATE_ROOT: join(root, 'state'),
    ARMORBREAK_WORKSPACE: join(root, 'workspace'),
    ARMORBREAK_PRINCIPAL_ID: 'generic-host',
  }
  const run = (...args) => spawnSync(process.execPath, ['packages/cli/index.js', ...args], { cwd: process.cwd(), env, encoding: 'utf8' })
  return { root, config, env, run }
}

test('generic MCP adapter installs, diagnoses and uninstalls without touching other servers', async () => {
  const f = await fixture()
  const installed = f.run('agent', 'install', '--target', 'generic', '--config', f.config, '--scope', 'user', '--state-root', f.env.ARMORBREAK_STATE_ROOT, '--workspace', f.env.ARMORBREAK_WORKSPACE, '--apply', '--json')
  assert.equal(installed.status, 0, installed.stderr)
  assert.equal(JSON.parse(installed.stdout).status, 'INSTALLED')
  const config = JSON.parse(await readFile(f.config, 'utf8'))
  assert.equal(config.mcpServers.other.command, 'node')
  assert.equal(config.mcpServers.armorbreak.command, 'node')
  assert.ok(config.mcpServers.armorbreak.args[0].replaceAll('\\', '/').endsWith('packages/mcp-server/index.js'))
  const doctor = f.run('agent', 'doctor', '--config', f.config, '--json')
  assert.equal(doctor.status, 0, doctor.stderr)
  const diagnosis = JSON.parse(doctor.stdout)
  assert.equal(diagnosis.status, 'OK')
  assert.ok(diagnosis.serverNames.includes('armorbreak'))
  const removed = f.run('agent', 'install', '--target', 'generic', '--config', f.config, '--scope', 'user', '--uninstall', '--json')
  assert.equal(removed.status, 0, removed.stderr)
  const after = JSON.parse(await readFile(f.config, 'utf8'))
  assert.deepEqual(after, { mcpServers: { other: { command: 'node', args: ['other.js'] } } })
})

test('generic MCP doctor fails closed when ArmorBreak is absent', async () => {
  const f = await fixture()
  const result = f.run('agent', 'doctor', '--config', f.config, '--json')
  assert.equal(result.status, 1)
  const diagnosis = JSON.parse(result.stdout)
  assert.equal(diagnosis.status, 'FAIL')
  assert.ok(diagnosis.problems.some((problem) => problem.includes('missing')))
})
