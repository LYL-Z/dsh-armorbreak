import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-agent-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-agent-ws-'))
  const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'installer-test' }
  const run = (...args) => spawnSync(process.execPath, ['packages/cli/index.js', ...args], { cwd: process.cwd(), env, encoding: 'utf8' })
  return { stateRoot, workspace, env, run }
}

test('agent install dry-run/apply/uninstall JSON preserves other servers and backup', async () => {
  const f = await fixture()
  const configPath = join(f.workspace, '.mcp.json')
  const original = JSON.stringify({ mcpServers: { other: { command: 'other' } } }, null, 2) + '\n'
  await writeFile(configPath, original)
  const base = ['agent', 'install', '--target', 'claude', '--config', configPath, '--scope', 'project', '--json']
  const dry = f.run(...base)
  assert.equal(dry.status, 0, dry.stderr)
  const plan = JSON.parse(dry.stdout)
  assert.equal(plan.status, 'DRY_RUN')
  assert.equal(plan.changed, true)
  assert.equal(await readFile(configPath, 'utf8'), original)
  const applied = f.run(...base, '--apply')
  assert.equal(applied.status, 0, applied.stderr)
  const installed = JSON.parse(await readFile(configPath, 'utf8'))
  assert.deepEqual(Object.keys(installed.mcpServers).sort(), ['armorbreak', 'other'])
  assert.match(applied.stdout, /armorbreak\.bak/)
  const removed = f.run(...base, '--uninstall')
  assert.equal(removed.status, 0, removed.stderr)
  assert.deepEqual(Object.keys(JSON.parse(await readFile(configPath, 'utf8')).mcpServers), ['other'])
})

test('agent install applies Codex TOML and Hermes YAML', async () => {
  const f = await fixture()
  const toml = join(f.workspace, 'config.toml')
  await writeFile(toml, '[mcp_servers.other]\ncommand = "other"\n')
  const codex = f.run('agent', 'install', '--target', 'codex', '--config', toml, '--scope', 'user', '--apply', '--json')
  assert.equal(codex.status, 0, codex.stderr)
  assert.match(await readFile(toml, 'utf8'), /mcp_servers\.armorbreak/)
  const yaml = join(f.workspace, 'config.yaml')
  await writeFile(yaml, 'mcp_servers:\n  node_repl:\n    enabled: true\n')
  const hermes = f.run('agent', 'install', '--target', 'hermes', '--config', yaml, '--scope', 'project', '--apply', '--json')
  assert.equal(hermes.status, 0, hermes.stderr)
  const yamlText = await readFile(yaml, 'utf8')
  assert.match(yamlText, /armorbreak:/)
  assert.match(yamlText, /node_repl:/)
})

test('agent install rejects conflicts without force', async () => {
  const f = await fixture()
  const configPath = join(f.workspace, '.mcp.json')
  await writeFile(configPath, JSON.stringify({ mcpServers: { armorbreak: { command: 'legacy' } } }))
  const result = f.run('agent', 'install', '--target', 'claude', '--config', configPath, '--scope', 'project', '--json')
  assert.equal(result.status, 1)
  assert.match(result.stderr, /already exists/)
})
