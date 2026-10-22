import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { applyTomlInstall, planTomlInstall, rollbackTomlInstall, uninstallTomlServer } from '../packages/installer/toml.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')

test('TOML installer uses managed markers, upgrades, and uninstalls only armorbreak', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-toml-'))
  const configPath = join(dir, 'config.toml')
  const original = '[mcp_servers.other]\ncommand = "other"\n'
  await writeFile(configPath, original)
  const plan = await planTomlInstall({ configPath, server: { command: 'node', args: ['server.js'], env: { WORKSPACE: 'C:/work' } } })
  assert.equal(plan.changed, true)
  assert.match(plan.after, /# >>> armorbreak managed: armorbreak/)
  assert.match(plan.after, /\[mcp_servers\.armorbreak\]/)
  await applyTomlInstall(plan)
  const installed = await readFile(configPath, 'utf8')
  assert.match(installed, /mcp_servers\.other/)
  assert.match(installed, /mcp_servers\.armorbreak/)
  await assert.rejects(() => planTomlInstall({ configPath, server: { command: 'node' } }), (error) => error.code === 'CONFIG_CONFLICT')
  const upgraded = await planTomlInstall({ configPath, server: { command: 'node', args: ['server-v2.js'] }, force: true })
  assert.equal(upgraded.changed, true)
  await applyTomlInstall(upgraded)
  assert.match(await readFile(configPath, 'utf8'), /server-v2\.js/)
  const removed = await uninstallTomlServer({ configPath })
  assert.equal(removed.changed, true)
  const final = await readFile(configPath, 'utf8')
  assert.doesNotMatch(final, /armorbreak managed|mcp_servers\.armorbreak/)
  assert.match(final, /mcp_servers\.other/)
})

test('TOML installer rejects unmanaged collision and backup restores byte-for-byte', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-toml-rollback-'))
  const configPath = join(dir, 'config.toml')
  const original = '[mcp_servers.armorbreak]\ncommand = "legacy"\n'
  await writeFile(configPath, original)
  await assert.rejects(() => planTomlInstall({ configPath, server: { command: 'node' }, force: true }), (error) => error.code === 'CONFIG_CONFLICT')
  const freshPath = join(dir, 'fresh.toml')
  await writeFile(freshPath, '[mcp_servers.other]\ncommand = \"other\"\n')
  const freshOriginal = await readFile(freshPath, 'utf8')
  const plan = await planTomlInstall({ configPath: freshPath, server: { command: 'node' } })
  const applied = await applyTomlInstall(plan)
  assert.ok(applied.backupPath)
  await rollbackTomlInstall(applied.backupPath, freshPath)
  assert.equal(hash(await readFile(freshPath, 'utf8')), hash(freshOriginal))
  await assert.rejects(() => planTomlInstall({ configPath: join(dir, 'bad.toml'), server: { command: 'node', apiKey: 'x' } }), (error) => error.code === 'CONFIG_INVALID')
  
})
