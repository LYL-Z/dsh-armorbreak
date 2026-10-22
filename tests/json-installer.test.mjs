import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { applyJsonInstall, planJsonInstall, rollbackJsonInstall, uninstallJsonServer } from '../packages/installer/index.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')

test('JSON installer dry-run/apply/rollback preserves other servers byte-for-byte', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-json-install-'))
  const configPath = join(dir, '.mcp.json')
  const original = JSON.stringify({ mcpServers: { other: { command: 'other-server' } } }, null, 2) + '\n'
  await writeFile(configPath, original)
  const plan = await planJsonInstall({ configPath, server: { command: 'node', args: ['server.js'], env: { ARMORBREAK_WORKSPACE: '${workspace}' } } })
  assert.equal(plan.changed, true)
  assert.equal(await readFile(configPath, 'utf8'), original)
  const applied = await applyJsonInstall(plan)
  const installed = JSON.parse(await readFile(configPath, 'utf8'))
  assert.deepEqual(Object.keys(installed.mcpServers).sort(), ['armorbreak', 'other'])
  assert.ok(applied.backupPath)
  await rollbackJsonInstall(applied.backupPath, configPath)
  assert.equal(hash(await readFile(configPath, 'utf8')), hash(original))
})

test('JSON installer blocks conflicts/secrets and supports force', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-json-conflict-'))
  const configPath = join(dir, 'config.json')
  await writeFile(configPath, JSON.stringify({ mcpServers: { armorbreak: { command: 'old' } } }))
  await assert.rejects(() => planJsonInstall({ configPath, server: { command: 'new' } }), (error) => error.code === 'CONFIG_CONFLICT')
  await assert.rejects(() => planJsonInstall({ configPath, server: { command: 'new', apiKey: 'sk-live' }, force: true }), (error) => error.code === 'CONFIG_INVALID')
  const forced = await planJsonInstall({ configPath, server: { command: 'new' }, force: true })
  assert.equal(JSON.parse(forced.after).mcpServers.armorbreak.command, 'new')
})

test('json uninstall removes only armorbreak and invalid input writes nothing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-json-uninstall-'))
  const configPath = join(dir, '.mcp.json')
  await writeFile(configPath, JSON.stringify({ mcpServers: { other: { command: 'other' }, armorbreak: { command: 'armorbreak' } } }))
  const result = await uninstallJsonServer({ configPath })
  assert.equal(result.changed, true)
  const config = JSON.parse(await readFile(configPath, 'utf8'))
  assert.deepEqual(Object.keys(config.mcpServers), ['other'])
  const bad = join(dir, 'bad.json')
  await writeFile(bad, '{not-json')
  await assert.rejects(() => planJsonInstall({ configPath: bad, server: { command: 'node' } }), (error) => error.code === 'CONFIG_INVALID')
  assert.equal(await readFile(bad, 'utf8'), '{not-json')
})
