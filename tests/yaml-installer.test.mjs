import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { applyYamlInstall, planYamlInstall, rollbackYamlInstall, uninstallYamlServer } from '../packages/installer/yaml.js'

const hash = (value) => createHash('sha256').update(value).digest('hex')

test('YAML installer adds/upgrades/uninstalls managed Hermes server', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-yaml-'))
  const configPath = join(dir, 'config.yaml')
  const original = 'model: test\nmcp_servers:\n  node_repl:\n    enabled: true\n'
  await writeFile(configPath, original)
  const plan = await planYamlInstall({ configPath, server: { command: 'C:/node.exe', args: ['server.js'], env: { ARMORBREAK_WORKSPACE: 'C:/work' } } })
  assert.equal(plan.changed, true)
  assert.match(plan.after, /# >>> armorbreak managed: armorbreak/)
  await applyYamlInstall(plan)
  const installed = await readFile(configPath, 'utf8')
  assert.match(installed, /node_repl:/)
  assert.match(installed, /armorbreak:/)
  assert.match(installed, /ARMORBREAK_WORKSPACE/)
  await assert.rejects(() => planYamlInstall({ configPath, server: { command: 'C:/node.exe' } }), (error) => error.code === 'CONFIG_CONFLICT')
  const upgraded = await planYamlInstall({ configPath, server: { command: 'C:/node2.exe' }, force: true })
  await applyYamlInstall(upgraded)
  assert.match(await readFile(configPath, 'utf8'), /node2\.exe/)
  const removed = await uninstallYamlServer({ configPath })
  assert.equal(removed.changed, true)
  const final = await readFile(configPath, 'utf8')
  assert.doesNotMatch(final, /armorbreak managed|armorbreak:/)
  assert.match(final, /node_repl:/)
})

test('YAML installer rejects unmanaged collision/secrets and rollback is byte-exact', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'abm-yaml-rollback-'))
  const configPath = join(dir, 'config.yaml')
  const original = 'mcp_servers:\n  armorbreak:\n    enabled: true\n'
  await writeFile(configPath, original)
  await assert.rejects(() => planYamlInstall({ configPath, server: { command: 'node' }, force: true }), (error) => error.code === 'CONFIG_CONFLICT')
  const fresh = join(dir, 'fresh.yaml')
  const freshOriginal = 'mcp_servers:\n  node_repl:\n    enabled: true\n'
  await writeFile(fresh, freshOriginal)
  const plan = await planYamlInstall({ configPath: fresh, server: { command: 'node' } })
  const applied = await applyYamlInstall(plan)
  assert.ok(applied.backupPath)
  await rollbackYamlInstall(applied.backupPath, fresh)
  assert.equal(hash(await readFile(fresh, 'utf8')), hash(freshOriginal))
  await assert.rejects(() => planYamlInstall({ configPath: join(dir, 'bad.yaml'), server: { command: 'node', apiKey: 'x' } }), (error) => error.code === 'CONFIG_INVALID')
})
