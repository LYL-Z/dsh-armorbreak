import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { planJsonInstall } from '../packages/installer/index.js'
import { planTomlInstall, renderTomlServer } from '../packages/installer/toml.js'
import { planYamlInstall, renderYamlServer } from '../packages/installer/yaml.js'

test('all host config installers reject nested plaintext secrets before writing config', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'abm-installer-secret-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const configs = {
    json: join(root, 'mcp.json'),
    toml: join(root, 'mcp.toml'),
    yaml: join(root, 'mcp.yaml'),
  }
  const before = ['{"mcpServers":{}}\n', '# existing TOML\n', 'mcp_servers:\n  existing: {}\n']
  Object.values(configs).forEach((path, index) => writeFileSync(path, before[index]))

  const server = { command: 'node', env: { OPENAI_API_KEY: 'sk-FAKE-REVIEW-CREDENTIAL-123456' } }
  await assert.rejects(() => planJsonInstall({ configPath: configs.json, server }), (error) => error.code === 'CONFIG_INVALID')
  await assert.rejects(() => planTomlInstall({ configPath: configs.toml, server }), (error) => error.code === 'CONFIG_INVALID')
  await assert.rejects(() => planYamlInstall({ configPath: configs.yaml, server }), (error) => error.code === 'CONFIG_INVALID')
  Object.values(configs).forEach((path, index) => assert.equal(readFileSync(path, 'utf8'), before[index]))

  assert.throws(() => renderTomlServer('armorbreak', server), (error) => error.code === 'CONFIG_INVALID')
  assert.throws(() => renderYamlServer('armorbreak', server), (error) => error.code === 'CONFIG_INVALID')
})

test('secret-shaped env names require exact environment placeholders', async () => {
  const server = { command: 'node', env: { OPENAI_API_KEY: '${OPENAI_API_KEY}', ARMORBREAK_WORKSPACE: '${workspace}' } }
  const plan = await planJsonInstall({ configPath: join(tmpdir(), 'not-created-mcp-config.json'), server })
  assert.match(plan.after, /\$\{OPENAI_API_KEY\}/)
  assert.match(renderTomlServer('armorbreak', server), /\$\{OPENAI_API_KEY\}/)
  assert.ok(renderYamlServer('armorbreak', server).join('\n').includes('${OPENAI_API_KEY}'))

  assert.throws(() => renderTomlServer('armorbreak', { command: 'node', api_key: '${API_KEY}' }), (error) => error.code === 'CONFIG_INVALID')
  assert.throws(() => renderYamlServer('armorbreak', { command: 'node', env: { NOTICE: 'sk-live-fakevalue12345' } }), (error) => error.code === 'CONFIG_INVALID')
})
