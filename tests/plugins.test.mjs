import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

async function json(path) { return JSON.parse(await readFile(path, 'utf8')) }

test('portable plugin manifest and MCP template are structurally valid', async () => {
  const plugin = await json('plugins/portable/plugin.json')
  const pkg = await json('package.json')
  assert.equal(plugin.schemaVersion, 'armorbreak.portable-plugin/v1')
  assert.equal(plugin.version, pkg.version)
  assert.equal(plugin.entrypoints.mcp.transport, 'stdio')
  assert.ok(plugin.entrypoints.mcp.args.includes('packages/mcp-server/index.js'))
  assert.equal(plugin.skills.length, 7)
  for (const file of plugin.skills) await readFile(file, 'utf8')
  assert.equal(plugin.trust.modelCanAuthorize, false)
  assert.equal(plugin.trust.l3, 'always denied')
  const mcp = await json('plugins/portable/mcp.json')
  assert.ok(mcp.mcpServers.armorbreak)
  assert.equal(mcp.mcpServers.armorbreak.env.ARMORBREAK_STATE_ROOT, '${ARMORBREAK_STATE_ROOT}')
  assert.doesNotMatch(JSON.stringify(mcp), /api[_-]?key\s*[:=]\s*["'][^$]/i)
})

test('host overlays honestly remain unverified and point at portable files', async () => {
  const hosts = ['codex', 'claude-code', 'cursor', 'zcode']
  for (const host of hosts) {
    const path = host === 'codex' ? 'plugins/codex/.codex-plugin/plugin.json'
      : host === 'claude-code' ? 'plugins/claude/.claude-plugin/plugin.json'
        : host === 'cursor' ? 'plugins/cursor/.cursor-plugin/plugin.json'
          : 'plugins/zcode/.zcode-plugin/plugin.json'
    const overlay = await json(path)
    assert.equal(overlay.host, host)
    assert.equal(overlay.verified, false)
    assert.equal(overlay.pluginManifest, 'plugins/portable/plugin.json')
    await readFile(overlay.mcpConfig, 'utf8')
  }
  const entries = await readdir('plugins')
  assert.ok(entries.includes('portable'))
})
