import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
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

test('Claude plugin manifest is official-shaped and validates offline', async () => {
  const manifest = await json('plugins/claude/.claude-plugin/plugin.json')
  const pkg = await json('package.json')
  assert.equal(manifest.name, 'armorbreak')
  assert.ok(manifest.description.length > 20)
  assert.equal(manifest.version, pkg.version)
  assert.equal(manifest.author.name, 'ArmorBreak Universal')
  assert.equal(manifest.license, 'MIT')
  assert.equal(Object.hasOwn(manifest, 'schemaVersion'), false)
  assert.equal(Object.hasOwn(manifest, 'host'), false)
  const skills = (await readdir('plugins/claude/skills', { withFileTypes: true })).filter((entry) => entry.isDirectory())
  assert.equal(skills.length, 7)
  for (const skill of skills) await readFile(`plugins/claude/skills/${skill.name}/SKILL.md`, 'utf8')
  const mcp = await json('plugins/claude/.mcp.json')
  assert.ok(mcp.mcpServers.armorbreak)
  const validation = await json('docs/v2/acceptance/claude-plugin-validation.json')
  assert.equal(validation.result, 'PASS')
  assert.equal(validation.exitCode, 0)
  assert.equal(validation.skills, 7)
})

test('unverified host overlays stay honestly unverified', async () => {
  for (const [host, path] of [
    ['codex', 'plugins/codex/.codex-plugin/plugin.json'],
    ['cursor', 'plugins/cursor/.cursor-plugin/plugin.json'],
    ['zcode', 'plugins/zcode/.zcode-plugin/plugin.json'],
  ]) {
    const overlay = await json(path)
    assert.equal(overlay.host, host)
    assert.equal(overlay.verified, false)
    assert.equal(overlay.pluginManifest, 'plugins/portable/plugin.json')
    await readFile(overlay.mcpConfig, 'utf8')
  }
})
