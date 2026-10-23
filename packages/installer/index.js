/**
 * Transactional installer for JSON-style host MCP configs (Claude project
 * .mcp.json / Cursor mcp JSON). It never executes host code, never removes other
 * servers, and keeps a byte-for-byte backup so rollback/uninstall restores the
 * original config.
 */
import { copyFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { existsSync } from 'node:fs'
import { validateNoPlaintextSecrets } from './secrets.js'

function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function validateServer(server) {
  if (!server || typeof server !== 'object' || Array.isArray(server)) throw fail('CONFIG_INVALID', 'server must be an object')
  if (!server.command || typeof server.command !== 'string') throw fail('CONFIG_INVALID', 'server.command is required')
  if (server.args !== undefined && (!Array.isArray(server.args) || server.args.some((arg) => typeof arg !== 'string'))) throw fail('CONFIG_INVALID', 'server.args must be strings')
  if (server.env !== undefined && (typeof server.env !== 'object' || Array.isArray(server.env))) throw fail('CONFIG_INVALID', 'server.env must be an object')
  validateNoPlaintextSecrets(server)
  return server
}

export async function planJsonInstall({ configPath, serverName = 'armorbreak', server, force = false } = {}) {
  if (!configPath) throw fail('CONFIG_INVALID', 'configPath is required')
  const abs = resolve(configPath)
  const before = existsSync(abs) ? await readFile(abs, 'utf8') : null
  let config = { mcpServers: {} }
  if (before !== null) {
    try { config = JSON.parse(before) } catch { throw fail('CONFIG_INVALID', 'existing config is not valid JSON') }
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw fail('CONFIG_INVALID', 'existing config must be an object')
  }
  validateServer(server)
  config.mcpServers ??= {}
  if (typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers)) throw fail('CONFIG_INVALID', 'mcpServers must be an object')
  const existing = config.mcpServers[serverName]
  if (existing && !force) throw fail('CONFIG_CONFLICT', `MCP server ${serverName} already exists; pass force to replace`)
  const afterConfig = { ...config, mcpServers: { ...config.mcpServers, [serverName]: server } }
  const after = `${JSON.stringify(afterConfig, null, 2)}\n`
  return { configPath: abs, before, after, changed: before !== after, force }
}

export async function applyJsonInstall(plan) {
  if (!plan?.changed) return { changed: false, backupPath: null }
  const abs = plan.configPath
  await mkdir(dirname(abs), { recursive: true })
  const backupPath = `${abs}.armorbreak.bak`
  if (plan.before !== null) await copyFile(abs, backupPath)
  const tmp = `${abs}.${process.pid}.tmp`
  await writeFile(tmp, plan.after)
  try {
    await rename(tmp, abs)
  } catch (error) {
    await rm(tmp, { force: true })
    if (plan.before !== null) {
      await copyFile(backupPath, abs)
      await rm(backupPath, { force: true })
    }
    throw error
  }
  return { changed: true, backupPath: plan.before !== null ? backupPath : null }
}

export async function rollbackJsonInstall(backupPath, configPath) {
  if (!backupPath || !existsSync(backupPath)) throw fail('ROLLBACK_MISSING', 'backup file does not exist')
  await copyFile(backupPath, configPath)
  await rm(backupPath, { force: true })
  return { restored: true }
}

export async function uninstallJsonServer({ configPath, serverName = 'armorbreak' } = {}) {
  const abs = resolve(configPath)
  if (!existsSync(abs)) return { changed: false }
  const before = await readFile(abs, 'utf8')
  const config = JSON.parse(before)
  if (!config.mcpServers || !config.mcpServers[serverName]) return { changed: false }
  const next = { ...config, mcpServers: { ...config.mcpServers } }
  delete next.mcpServers[serverName]
  const after = `${JSON.stringify(next, null, 2)}\n`
  const tmp = `${abs}.${process.pid}.tmp`
  await writeFile(tmp, after)
  await rename(tmp, abs)
  return { changed: true, before, after }
}
