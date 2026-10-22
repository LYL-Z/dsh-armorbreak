/** Transactional TOML MCP config writer using explicit managed markers. */
import { copyFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { existsSync } from 'node:fs'

function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function quote(value) {
  return JSON.stringify(String(value))
}

export function renderTomlServer(name, server) {
  if (!server?.command || typeof server.command !== 'string') throw fail('CONFIG_INVALID', 'server.command is required')
  for (const key of Object.keys(server)) if (/api[_-]?key|token|secret|password/i.test(key)) throw fail('CONFIG_INVALID', 'plaintext secret fields are forbidden; use env placeholders')
  const lines = [`[mcp_servers.${name}]`, `command = ${quote(server.command)}`]
  if (server.args !== undefined) {
    if (!Array.isArray(server.args) || server.args.some((arg) => typeof arg !== 'string')) throw fail('CONFIG_INVALID', 'server.args must be strings')
    lines.push(`args = [${server.args.map(quote).join(', ')}]`)
  }
  if (server.env !== undefined) {
    if (typeof server.env !== 'object' || Array.isArray(server.env)) throw fail('CONFIG_INVALID', 'server.env must be an object')
    const entries = Object.entries(server.env)
    lines.push(`env = { ${entries.map(([key, value]) => `${key} = ${quote(value)}`).join(', ')} }`)
  }
  return lines.join('\n')
}

function markers(name) {
  return { start: `# >>> armorbreak managed: ${name}`, end: `# <<< armorbreak managed: ${name}` }
}

export async function planTomlInstall({ configPath, serverName = 'armorbreak', server, force = false } = {}) {
  if (!configPath) throw fail('CONFIG_INVALID', 'configPath is required')
  const abs = resolve(configPath)
  const before = existsSync(abs) ? await readFile(abs, 'utf8') : ''
  const { start, end } = markers(serverName)
  const startIndex = before.indexOf(start)
  const endIndex = before.indexOf(end)
  const hasMarkers = startIndex >= 0 && endIndex > startIndex
  const header = `[mcp_servers.${serverName}]`
  if (before.includes(header) && !hasMarkers) throw fail('CONFIG_CONFLICT', `unmanaged ${header} already exists`)
  if (hasMarkers && !force) throw fail('CONFIG_CONFLICT', `${serverName} is already managed; pass force to upgrade`)
  const block = `${start}\n${renderTomlServer(serverName, server)}\n${end}`
  let after
  if (hasMarkers) {
    after = before.slice(0, startIndex) + block + before.slice(endIndex + end.length)
  } else {
    const separator = before.length === 0 ? '' : before.endsWith('\n') ? '\n' : '\n\n'
    after = `${before}${separator}${block}\n`
  }
  return { configPath: abs, before, after, changed: before !== after, backup: hasMarkers }
}

export async function applyTomlInstall(plan) {
  if (!plan?.changed) return { changed: false, backupPath: null }
  await mkdir(dirname(plan.configPath), { recursive: true })
  const backupPath = `${plan.configPath}.armorbreak.bak`
  if (plan.before) await copyFile(plan.configPath, backupPath)
  const tmp = `${plan.configPath}.${process.pid}.tmp`
  await writeFile(tmp, plan.after)
  try { await rename(tmp, plan.configPath) } catch (error) {
    await rm(tmp, { force: true })
    if (plan.before) { await copyFile(backupPath, plan.configPath); await rm(backupPath, { force: true }) }
    throw error
  }
  return { changed: true, backupPath: plan.before ? backupPath : null }
}

export async function rollbackTomlInstall(backupPath, configPath) {
  if (!backupPath || !existsSync(backupPath)) throw fail('ROLLBACK_MISSING', 'backup file does not exist')
  await copyFile(backupPath, configPath)
  await rm(backupPath, { force: true })
  return { restored: true }
}

export async function uninstallTomlServer({ configPath, serverName = 'armorbreak' } = {}) {
  const abs = resolve(configPath)
  if (!existsSync(abs)) return { changed: false }
  const before = await readFile(abs, 'utf8')
  const { start, end } = markers(serverName)
  const startIndex = before.indexOf(start)
  const endIndex = before.indexOf(end)
  if (startIndex < 0 || endIndex < startIndex) return { changed: false }
  let after = before.slice(0, startIndex) + before.slice(endIndex + end.length)
  after = after.replace(/\n{3,}/g, '\n\n').replace(/\s+$/, '\n')
  const tmp = `${abs}.${process.pid}.tmp`
  await writeFile(tmp, after)
  await rename(tmp, abs)
  return { changed: true, before, after }
}
