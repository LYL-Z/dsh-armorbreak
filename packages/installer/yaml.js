/** Transactional Hermes-style YAML mcp_servers insertion with managed markers. */
import { copyFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { existsSync } from 'node:fs'

function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function quote(value) { return JSON.stringify(String(value)) }

function markers(name) {
  return {
    start: `  # >>> armorbreak managed: ${name}`,
    end: `  # <<< armorbreak managed: ${name}`,
  }
}

export function renderYamlServer(name, server) {
  if (!server?.command || typeof server.command !== 'string') throw fail('CONFIG_INVALID', 'server.command is required')
  for (const key of Object.keys(server)) if (/api[_-]?key|token|secret|password/i.test(key)) throw fail('CONFIG_INVALID', 'plaintext secret fields are forbidden; use env placeholders')
  if (server.args !== undefined && (!Array.isArray(server.args) || server.args.some((arg) => typeof arg !== 'string'))) throw fail('CONFIG_INVALID', 'server.args must be strings')
  if (server.env !== undefined && (typeof server.env !== 'object' || Array.isArray(server.env))) throw fail('CONFIG_INVALID', 'server.env must be an object')
  const { start, end } = markers(name)
  const lines = [start, `  ${name}:`, '    enabled: true', `    command: ${quote(server.command)}`]
  if (server.args?.length) {
    lines.push('    args:')
    for (const arg of server.args) lines.push(`      - ${quote(arg)}`)
  }
  if (server.env && Object.keys(server.env).length) {
    lines.push('    env:')
    for (const [key, value] of Object.entries(server.env)) lines.push(`      ${key}: ${quote(value)}`)
  }
  lines.push(end)
  return lines
}

function sectionBounds(text) {
  const lines = text.split('\n')
  const start = lines.findIndex((line) => /^mcp_servers:\s*$/.test(line))
  if (start < 0) return null
  let end = lines.length
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\S/.test(lines[i]) && lines[i].trim() !== '') { end = i; break }
  }
  return { lines, start, end }
}

export async function planYamlInstall({ configPath, serverName = 'armorbreak', server, force = false } = {}) {
  if (!configPath) throw fail('CONFIG_INVALID', 'configPath is required')
  const abs = resolve(configPath)
  const before = existsSync(abs) ? await readFile(abs, 'utf8') : ''
  const { start, end } = markers(serverName)
  const hasMarkers = before.includes(start) && before.includes(end)
  const section = sectionBounds(before)
  if (!section && before.trim() !== '' && !before.endsWith('\n')) throw fail('CONFIG_INVALID', 'config must end with a newline')
  let sectionHasName = false
  if (section) {
    for (let i = section.start + 1; i < section.end; i += 1) {
      if (new RegExp(`^\\s{2}${serverName}:\\s*$`).test(section.lines[i])) sectionHasName = true
    }
  }
  if (sectionHasName && !hasMarkers) throw fail('CONFIG_CONFLICT', `unmanaged mcp_servers.${serverName} already exists`)
  if (hasMarkers && !force) throw fail('CONFIG_CONFLICT', `${serverName} is already managed; pass force to upgrade`)
  const blockLines = renderYamlServer(serverName, server)
  let after
  if (section) {
    all: {
      const lines = [...section.lines]
      if (hasMarkers) {
        const s = lines.indexOf(start)
        const e = lines.indexOf(end)
        if (s < 0 || e < s) break all
        lines.splice(s, e - s + 1, ...blockLines)
      } else {
        lines.splice(section.end, 0, ...blockLines)
      }
      after = lines.join('\n')
    }
  } else {
    const prefix = before.length === 0 ? '' : before.endsWith('\n') ? before : `${before}\n`
    after = `${prefix}mcp_servers:\n${blockLines.join('\n')}\n`
  }
  return { configPath: abs, before, after, changed: before !== after }
}

export async function applyYamlInstall(plan) {
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

export async function rollbackYamlInstall(backupPath, configPath) {
  if (!backupPath || !existsSync(backupPath)) throw fail('ROLLBACK_MISSING', 'backup file does not exist')
  await copyFile(backupPath, configPath)
  await rm(backupPath, { force: true })
  return { restored: true }
}

export async function uninstallYamlServer({ configPath, serverName = 'armorbreak' } = {}) {
  const abs = resolve(configPath)
  if (!existsSync(abs)) return { changed: false }
  const before = await readFile(abs, 'utf8')
  const { start, end } = markers(serverName)
  const s = before.indexOf(start)
  const e = before.indexOf(end)
  if (s < 0 || e < s) return { changed: false }
  let after = before.slice(0, s) + before.slice(e + end.length)
  after = after.replace(/\n{3,}/g, '\n\n').replace(/\s+$/, '\n')
  const tmp = `${abs}.${process.pid}.tmp`
  await writeFile(tmp, after)
  await rename(tmp, abs)
  return { changed: true, before, after }
}
