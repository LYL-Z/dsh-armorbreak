/** Secret vault adapters. Secrets are never returned in list() or logs. */
import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

function fail(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

export class MemorySecretVault {
  constructor(seed = {}) { this.values = new Map(Object.entries(seed)) }
  set(name, value) { if (!name || typeof value !== 'string' || value.length === 0) throw fail('VAULT_INVALID', 'secret name/value required'); this.values.set(String(name), value) }
  get(name) { return this.values.get(String(name)) ?? null }
  delete(name) { return this.values.delete(String(name)) }
  list() { return [...this.values.keys()].sort() }
}

function powershell(script, input) {
  const result = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { input, encoding: 'utf8', timeout: 60_000, windowsHide: true })
  return result.trim()
}

const PROTECT = `Add-Type -AssemblyName System.Security
$bytes = [Convert]::FromBase64String([Console]::In.ReadToEnd())
$protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')
[Console]::Out.Write([Convert]::ToBase64String($protected))`

const UNPROTECT = `Add-Type -AssemblyName System.Security
$bytes = [Convert]::FromBase64String([Console]::In.ReadToEnd())
$plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'CurrentUser')
[Console]::Out.Write([Convert]::ToBase64String($plain))`

/** Windows DPAPI (CurrentUser) file-backed vault. Only encrypted blobs are persisted. */
export class WindowsDpapiVault {
  constructor({ path }) {
    if (!path) throw fail('VAULT_INVALID', 'WindowsDpapiVault requires a path')
    this.path = resolve(path)
    this.data = existsSync(this.path) ? JSON.parse(readFileSync(this.path, 'utf8')) : { schemaVersion: 'armorbreak.dpapi-vault/v1', entries: {} }
    if (!this.data.entries) this.data.entries = {}
  }
  save() { mkdirSync(dirname(this.path), { recursive: true }); writeFileSync(this.path, `${JSON.stringify(this.data, null, 2)}\n`) }
  set(name, value) {
    if (!name || typeof value !== 'string' || value.length === 0) throw fail('VAULT_INVALID', 'secret name/value required')
    const encrypted = powershell(PROTECT, Buffer.from(value, 'utf8').toString('base64'))
    this.data.entries[String(name)] = encrypted
    this.save()
  }
  get(name) {
    const encrypted = this.data.entries[String(name)]
    if (!encrypted) return null
    try { return Buffer.from(powershell(UNPROTECT, encrypted), 'base64').toString('utf8') } catch { throw fail('VAULT_DECRYPT_FAILED', `could not decrypt secret ${String(name)}`) }
  }
  delete(name) { const existed = delete this.data.entries[String(name)]; this.save(); return existed }
  list() { return Object.keys(this.data.entries).sort() }
}

export function createSecretVault({ platform = process.platform, path = null } = {}) {
  if (platform === 'win32') {
    if (!path) throw fail('VAULT_PATH_REQUIRED', 'Windows DPAPI vault requires a D-drive path')
    return new WindowsDpapiVault({ path })
  }
  return new MemorySecretVault()
}

export function redactSecret(value) {
  let text = typeof value === 'string' ? value : JSON.stringify(value ?? '')
  text = text.replace(/\b(?:sk|ant|gem)-[A-Za-z0-9_-]{8,}\b/g, '[REDACTED]')
  text = text.replace(/(authorization|api[_-]?key|token|secret|password)\s*[:=]\s*["']?[^"',\s}]+/gi, '$1=[REDACTED]')
  return text
}
