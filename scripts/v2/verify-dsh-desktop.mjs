#!/usr/bin/env node
/**
 * AB2-M4-06 Desktop E2E probe. It records what is actually reachable; it never
 * claims a GUI/model call when the installed bundle or credentials are absent.
 */
import { readFile, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'

const result = {
  schemaVersion: 'armorbreak.desktop-e2e/v1',
  generatedAt: new Date().toISOString(),
  platform: process.platform,
  node: process.version,
  bundleLock: existsSync('docs/v2/bundle.lock.json'),
  checks: {},
  result: 'BLOCKED',
  reason: 'Not run: requires an installed V2 DSH Desktop bundle, selected ArmorBreak preset, and a live model tool call.',
}
try {
  const lock = JSON.parse(await readFile('docs/v2/bundle.lock.json', 'utf8'))
  result.bundle = { name: lock.name, version: lock.version, preset: lock.preset, aggregateSha256: lock.aggregateSha256 }
} catch { result.bundle = null }
try {
  const env = execFileSync('cmd', ['/c', 'where', 'dsh'], { encoding: 'utf8', timeout: 5000 }).trim()
  result.checks.dshCli = env.split(/\r?\n/)[0] ?? null
} catch { result.checks.dshCli = null }
result.checks.guiUrl = process.env.DSH_WEB_URL ?? null
result.checks.modelCredential = process.env.DEEPSEEK_API_KEY ? 'present-in-env' : 'not-in-headless-env'
await writeFile('docs/v2/acceptance/desktop-e2e.json', `${JSON.stringify(result, null, 2)}\n`)
console.log(JSON.stringify(result, null, 2))
