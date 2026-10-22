#!/usr/bin/env node
/**
 * One-click real-provider / real-host retest.
 *
 * Default is a pure preparation check: no model request is made and no 401/429
 * is generated. Add --run only after local authentication/credentials exist.
 * Secrets are read from the local environment and never printed or stored.
 */
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import { createProviderRouter } from '../../packages/provider-router/index.js'
import { createProviderClient } from '../../packages/provider-router/client.js'

const root = resolve(new URL('../..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
const args = process.argv.slice(2)
const value = (name, fallback) => { const index = args.indexOf(name); return index >= 0 ? args[index + 1] : fallback }
const has = (name) => args.includes(name)
const run = has('--run')
const all = has('--all')
const outDir = join(root, 'docs/v2/acceptance')
mkdirSync(join(outDir, 'retest'), { recursive: true })

function loadDotEnv(file) {
  if (!existsSync(file)) return
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line)
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].trim().replace(/^["']|["']$/g, '')
  }
}

function writeEvidence(id, evidence) {
  const path = join(outDir, 'retest', `${id}.json`)
  writeFileSync(path, `${JSON.stringify(evidence, null, 2)}\n`)
  console.log(JSON.stringify({ id, status: evidence.status, evidence: path, details: evidence.details ?? {} }, null, 2))
  return path
}

function taskById(taskId) {
  const dir = join(root, '.armorbreak/tasks', taskId)
  if (!existsSync(join(dir, 'task.json'))) return null
  const task = JSON.parse(readFileSync(join(dir, 'task.json'), 'utf8'))
  const report = task.report?.path && existsSync(task.report.path) ? task.report.path : null
  const reportSha = report ? createHash('sha256').update(readFileSync(report)).digest('hex') : null
  const evidenceLines = existsSync(join(dir, 'evidence.jsonl')) ? readFileSync(join(dir, 'evidence.jsonl'), 'utf8').split(/\r?\n/).filter(Boolean).length : 0
  return { task, report, reportSha, evidenceLines, pass: task.state === 'COMPLETED' && reportSha === task.report?.sha256 && evidenceLines > 0 }
}

const hostSpecs = {
  claude: {
    label: 'Claude Code', binary: process.env.CLAUDE_BIN || 'claude', versionArgs: ['--version'],
    promptArgs: (prompt) => ['-p', prompt, '--max-turns', '4'], env: () => {},
  },
  antigravity: {
    label: 'Antigravity', binary: process.env.GEMINI_BIN || 'gemini', versionArgs: ['--version'],
    promptArgs: (prompt) => ['-p', prompt, '--approval-mode', 'yolo', '--skip-trust', '--output-format', 'json'],
    env: () => loadDotEnv(join(homedir(), '.gemini/.env')),
  },
  zcode: {
    label: 'ZCode', binary: process.env.NODE_BINARY || 'node', versionArgs: [process.env.ZCODE_CLI || 'D:/dsh-ABM/tools/zcode/zcode.cjs', '--version'],
    promptArgs: (prompt) => [process.env.ZCODE_CLI || 'D:/dsh-ABM/tools/zcode/zcode.cjs', '-p', prompt, '--cwd', root, '--mode', 'yolo', '--json'],
    env: () => {},
  },
}

function updateMatrix(hostName, evidence) {
  const path = join(outDir, 'compatibility-matrix.json')
  const matrix = JSON.parse(readFileSync(path, 'utf8'))
  const row = matrix.hosts.find((item) => item.host === hostName)
  if (!row) return false
  Object.assign(row, {
    taskRunState: 'L0_COMPLETED', toolHandshake: 'PASS', evidenceLevel: 'real_verified',
    evidenceId: evidence.evidencePath, reportHash: evidence.reportSha, testAt: evidence.at,
    limitation: evidence.model ? `Real host L0 via ${evidence.model}.` : 'Real host L0.',
  })
  writeFileSync(path, `${JSON.stringify(matrix, null, 2)}\n`)
  return true
}

async function retestHost(key) {
  const spec = hostSpecs[key]
  spec.env()
  const base = { schemaVersion: 'armorbreak.real-retest/v1', kind: 'host', id: key, host: spec.label, at: new Date().toISOString(), run }
  if (!run) {
    const version = spawnSync(spec.binary, spec.versionArgs, { cwd: root, encoding: 'utf8', timeout: 20_000, shell: process.platform === 'win32' })
    return writeEvidence(`host-${key}`, { ...base, status: version.status === 0 ? 'PREPARED' : 'CLI_MISSING', details: { version: (version.stdout ?? '').trim().split(/\r?\n/)[0] } })
  }
  const prompt = 'Use the armorbreak_health tool exactly once, then armorbreak_analyze with capability forensics.hash and target README.md, then armorbreak_report with the returned taskId. Reply with the taskId. Do not edit files.'
  const version = spawnSync(spec.binary, spec.versionArgs, { cwd: root, encoding: 'utf8', timeout: 20_000, shell: process.platform === 'win32' })
  if (version.status !== 0) return writeEvidence(`host-${key}`, { ...base, status: 'CLI_MISSING', details: { error: (version.stderr ?? '').slice(0, 500) } })
  const result = spawnSync(spec.binary, spec.promptArgs(prompt), { cwd: root, env: { ...process.env, ARMORBREAK_WORKSPACE: root }, encoding: 'utf8', timeout: 300_000, shell: process.platform === 'win32' })
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`
  const taskId = /task_[a-z0-9_]+/.exec(output)?.[0]
  const task = taskId ? taskById(taskId) : null
  const status = task?.pass ? 'PASS' : 'FAIL'
  const evidence = { ...base, status, taskId: taskId ?? null, model: process.env.GEMINI_MODEL || process.env.CLAUDE_MODEL || null, details: { exitCode: result.status, output: output.slice(-4000), taskState: task?.task.state ?? null, reportSha: task?.reportSha ?? null, evidenceLines: task?.evidenceLines ?? 0 } }
  const path = writeEvidence(`host-${key}`, evidence)
  evidence.evidencePath = `docs/v2/acceptance/retest/host-${key}.json`
  if (status === 'PASS') updateMatrix(spec.label, evidence)
  return path
}

const providerSpecs = [
  { id: 'openai-chat', label: 'OpenAI Chat', kind: 'openai-compatible', baseUrl: 'https://api.openai.com/v1', baseUrlEnv: 'OPENAI_BASE_URL', model: process.env.OPENAI_CHAT_MODEL || 'gpt-4.1', keyEnv: 'OPENAI_API_KEY' },
  { id: 'openai-responses', label: 'OpenAI Responses', kind: 'openai-responses', baseUrl: 'https://api.openai.com/v1', baseUrlEnv: 'OPENAI_BASE_URL', model: process.env.OPENAI_RESPONSES_MODEL || 'gpt-5', keyEnv: 'OPENAI_API_KEY' },
  { id: 'anthropic', label: 'Anthropic Messages', kind: 'anthropic', baseUrl: 'https://api.anthropic.com', baseUrlEnv: 'ANTHROPIC_BASE_URL', model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5', keyEnv: 'ANTHROPIC_API_KEY' },
  { id: 'gemini', label: 'Gemini Native', kind: 'gemini', baseUrl: 'https://generativelanguage.googleapis.com/v1beta', baseUrlEnv: 'GEMINI_BASE_URL', model: process.env.GEMINI_PROVIDER_MODEL || 'gemini-2.5-pro', keyEnv: 'GEMINI_API_KEY' },
]

async function retestProvider(spec) {
  const base = { schemaVersion: 'armorbreak.real-retest/v1', kind: 'provider', id: spec.id, provider: spec.label, at: new Date().toISOString(), run, model: spec.model }
  if (!run || !process.env[spec.keyEnv]) {
    return writeEvidence(`provider-${spec.id}`, { ...base, status: run ? 'BLOCKED_EXTERNAL' : 'PREPARED', details: { credentialEnv: spec.keyEnv, credentialPresent: Boolean(process.env[spec.keyEnv]) } })
  }
  const router = createProviderRouter({ providers: [{ id: spec.id, kind: spec.kind, baseUrl: process.env[spec.baseUrlEnv] || spec.baseUrl, models: [spec.model], apiKeyEnv: spec.keyEnv, supportsTools: true, timeoutMs: 60_000 }] })
  const client = createProviderClient({ router })
  try {
    const result = await client.chat({ model: spec.model, messages: [{ role: 'user', content: 'Reply with exactly PONG.' }], maxTokens: 32 })
    const status = String(result.text ?? '').includes('PONG') ? 'PASS' : 'FAIL'
    return writeEvidence(`provider-${spec.id}`, { ...base, status, details: { text: result.text, usage: result.usage, finishReason: result.finishReason } })
  } catch (error) {
    return writeEvidence(`provider-${spec.id}`, { ...base, status: 'FAIL', details: { code: error.code ?? null, message: String(error.message).slice(0, 1000) } })
  }
}

const hostArg = value('--host', null)
const providerArg = value('--provider', null)
if (hostArg && providerArg) {
  console.error('use either --host or --provider, not both')
  process.exitCode = 2
} else if (hostArg || providerArg || all) {
  if (hostArg || all) {
    const keys = hostArg === 'all' || !hostArg ? Object.keys(hostSpecs) : [hostArg]
    for (const key of keys) {
      if (!Object.hasOwn(hostSpecs, key)) { console.error(`unknown host: ${key}`); process.exitCode = 2; break }
      await retestHost(key)
    }
  }
  if (providerArg || all) {
    const specs = providerArg === 'all' || !providerArg ? providerSpecs : providerSpecs.filter((spec) => spec.id === providerArg)
    if (specs.length === 0) { console.error(`unknown provider: ${providerArg}`); process.exitCode = 2 }
    for (const spec of specs) await retestProvider(spec)
  }
} else {
  console.error('usage: node scripts/v2/retest-real.mjs --host claude|antigravity|zcode|all [--run] | --provider openai-chat|openai-responses|anthropic|gemini|all [--run]')
  process.exitCode = 2
}
