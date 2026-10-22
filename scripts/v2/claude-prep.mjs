#!/usr/bin/env node
/** Claude Code preparation evidence: plugin validation, MCP connection, skill count, model gate. */
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const run = (command, args, timeout = 60_000) => spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout, shell: process.platform === 'win32' })
const version = run('claude', ['--version'], 15_000)
const mcp = run('claude', ['mcp', 'list'], 60_000)
const plugin = run('claude', ['plugin', 'validate', 'plugins/claude'], 60_000)
const model = run('claude', ['-p', 'Reply with exactly CLAUDE_PREP_OK', '--max-turns', '1'], 90_000)
const skills = existsSync(join(root, 'plugins/claude/skills'))
  ? readdirSync(join(root, 'plugins/claude/skills'), { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort()
  : []
const mcpOutput = `${mcp.stdout ?? ''}\n${mcp.stderr ?? ''}`
const modelOutput = `${model.stdout ?? ''}\n${model.stderr ?? ''}`
const report = {
  schemaVersion: 'armorbreak.claude-prep/v1',
  generatedAt: new Date().toISOString(),
  claudeVersion: (version.stdout ?? '').trim() || null,
  pluginValidation: { exitCode: plugin.status, output: `${plugin.stdout ?? ''}${plugin.stderr ?? ''}`.slice(0, 2000) },
  mcp: { exitCode: mcp.status, armorbreakConnected: /armorbreak.*Connected/i.test(mcpOutput), output: mcpOutput.slice(0, 4000) },
  skills: { count: skills.length, names: skills },
  model: { exitCode: model.status, blocked: /not logged in|authentication|401|login/i.test(modelOutput), output: modelOutput.slice(0, 2000) },
  result: /not logged in|authentication|401|login/i.test(modelOutput) ? 'BLOCKED_EXTERNAL' : (model.status === 0 ? 'PASS' : 'FAILED'),
}
writeFileSync(join(root, 'docs/v2/acceptance/claude-prep.json'), `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify(report, null, 2))
if (!report.mcp.armorbreakConnected) process.exitCode = 1
