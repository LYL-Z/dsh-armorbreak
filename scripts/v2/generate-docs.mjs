#!/usr/bin/env node
/** Generate host/API/Skill/release docs from machine-readable sources. */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const outDir = resolve(root, 'docs/v2/generated')
const check = process.argv.includes('--check')

function json(path) { return JSON.parse(readFileSync(resolve(root, path), 'utf8').replace(/^\uFEFF/, '')) }
function frontmatter(path) {
  const text = readFileSync(resolve(root, path), 'utf8')
  const block = /^---\n([\s\S]*?)\n---\n/.exec(text)?.[1] ?? ''
  return { name: /^name:\s*(\S+)$/m.exec(block)?.[1], description: /^description:\s*(.+)$/m.exec(block)?.[1] }
}

function hostMatrix() {
  const matrix = json('docs/v2/acceptance/compatibility-matrix.json')
  const lines = ['# Host Compatibility Matrix (generated)', '', '| Host | Version | Integration | Install | Handshake | Task | Evidence |', '|---|---|---|---|---|---|---|']
  for (const row of matrix.hosts) lines.push(`| ${row.host} | ${row.hostVersion ?? '—'} | ${row.integrationMethod} | ${row.installState} | ${row.toolHandshake} | ${row.taskRunState} | ${row.evidenceId ?? '—'} |`)
  return `${lines.join('\n')}\n`
}
function apiMatrix() {
  const contract = json('packages/core/api-contract.json')
  const lines = ['# Core API Matrix (generated)', '', `Package: \`${contract.package}\``, '', '| Export |', '|---|']
  for (const name of contract.exports) lines.push(`| \`${name}\` |`)
  lines.push('', '| Core method |', '|---|')
  for (const name of contract.coreMethods) lines.push(`| \`${name}\` |`)
  return `${lines.join('\n')}\n`
}
function skillList() {
  const skills = []
  for (const entry of readdirSync(resolve(root, 'skills'), { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const meta = frontmatter(`skills/${entry.name}/SKILL.md`)
    if (meta.name) skills.push({ name: meta.name, description: meta.description ?? '' })
  }
  skills.sort((a, b) => a.name.localeCompare(b.name))
  return `# Skill List (generated)\n\n| Skill | Description |\n|---|---|\n${skills.map((skill) => `| \`${skill.name}\` | ${skill.description} |`).join('\n')}\n`
}
function releaseStatus() {
  const raw = execFileSync(process.execPath, [resolve(root, 'scripts/v2/v2-readiness.mjs')], { cwd: root, encoding: 'utf8' })
  const report = JSON.parse(raw)
  const lines = ['# Release Status (generated)', '', `Ready: **${report.ready}**`, `Release tag: **${report.releaseTag}**`, '', '## Blockers', '']
  for (const blocker of report.blockers) lines.push(`- \`${blocker.code}\`: ${blocker.detail}`)
  return `${lines.join('\n')}\n`
}

const files = {
  'host-matrix.md': hostMatrix(),
  'api-matrix.md': apiMatrix(),
  'skill-list.md': skillList(),
  'release-status.md': releaseStatus(),
}
mkdirSync(outDir, { recursive: true })
let failed = false
for (const [name, content] of Object.entries(files)) {
  const path = resolve(outDir, name)
  if (check) {
    if (!existsSync(path) || readFileSync(path, 'utf8') !== content) { console.error(`generated docs stale: docs/v2/generated/${name}`); failed = true }
  } else {
    writeFileSync(path, content)
  }
}
if (failed) process.exitCode = 1
else console.log(JSON.stringify({ generated: Object.keys(files), check }, null, 2))
