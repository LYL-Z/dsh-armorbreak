#!/usr/bin/env node
/** AB2-M2-09/10 live catalog + OSV/Scorecard evidence (read-only network run). */
import { writeFile } from 'node:fs/promises'
import { collectCatalog } from '../../lib/catalog/collector.js'
import { assessPlan } from '../../lib/catalog/licenseGate.js'

async function get(url, init = {}) {
  const response = await fetch(url, { ...init, headers: { 'user-agent': 'ArmorBreak/2.0 read-only-research', accept: 'application/json', ...(init.headers ?? {}) } })
  const text = await response.text()
  return { status: response.status, headers: response.headers, json: (() => { try { return JSON.parse(text) } catch { return null } })(), bytes: Buffer.byteLength(text) }
}

const repo = await get('https://api.github.com/repos/deepseek-ai/DeepSeek-V3')
const commit = repo.status === 200 ? await get(`https://api.github.com/repos/deepseek-ai/DeepSeek-V3/commits?per_page=1`) : null
const notFound = await get('https://api.github.com/repos/LYL-Z/definitely-not-a-real-repo-armorbreak')
const osv = await get('https://api.osv.dev/v1/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' }) })
const scorecard = await get('https://api.securityscorecards.dev/projects/github.com/ossf/scorecard')

const catalogEntries = []
if (repo.status === 200) {
  catalogEntries.push({ url: repo.json.html_url, commit: commit?.json?.[0]?.sha ?? null, license: repo.json.license?.spdx_id ?? null, version: repo.json.default_branch, source: 'github-api' })
}
const catalog = collectCatalog(catalogEntries)
const osvVulns = Array.isArray(osv.json?.vulns) ? osv.json.vulns.length : 0
const score = scorecard.status === 200 ? scorecard.json?.score ?? null : null
const component = {
  name: 'lodash', version: '4.17.20', license: 'MIT', commit: '4.17.20', digest: 'sha256:lodash-fixture', scripts: {},
  osv: { known: osvVulns > 0, summary: osvVulns > 0 ? `${osvVulns} OSV vulnerabilities` : 'none' },
  scorecard: score === null ? null : { score },
}
const gate = assessPlan({ components: [component], requireScorecard: true })
const report = {
  schemaVersion: 'armorbreak.supplychain-live/v1',
  generatedAt: new Date().toISOString(),
  network: 'read-only GET/POST query only; no package execution',
  catalog: { github: { status: repo.status, repo: repo.json?.full_name ?? null, license: repo.json?.license?.spdx_id ?? null, defaultBranch: repo.json?.default_branch ?? null, commit: commit?.json?.[0]?.sha ?? null }, notFound: { status: notFound.status, expected: 404 }, dshOfficial: { status: 'NOT_AVAILABLE', reason: 'no official DSH catalog endpoint in current host' }, collected: catalog },
  osv: { status: osv.status, vulnerabilities: osvVulns },
  scorecard: { status: scorecard.status, score },
  gate: { allowed: gate.allowed, denied: gate.denied, reasons: gate.reasons.map((reason) => reason.code) },
  result: repo.status === 200 && notFound.status === 404 && osv.status === 200 && scorecard.status === 200 ? 'PASS' : 'FAIL',
}
await writeFile('docs/v2/acceptance/supplychain-live.json', `${JSON.stringify(report, null, 2)}\n`)
console.log(JSON.stringify(report, null, 2))
if (report.result !== 'PASS') process.exitCode = 1
