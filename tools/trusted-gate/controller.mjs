// Run only in the independently deployed controller, never on a candidate runner.
// Policy path must point outside the candidate checkout, pinned by the operator.
import { readFileSync } from 'node:fs'
import { evaluate, context, policyDigest } from './evaluate.mjs'
const [policyFile, number, runId, mode = '--dry-run'] = process.argv.slice(2)
if (!policyFile || !/^\d+$/.test(number ?? '') || !/^\d+$/.test(runId ?? '') || !['--dry-run', '--publish'].includes(mode)) throw new Error('usage: controller POLICY PR RUN [--dry-run|--publish]')
const policy = JSON.parse(readFileSync(policyFile, 'utf8').replace(/^\uFEFF/, ''))
if (!/^[\w.-]+\/[\w.-]+$/.test(policy.repository) || !/^[a-f0-9]{40}$/.test(policy.trustCommit)) throw new Error('invalid externally pinned policy')
const token = process.env.ARMORBREAK_CONTROLLER_TOKEN
if (!token) throw new Error('external controller installation/read token required')
async function api(path, method = 'GET', body) {
  const r = await fetch(`https://api.github.com/repos/${policy.repository}/${path}`, { method, headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' }, body: body && JSON.stringify(body), signal: AbortSignal.timeout(30000) })
  if (!r.ok) throw new Error(`GitHub API ${r.status}; no success published`)
  return r.json()
}
const pr = await api(`pulls/${number}`)
const sha = pr.head.sha
if (pr.state !== 'open' || pr.base.repo.full_name !== policy.repository) throw new Error('not an open candidate PR')
const run = await api(`actions/runs/${runId}`)
const tree = await api(`git/trees/${sha}?recursive=1`)
const jobs = []
for (let page=1; page<=20; page++) {
  const data = await api(`actions/runs/${runId}/attempts/${run.run_attempt}/jobs?per_page=100&page=${page}`)
  jobs.push(...data.jobs)
  if (jobs.length >= data.total_count) break
  if (page === 20) throw new Error('incomplete job pagination')
}
const errors = evaluate({ policy, candidate: { repository: policy.repository, sha }, run, jobs, tree })
// Re-read immediately before publication. Stale-SHA checks cannot satisfy new HEAD.
if ((await api(`pulls/${number}`)).head.sha !== sha) throw new Error('PR advanced during evaluation')
const decision = { context, sha, runId: run.id, policyCommit: policy.trustCommit, policyDigest: policyDigest(policy), conclusion: errors.length ? 'failure' : 'success', errors }
if (mode === '--publish') {
  if (!Number.isSafeInteger(policy.appId) || policy.appId <= 0 || policy.appId === 15368) throw new Error('independent App ID required; Actions identity prohibited')
  const check = await api('check-runs', 'POST', { name: context, head_sha: sha, status: 'completed', conclusion: decision.conclusion, output: { title: decision.conclusion, summary: JSON.stringify(decision) } })
  if (check.app?.id !== policy.appId) throw new Error('check issuer differs from configured independent App; do not enable protection')
}
console.log(JSON.stringify(decision, null, 2))
if (errors.length) process.exitCode = 1
