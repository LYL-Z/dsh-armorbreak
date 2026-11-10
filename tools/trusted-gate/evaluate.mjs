import { bindRun } from './binding.mjs'
import { createHash } from 'node:crypto'
export const context = 'ArmorBreak trusted development gate'
export const expectedJobs = ['Node 22 / ubuntu-latest (common development)', 'Node 24 / ubuntu-latest (common development)', 'Node 22 / windows-latest (common development)', 'Node 24 / windows-latest (common development)', 'Common development L0', 'Common development L1', 'ArmorBreak development gate (required)']
const sourceFile = p => /^(?:docs\/integrations\/.+\.md|README(?:\.zh-CN)?\.md|CHANGELOG\.md|SECURITY\.md)$/.test(p) || /^(lib\/|packages\/core\/src\/).+\.(?:js|mjs|ts)$/.test(p) && !/(^|\/)(?:tests?|fixtures|__tests__)(\/|\.)/.test(p)
export function evaluate({ policy, candidate, run, jobs, tree }) {
  const errors = bindRun(candidate, run)
  if (policy.repository !== candidate.repository || !/^[a-f0-9]{40}$/.test(candidate.sha)) errors.push('candidate identity')
  if (tree.truncated || !Array.isArray(tree.tree)) return ['incomplete candidate tree']
  const actual = new Map(tree.tree.filter(x => x.type === 'blob').map(x => [x.path, `${x.mode}:${x.sha}`]))
  for (const p of new Set([...Object.keys(policy.files), ...actual.keys()])) {
    if (!sourceFile(p) && actual.get(p) !== policy.files[p]) errors.push(`protected control changed: ${p}`)
  }
  if (run.head_sha !== candidate.sha || run.repository?.full_name !== policy.repository || run.event !== 'pull_request' || run.path !== '.github/workflows/development-gate.yml' || run.workflow_id !== policy.workflowId || run.status !== 'completed' || run.conclusion !== 'success') errors.push('untrusted or unsuccessful workflow run')
  if (jobs.length !== expectedJobs.length || new Set(jobs.map(x => x.name)).size !== expectedJobs.length) errors.push('job set')
  for (const name of expectedJobs) {
    const job = jobs.find(x => x.name === name)
    if (!job || job.head_sha !== candidate.sha || job.run_id !== run.id || job.status !== 'completed' || job.conclusion !== 'success') { errors.push(`job failed or missing: ${name}`); continue }
    const required = name.startsWith('Node ') ? ['Full test suite', 'TypeScript contract check', 'Assert exact candidate SHA'] : name === 'Common development L0' ? ['Static L0 network-free gate', 'Assert exact candidate SHA'] : name === 'Common development L1' ? ['Pull a digest-pinned image', 'Verify hardened container execution path', 'Assert exact candidate SHA'] : ['Require executed successful dependencies on this exact candidate']
    for (const step of required) if (!job.steps?.some(s => s.name === step && s.status === 'completed' && s.conclusion === 'success')) errors.push(`${name}: missing successful step ${step}`)
  }
  return errors
}
export function policyDigest(policy) { return createHash('sha256').update(JSON.stringify(policy)).digest('hex') }

