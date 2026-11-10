export function bindRun(candidate, run) {
  const errors = []
  if (!Number.isSafeInteger(candidate.number) || candidate.number <= 0 || !/^[a-f0-9]{40}$/.test(candidate.baseSha ?? '') || !candidate.baseRef || !candidate.headRef || !candidate.headRepository || !candidate.baseRepository || !Number.isSafeInteger(candidate.headRepositoryId) || !Number.isSafeInteger(candidate.baseRepositoryId)) return ['missing PR binding']
  if (candidate.baseRepository !== candidate.repository || run.repository?.id !== candidate.baseRepositoryId || run.head_repository?.id !== candidate.headRepositoryId) errors.push('repository binding mismatch')
  if (!Array.isArray(run.pull_requests) || run.pull_requests.length !== 1) return [...errors, 'missing or ambiguous run PR association']
  const p = run.pull_requests[0]
  if (p.number !== candidate.number) errors.push('run PR number mismatch')
  for (const [side, ref, sha, id] of [['head', candidate.headRef, candidate.sha, candidate.headRepositoryId], ['base', candidate.baseRef, candidate.baseSha, candidate.baseRepositoryId]]) {
    if (p[side]?.sha !== sha || p[side]?.ref !== ref || p[side]?.repo?.id !== id || p[side]?.repo?.url !== `https://api.github.com/repos/${candidate[`${side}Repository`]}`) errors.push(`${side} association mismatch`)
  }
  return errors
}
export function candidateFromPr(pr) {
  return { repository: pr.base.repo.full_name, number: pr.number, sha: pr.head.sha, headRef: pr.head.ref, baseSha: pr.base.sha, baseRef: pr.base.ref, headRepository: pr.head.repo.full_name, baseRepository: pr.base.repo.full_name, headRepositoryId: pr.head.repo.id, baseRepositoryId: pr.base.repo.id }
}
export function sameCandidate(a,b) { return JSON.stringify(a) === JSON.stringify(b) }
export function mergeTarget(pr, merge, head) {
  if (!/^[a-f0-9]{40}$/.test(pr.merge_commit_sha ?? '') || merge.sha !== pr.merge_commit_sha || head.sha !== pr.head.sha || merge.parents?.length !== 2 || merge.parents[0].sha !== pr.base.sha || merge.parents[1].sha !== pr.head.sha) throw new Error('merge identity/parents unavailable or changed')
  // The reviewed worker checks out HEAD, so it can qualify the merge only if
  // both Git trees are identical. A different merge tree requires new testing.
  if (merge.tree?.sha !== head.tree?.sha || !/^[a-f0-9]{40}$/.test(head.tree?.sha ?? '')) throw new Error('merge tree not tested; separate merge-source validation required')
  return { sha: merge.sha, headSha: head.sha, baseSha: pr.base.sha, tree: head.tree.sha, method: 'IDENTICAL_HEAD_MERGE_TREE' }
}
