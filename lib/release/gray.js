/** Gray rollout decision helpers. */
export const STAGES = [5, 25, 100]

export function decideGray({ stage, gatePass, evidenceValid, l3Denied, errorRate = 0, installRollbackFailed = false } = {}) {
  if (!STAGES.includes(stage)) throw new Error(`invalid gray stage: ${stage}`)
  const reasons = []
  if (!gatePass) reasons.push('release gate failed')
  if (!evidenceValid) reasons.push('evidence chain invalid')
  if (!l3Denied) reasons.push('L3 was not denied')
  if (installRollbackFailed) reasons.push('install rollback failed')
  if (errorRate > 0.01) reasons.push(`error rate ${errorRate} > 1%`)
  return { stage, decision: reasons.length === 0 ? 'CONTINUE' : 'ROLLBACK', reasons }
}
