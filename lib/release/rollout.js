/**
 * AB2-M4-10 staged rollout controller.
 *
 * Promotion is manual and ordered 1→10→50→100. A REVIEW/FAIL gate blocks
 * promotion; rollback is always allowed and audited. This software does not
 * deploy anything; it guards a release operator's staged rollout.
 */
export const ROLLOUT_STAGES = Object.freeze([1, 10, 50, 100])

export class RolloutController {
  /** @param {{gates: Record<string,{status:string}>, currentStage?:number, audit?:Function}} input */
  constructor(input) {
    this.gates = input.gates ?? {}
    this.currentStage = input.currentStage ?? 0
    this.audit = input.audit ?? (() => {})
    this.history = []
  }

  blockers() {
    const required = ['security', 'offline', 'supplyChain', 'aiEvaluation', 'compatibility', 'performance']
    return required.filter((gate) => this.gates[gate]?.status !== 'PASS')
  }

  status() {
    return { currentStage: this.currentStage, nextStage: ROLLOUT_STAGES.find((stage) => stage > this.currentStage) ?? null, blockers: this.blockers() }
  }

  promote(stage, operator) {
    if (!String(operator ?? '').trim()) throw new Error('operator is required')
    const blockers = this.blockers()
    if (blockers.length > 0) throw new Error(`rollout blocked by gates: ${blockers.join(',')}`)
    const expected = ROLLOUT_STAGES.find((candidate) => candidate > this.currentStage)
    if (!expected) throw new Error('already at 100%')
    if (Number(stage) !== expected) throw new Error(`must promote in order; next is ${expected}%`)
    this.currentStage = Number(stage)
    this.history.push({ action: 'promote', stage: this.currentStage, operator, at: new Date().toISOString() })
    this.audit(this.history[this.history.length - 1])
    return this.status()
  }

  rollback(operator, reason) {
    if (!String(operator ?? '').trim()) throw new Error('operator is required')
    const from = this.currentStage
    this.currentStage = 0
    this.history.push({ action: 'rollback', from, operator, reason: String(reason ?? '').slice(0, 300), at: new Date().toISOString() })
    this.audit(this.history[this.history.length - 1])
    return this.status()
  }
}
