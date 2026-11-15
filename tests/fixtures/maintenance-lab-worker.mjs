import { ArmorBreakRuntime } from '../../packages/core/src/runtime.js'
import { createSyntheticMaintenance } from '../../packages/core/src/syntheticMaintenance.js'
const runtime = new ArmorBreakRuntime({ stateRoot: process.argv[2] })
await runtime.init()
const lab = await createSyntheticMaintenance(runtime, { operator: 'fixture-owner', sessionId: 'fixture-session', seeds: { 'first.txt': 'before-first', 'second.txt': 'before-second' } })
const plan = await lab.plan([{ name: 'first.txt', content: 'after-first' }, { name: 'second.txt', content: 'after-second' }])
await lab.apply(plan.planId, { request: async () => 'allowed-once' }, async index => {
  if (index === 0) {
    process.send({ root: lab.root, planId: plan.planId })
    await new Promise(() => { setInterval(() => {}, 1000) })
  }
})
