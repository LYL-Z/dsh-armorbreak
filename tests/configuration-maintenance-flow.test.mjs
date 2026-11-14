import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
import { planSyntheticConfiguration } from '../packages/core/src/syntheticConfiguration.js'
import { importConfiguration } from '../lib/integrations/configFormats.js'
const configuration = { schema: 'armorbreak.configuration-import/v1', format: 'yaml', source: 'privatePin: "1234"\r\nunknown: false\r\nfuture:\r\n  raw: "${inert}"\r\n' }
async function runtime(t) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'ab-config-transaction-')); t.after(() => rm(stateRoot, { recursive: true, force: true }))
  const r = new ArmorBreakRuntime({ stateRoot }); await r.init(); return r
}
const args = { configuration, operator: 'synthetic-owner', sessionId: 'synthetic-session', overlays: [{ id: 'inert', values: { privatePin: '5678' } }], conflictPolicy: 'last-wins' }
test('YAML import -> private profile/overlay -> approved synthetic apply -> exact raw CRLF rollback is one actual lifecycle', async t => {
  const r = await runtime(t), { lab, plan, preview } = await planSyntheticConfiguration(r, args)
  t.after(() => rm(lab.root, { recursive: true, force: true }))
  assert.doesNotMatch(JSON.stringify(preview), /privatePin|1234|5678|beforeSha256|afterSha256/)
  await assert.rejects(() => lab.apply(plan.planId), /PROVIDER_REQUIRED/)
  await lab.apply(plan.planId, { request: async () => 'allowed-once' })
  const after = await readFile(join(lab.data, 'config.txt'), 'utf8')
  const parsed = importConfiguration({ ...configuration, source: after }).document.data
  assert.equal(parsed.privatePin, '5678'); assert.equal(parsed.unknown, false); assert.equal(parsed.future.raw, '${inert}')
  await lab.rollback(plan.planId, { request: async () => 'allowed-once' })
  assert.deepEqual(await readFile(join(lab.data, 'config.txt')), Buffer.from(configuration.source))
  const audit = await readFile(join(lab.control, 'audit.jsonl'), 'utf8')
  assert.match(audit, /COMMITTED/); assert.match(audit, /ROLLED_BACK/); assert.doesNotMatch(audit, /privatePin|1234|5678/)
})
test('reject conflict, invalid profile and invalid Cordis data before creating any synthetic plan', async t => {
  const r = await runtime(t)
  await assert.rejects(() => planSyntheticConfiguration(r, { ...args, conflictPolicy: 'reject' }), /CONFIG_CONFLICT/)
  await assert.rejects(() => planSyntheticConfiguration(r, { ...args, selectedProfile: 'missing' }), /profile not found/)
  await assert.rejects(() => planSyntheticConfiguration(r, { ...args, configuration: { ...configuration, format: 'cordis', source: '- id: x\n  disabled: false' } }), /configuration import rejected/)
})
