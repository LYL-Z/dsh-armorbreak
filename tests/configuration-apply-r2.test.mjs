import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
import { planSyntheticConfiguration } from '../packages/core/src/syntheticConfiguration.js'
import { importConfiguration } from '../lib/integrations/configFormats.js'
import { runCli } from '../packages/cli/index.js'
const configuration = (format, source) => ({ schema: 'armorbreak.configuration-import/v1', format, source })
const provider = { request: async () => 'allowed-once' }
async function setup(t) {
  const root = await mkdtemp(join(tmpdir(), 'ab-config-apply-')), workspace = join(root, 'workspace'); await mkdir(workspace)
  t.after(() => rm(root, { recursive: true, force: true }))
  const stateRoot = join(root, 'state'), runtime = new ArmorBreakRuntime({ stateRoot }); await runtime.init()
  return { root, workspace, stateRoot, runtime }
}

for (const format of ['json','yaml','cordis','purge-preset']) test(`${format}: profile preview -> approved synthetic apply -> raw-byte restore`, async t => {
  const { runtime } = await setup(t)
  const source = format === 'json' ? '{"privatePin":"1234","unknown":false}\r\n' : format === 'yaml' ? 'privatePin: "1234"\r\nunknown: false\r\n'
    : format === 'cordis' ? '- id: fixture\r\n  name: example/inert\r\n  disabled: true\r\n  config:\r\n    privatePin: "1234"\r\n'
      : { preset: 'name: privatePreset\r\nfuture: false\r\n', agent: '- id: fixture\r\n  name: example/inert\r\n  disabled: true\r\n  config:\r\n    privatePin: "1234"\r\n' }
  const original = configuration(format, source)
  const values = ['cordis','purge-preset'].includes(format) ? { composition: [{ id: 'fixture', name: 'example/inert', disabled: true, config: { privatePin: '5678' } }] } : { privatePin: '5678' }
  const { lab, plan, preview } = await planSyntheticConfiguration(runtime, { configuration: original, profiles: [{ id: 'privateProfile', values }], selectedProfile: 'privateProfile', conflictPolicy: 'last-wins', operator: 'test', sessionId: 'test-session' })
  t.after(() => rm(lab.root, { recursive: true, force: true }))
  assert.doesNotMatch(JSON.stringify({ plan, preview }), /privatePin|privatePreset|privateProfile|1234|5678|beforeSha256|afterSha256/)
  await assert.rejects(() => lab.apply(plan.planId), /PROVIDER_REQUIRED/)
  await lab.apply(plan.planId, provider)
  const resultSource = format === 'purge-preset' ? { preset: await readFile(join(lab.data, 'preset.txt'), 'utf8'), agent: await readFile(join(lab.data, 'agent.txt'), 'utf8') } : await readFile(join(lab.data, 'config.txt'), 'utf8')
  const parsed = importConfiguration(configuration(format, resultSource)).document.data
  const pin = format === 'cordis' ? parsed[0].config.privatePin : format === 'purge-preset' ? parsed.composition[0].config.privatePin : parsed.privatePin
  assert.equal(pin, '5678')
  if (format === 'purge-preset') assert.equal(parsed.metadata.future, false)
  await lab.rollback(plan.planId, provider)
  for (const [name, bytes] of format === 'purge-preset' ? [['preset.txt', source.preset], ['agent.txt', source.agent]] : [['config.txt', source]]) assert.deepEqual(await readFile(join(lab.data, name)), Buffer.from(bytes))
})

test('two-file Purge failure after first write recovers both original files, with separate rollback approval', async t => {
  const { runtime } = await setup(t), source = { preset: 'name: old\r\n', agent: '- id: fixture\r\n  name: inert\r\n' }
  const { lab, plan } = await planSyntheticConfiguration(runtime, { configuration: configuration('purge-preset', source), overlays: [{ id: 'new', values: { metadata: { name: 'new' } } }], conflictPolicy: 'last-wins', operator: 'test', sessionId: 'session' })
  t.after(() => rm(lab.root, { recursive: true, force: true }))
  await assert.rejects(() => lab.apply(plan.planId, provider, () => { throw new Error('INJECTED_BETWEEN_FILES') }), /INJECTED_BETWEEN_FILES/)
  assert.notEqual(await readFile(join(lab.data, 'preset.txt'), 'utf8'), source.preset)
  await assert.rejects(() => lab.rollback(plan.planId, { request: async () => 'denied' }), /APPROVAL_DENIED/)
  await lab.rollback(plan.planId, provider)
  assert.deepEqual(await readFile(join(lab.data, 'preset.txt')), Buffer.from(source.preset))
  assert.deepEqual(await readFile(join(lab.data, 'agent.txt')), Buffer.from(source.agent))
})

test('CLI host bridge stages, refuses standalone self-approval, applies and reverts only with trusted session provider', async t => {
  const { root, workspace, stateRoot } = await setup(t), file = join(workspace, 'request.json')
  const request = { schema: 'armorbreak.configuration-lab-request/v1', configuration: configuration('yaml', 'privatePin: "1234"\r\n'), overlays: [{ id: 'privateLabel', values: { privatePin: '5678' } }], conflictPolicy: 'last-wins' }
  await writeFile(file, JSON.stringify(request))
  const env = { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'host-fixture' }
  const dependencies = { env, sessionId: 'host-session', agent: 'host-agent', callId: 'host-call', approvalProvider: provider }
  const call = async (args, deps = dependencies) => {
    let output = ''; const original = process.stdout.write
    process.stdout.write = function (chunk) { output += chunk; return true }
    try { await runCli(['config', ...args, '--json'], deps); return JSON.parse(output) } finally { process.stdout.write = original }
  }
  const staged = await call(['stage','--bundle',file]); t.after(() => rm(staged.lab, { recursive: true, force: true }))
  assert.doesNotMatch(JSON.stringify(staged), /privatePin|privateLabel|1234|5678/)
  const args = ['--lab', staged.lab, '--plan', staged.planId]
  const publicCli = spawnSync(process.execPath, ['packages/cli/index.js','config','apply', ...args,'--json'], { env, encoding: 'utf8', timeout: 30000 })
  assert.equal(publicCli.status, 1); assert.match(publicCli.stderr, /TRUSTED_APPROVAL_PROVIDER_REQUIRED/)
  await assert.rejects(() => call(['apply',...args,'--yes']), /UNKNOWN_OPTION/)
  await assert.rejects(() => call(['apply',...args], { ...dependencies, sessionId: 'wrong-session' }), /CONTEXT_BINDING/)
  await assert.rejects(() => call(['apply',...args], { ...dependencies, approvalProvider: { request: async () => 'denied' } }), { code: 'TRUSTED_APPROVAL_DENIED' })
  assert.equal((await call(['status','--lab',staged.lab])).state, 'PLANNED')
  assert.equal((await call(['apply',...args])).state, 'COMMITTED')
  assert.equal(importConfiguration(configuration('yaml', await readFile(join(staged.lab,'data','config.txt'),'utf8'))).document.data.privatePin,'5678')
  assert.equal((await call(['revert',...args])).state, 'ROLLED_BACK')
  assert.deepEqual(await readFile(join(staged.lab,'data','config.txt')),Buffer.from('privatePin: "1234"\r\n'))
  assert.equal(await readFile(file,'utf8'),JSON.stringify(request))
  const outside = join(root,'outside.json'); await writeFile(outside,JSON.stringify(request))
  await assert.rejects(() => call(['stage','--bundle',outside]), /scope|outside|workspace/i)
})
