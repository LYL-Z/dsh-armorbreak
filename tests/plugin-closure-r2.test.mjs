import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, copyFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { createMcpServer } from '../packages/mcp-server/index.js'
import { canonicalConfig } from '../lib/integrations/configOverlay.js'
import { createPluginReviewer, pluginAttestationPayload } from '../lib/catalog/pluginLifecycle.js'
import { verifyPluginClosure } from '../lib/catalog/pluginPackage.js'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
import { planSyntheticPluginUpdate } from '../packages/core/src/syntheticPlugin.js'
const sha = text => createHash('sha256').update(text).digest('hex')
const repository = 'https://github.com/example/self-authored-fixture'
async function setup(t) {
  const root = await mkdtemp(join(tmpdir(), 'ab-plugin-closure-')), workspace = join(root, 'workspace'), target = join(workspace, 'package')
  await mkdir(target, { recursive: true })
  t.after(() => rm(root, { recursive: true, force: true }))
  const manifest = { schema: 'armorbreak.plugin-catalog/v1', plugins: [{ id: 'inert', version: '1.0.0', source: { repository, commit: 'a'.repeat(40) },
    license: 'MIT', dependencies: [], permissions: ['workspace.read'], platforms: ['win32', 'linux', 'darwin'], channel: 'stable', enabled: false,
    files: [{ path: 'inert.txt', sha256: sha('inert fixture') }] }] }
  const save = () => writeFile(join(target, 'armorbreak-plugin.json'), JSON.stringify(manifest))
  await save(); await writeFile(join(target, 'inert.txt'), 'inert fixture')
  const { server, engine } = await createMcpServer({ principal: { id: 'closure-test', kind: 'local-user', workspaces: [workspace] }, workspaceId: workspace, stateRoot: join(root, 'state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  let id = 1
  const call = async (options = { closure: true }) => JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'plugin.verify', target, options } } }))).result
  let lastResult
  const snapshot = async () => { const result = await call(); assert.equal(result.isError, false, result.content[0].text); lastResult = JSON.parse(result.content[0].text); return lastResult.data }
  const persisted = () => lastResult
  return { root, workspace, target, manifest, save, call, snapshot, persisted }
}

test('full package closure goes through Core/MCP, CLI and persisted artifact without gaining trust', async t => {
  const { root, workspace, target, snapshot, persisted } = await setup(t), value = await snapshot()
  assert.equal(value.verificationStatus, 'LOCAL_PACKAGE_CLOSURE_VERIFIED')
  assert.equal(value.closure.length, 2)
  assert.equal(value.closureSha256, sha(canonicalConfig(value.closure)))
  const taskRoot = join(workspace, '.armorbreak', 'tasks', persisted().taskId)
  assert.deepEqual(JSON.parse(await readFile(join(taskRoot, 'artifacts', 'plugin-review.json'), 'utf8')), value)
  for (const key of ['sourceAuthenticated', 'rightsVerified', 'activationAuthorized', 'releaseEligible', 'policyEligible']) assert.equal(value.plugins[0][key], false)
  const cli = spawnSync(process.execPath, ['packages/cli/index.js', 'plugin', 'verify', '--root', target, '--closure', '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_STATE_ROOT: join(root, 'cli-state') } })
  assert.equal(cli.status, 0, cli.stderr); assert.deepEqual(JSON.parse(cli.stdout).data, value)
})

test('signed closure -> dependency plan -> approved inert staging -> exact-byte rollback, without touching package inputs', async t => {
  const { root, workspace, target, manifest, save } = await setup(t)
  manifest.plugins.push({ ...structuredClone(manifest.plugins[0]), id: 'dependent', dependencies: [{ id: 'inert', version: '1.0.0' }], files: [{ path: 'dependent.js', sha256: sha('throw new Error("MUST NEVER EXECUTE")') }] })
  await writeFile(join(target, 'dependent.js'), 'throw new Error("MUST NEVER EXECUTE")'); await save()
  const runtime = new ArmorBreakRuntime({ stateRoot: join(root, 'trusted-state') }); await runtime.init()
  const task = await runtime.workspace(workspace).taskStore.create({ title: 'Inert package staging', targetPath: target, steps: [] })
  const build = (targetPath = target) => runtime.runner.buildCapabilityInput({ task, capability: runtime.registry.get('plugin.verify'), targetPath, options: { closure: true }, controller: new AbortController(), log: [] })
  const candidate = await build()
  let snapshot = await verifyPluginClosure(candidate)
  const key = generateKeyPairSync('ed25519'), publicKey = key.publicKey.export({ type: 'spki', format: 'pem' })
  const reviewer = createPluginReviewer([{ keyId: 'source', role: 'source', repositories: [repository], publicKey }, { keyId: 'rights', role: 'rights', repositories: [repository], publicKey }])
  const receipt = role => { const payload = pluginAttestationPayload(snapshot, role); return { keyId: role, payload, signature: sign(null, Buffer.from(canonicalConfig(payload)), key.privateKey).toString('base64') } }
  const options = { candidate, reviewer, receipts: { sourceReceipt: receipt('source'), rightsReceipt: receipt('rights') }, operator: 'lab-owner', sessionId: 'lab-session' }
  const blocked = { ...options, receipts: {} }
  await assert.rejects(() => planSyntheticPluginUpdate(runtime, blocked), /STAGING_REVIEW_DENIED/)
  const { lab, plan, dependencyOrder, hostWrites } = await planSyntheticPluginUpdate(runtime, options)
  t.after(() => rm(lab.root, { recursive: true, force: true }))
  assert.deepEqual(dependencyOrder, ['inert', 'dependent']); assert.equal(hostWrites, false)
  await assert.rejects(() => lab.apply(plan.planId), /PROVIDER_REQUIRED/)
  assert.equal(await readFile(join(lab.data, 'packages.txt'), 'utf8'), '')
  const approved = { request: async () => 'allowed-once' }
  assert.equal((await lab.apply(plan.planId, approved)).state, 'COMMITTED')
  const bytes = await readFile(join(lab.data, 'packages.txt'))
  assert.ok(JSON.parse(bytes).files.some(file => file.path === 'dependent.js'))
  assert.equal(await readFile(join(target, 'dependent.js'), 'utf8'), 'throw new Error("MUST NEVER EXECUTE")')
  assert.equal((await lab.rollback(plan.planId, approved)).state, 'ROLLED_BACK')
  assert.deepEqual(await readFile(join(lab.data, 'packages.txt')), Buffer.alloc(0))
  await assert.rejects(() => lab.apply(plan.planId, approved), /STATE_DENIED/)
  // Existing synthetic baseline captured independently; a partial write can be explicitly restored.
  const oldRoot = join(workspace, 'previous'); await mkdir(oldRoot)
  for (const name of ['armorbreak-plugin.json', 'inert.txt', 'dependent.js']) await copyFile(join(target, name), join(oldRoot, name))
  manifest.plugins[0].version = '2.0.0'; manifest.plugins[1].dependencies[0].version = '2.0.0'; await save()
  snapshot = await verifyPluginClosure(await build())
  const next = await planSyntheticPluginUpdate(runtime, { ...options, receipts: { sourceReceipt: receipt('source'), rightsReceipt: receipt('rights') }, current: await build(oldRoot), candidate: await build() })
  t.after(() => rm(next.lab.root, { recursive: true, force: true }))
  const original = await readFile(join(next.lab.data, 'packages.txt'))
  await assert.rejects(() => next.lab.apply(next.plan.planId, approved, () => { throw new Error('INJECTED_AFTER_WRITE') }), /INJECTED_AFTER_WRITE/)
  assert.notDeepEqual(await readFile(join(next.lab.data, 'packages.txt')), original)
  assert.equal((await next.lab.rollback(next.plan.planId, approved)).state, 'ROLLED_BACK')
  assert.deepEqual(await readFile(join(next.lab.data, 'packages.txt')), original)
})

for (const name of ['hidden.txt', '.hidden', 'node_modules/undeclared.js', 'dist/undeclared.js']) test(`strict closure rejects unlisted ${name}`, async t => {
  const { target, call } = await setup(t)
  const parts = name.split('/'); if (parts.length > 1) await mkdir(join(target, parts[0]))
  await writeFile(join(target, ...parts), 'not executed')
  const result = await call(); assert.equal(result.isError, true); assert.match(result.content[0].text, /undeclared/)
})

test('strict closure rejects even an unlisted junction rather than silently skipping it', async t => {
  const { target, root, call } = await setup(t), outside = join(root, 'outside')
  await mkdir(outside); await writeFile(join(outside, 'outside.txt'), 'outside')
  await symlink(outside, join(target, 'unlisted-link'), process.platform === 'win32' ? 'junction' : 'dir')
  const result = await call(); assert.equal(result.isError, true); assert.match(result.content[0].text, /INVENTORY_LINK|symbolic links/)
  assert.equal(await readFile(join(outside, 'outside.txt'), 'utf8'), 'outside')
})

test('closure rejects missing bytes, cross-plugin ownership collisions and depth truncation', async t => {
  const { target, manifest, save, call } = await setup(t)
  manifest.plugins.push({ ...manifest.plugins[0], id: 'other' }); await save()
  assert.equal((await call()).isError, true)
  manifest.plugins.pop(); await save()
  await mkdir(join(target, ...Array(10).fill('deep')), { recursive: true })
  const deep = await call(); assert.equal(deep.isError, true); assert.match(deep.content[0].text, /depth/)
  await rm(join(target, 'deep'), { recursive: true })
  await rm(join(target, 'inert.txt')); assert.equal((await call()).isError, true)
})

test('pinned source and rights attesters are separate, digest-bound and scoped; no production or execution grant', async t => {
  const { snapshot } = await setup(t), value = await snapshot()
  // Ephemeral TEST ONLY signing keys. No files, production key, GitHub App or Check.
  const source = generateKeyPairSync('ed25519'), rights = generateKeyPairSync('ed25519'), attacker = generateKeyPairSync('ed25519')
  const reviewer = createPluginReviewer([{ keyId: 'source-test', role: 'source', repositories: [repository], publicKey: source.publicKey.export({ type: 'spki', format: 'pem' }) },
    { keyId: 'rights-test', role: 'rights', repositories: [repository], publicKey: rights.publicKey.export({ type: 'spki', format: 'pem' }) }])
  const receipt = (role, key, keyId) => { const payload = pluginAttestationPayload(value, role); return { keyId, payload, signature: sign(null, Buffer.from(canonicalConfig(payload)), key).toString('base64') } }
  const sourceReceipt = receipt('source', source.privateKey, 'source-test'), rightsReceipt = receipt('rights', rights.privateKey, 'rights-test')
  assert.equal(reviewer.review(value).state, 'BLOCKED')
  assert.equal(reviewer.review(value, { sourceReceipt }).rightsVerified, false)
  assert.equal(reviewer.review(value, { sourceReceipt: receipt('source', attacker.privateKey, 'source-test'), rightsReceipt }).sourceAuthenticated, false)
  const valid = reviewer.review(value, { sourceReceipt, rightsReceipt })
  assert.equal(valid.state, 'READY_FOR_SYNTHETIC_STAGING_APPROVAL')
  assert.equal(valid.plugins[0].policyEligible, true)
  for (const key of ['activationAuthorized', 'releaseEligible', 'installationPerformed']) assert.equal(valid[key], false)
  const changed = structuredClone(value); changed.plugins[0].version = '2.0.0'
  assert.throws(() => reviewer.review(changed, { sourceReceipt, rightsReceipt }), /METADATA_BINDING/)
  const changedPolicy = structuredClone(value); changedPolicy.plugins[0].riskClassificationEligible = false
  assert.throws(() => reviewer.review(changedPolicy, { sourceReceipt, rightsReceipt }), /METADATA_BINDING/)
  const forged = { ...sourceReceipt, publicKey: attacker.publicKey.export({ type: 'spki', format: 'pem' }) }
  assert.equal(reviewer.review(value, { sourceReceipt: forged, rightsReceipt }).sourceAuthenticated, false)
})
