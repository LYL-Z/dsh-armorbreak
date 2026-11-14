import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createWorkbenchServer } from '../workbench/server.mjs'
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'abm-panel-')), workspace = join(root, 'workspace'), stateRoot = join(root, 'state')
  t.after(() => rm(root, { recursive: true, force: true }))
  await mkdir(workspace)
  const bundle = JSON.stringify({ schema: 'armorbreak.config-overlay/v1', base: { SYNTHETIC_SECRET: 'do-not-render', enabled: true }, overlays: [{ id: 'readonly', values: { enabled: false } }], conflictPolicy: 'last-wins' })
  const target = join(workspace, 'bundle.json'); await writeFile(target, bundle)
  const server = await createWorkbenchServer({ native: { workspaceId: workspace, stateRoot } })
  t.after(() => server.close())
  const session = await (await fetch(`${server.url}/api/native/session`)).json()
  const post = (body, headers = {}) => fetch(`${server.url}/api/native/run`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-armorbreak-session': session.csrf, ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) })
  return { root, workspace, stateRoot, target, bundle, server, session, post }
}
test('native panel is opt-in and archival state is explicitly historical', async t => {
  const server = await createWorkbenchServer(); t.after(() => server.close())
  const session = await (await fetch(`${server.url}/api/native/session`)).json()
  assert.equal(session.enabled, false)
  assert.equal(session.csrf, null)
  assert.equal((await fetch(`${server.url}/api/native/run`, { method: 'POST' })).status, 503)
  assert.equal((await (await fetch(`${server.url}/api/state`)).json()).evidenceScope, 'HISTORICAL_ACCEPTANCE_RECORDS')
  await assert.rejects(() => createWorkbenchServer({ native: { workspaceId: '.', stateRoot: '.' } }), /explicit absolute/)
})
test('HTTP panel executes actual Core preview and persists task/evidence without changing the input', async t => {
  const f = await fixture(t)
  assert.equal(f.session.enabled, true)
  assert.equal(f.session.authentication, 'NONE')
  assert.equal(f.session.tokenPurpose, 'CSRF_ONLY')
  assert.ok(f.session.capabilities.includes('configuration.preview'))
  const response = await f.post({ capability: 'configuration.preview', target: f.target })
  assert.equal(response.status, 200)
  const result = await response.json()
  assert.equal(result.data.status, 'PREVIEW_READY')
  assert.ok(result.taskId && result.evidenceIds.length && result.reportAvailable)
  assert.equal(result.hostModified, false)
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_SECRET|do-not-render/)
  assert.equal(await readFile(f.target, 'utf8'), f.bundle)
  assert.ok((await readdir(f.stateRoot)).length)
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/)
  assert.equal(response.headers.get('cache-control'), 'no-store')
  const page = await (await fetch(`${f.server.url}/`)).text()
  for (const id of ['native-form', 'native-target', 'native-capability', 'native-output']) assert.ok(page.includes(`id="${id}"`))
})
test('a second unauthenticated HTTP client can obtain CSRF but cannot gain host-write or approval authority', async t => {
  const f = await fixture(t)
  // Independent HTTP connection and no cookies, Origin, login or OS identity.
  // This proves the HTTP boundary, not a second Windows-account execution.
  const stranger = await (await fetch(`${f.server.url}/api/native/session`, { headers: { connection: 'close' } })).json()
  assert.equal(stranger.csrf, f.session.csrf)
  assert.equal(stranger.localClientAccess, 'ANY_LOCAL_PROCESS')
  const post = body => fetch(`${f.server.url}/api/native/run`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-armorbreak-session': stranger.csrf }, body: JSON.stringify(body) })
  assert.equal((await post({ capability: 'configuration.preview', target: f.target })).status, 200)
  for (const capability of ['host.modify', 'maintenance.apply', 'plugin.activate', 'network.probe']) assert.equal((await post({ capability, target: f.target })).status, 400)
  assert.equal((await post({ capability: 'configuration.preview', target: f.target, requestApproval: 'allowed-once' })).status, 400)
  assert.equal((await fetch(`${f.server.url}/api/approve`, { method: 'POST' })).status, 404)
  assert.equal(await readFile(f.target, 'utf8'), f.bundle)
})
test('missing/wrong/non-ASCII token, cross origin and caller principal/permission injection are refused', async t => {
  const f = await fixture(t), input = { capability: 'configuration.preview', target: f.target }
  for (const token of ['', 'a'.repeat(64), 'é'.repeat(64)]) assert.equal((await f.post(input, { 'x-armorbreak-session': token })).status, 403)
  assert.equal((await f.post(input, { Origin: 'http://attacker.invalid' })).status, 403)
  assert.equal((await f.post(input, { 'content-type': 'text/plain' })).status, 403)
  for (const extra of [{ principal: 'admin' }, { approvalToken: 'x' }, { apply: true }, { options: { permission: 'L3' } }]) assert.equal((await f.post({ ...input, ...extra })).status, 400)
  assert.equal((await f.post({ ...input, capability: 'shell.execute' })).status, 400)
})
test('workspace escapes, malformed/oversized requests and stale session tokens fail without path disclosure', async t => {
  const f = await fixture(t), outside = join(f.root, 'PRIVATE_PATH.json')
  await writeFile(outside, f.bundle)
  const escaped = await f.post({ capability: 'configuration.preview', target: outside })
  assert.equal(escaped.status, 400)
  assert.doesNotMatch(await escaped.text(), /PRIVATE_PATH|abm-panel/)
  assert.equal((await f.post('{malformed')).status, 400)
  assert.equal((await f.post(' '.repeat(5000))).status, 400)
  const other = await createWorkbenchServer({ native: { workspaceId: f.workspace, stateRoot: join(f.root, 'other-state') } }); t.after(() => other.close())
  const response = await fetch(`${other.url}/api/native/run`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-armorbreak-session': f.session.csrf }, body: JSON.stringify({ capability: 'configuration.preview', target: f.target }) })
  assert.equal(response.status, 403)
})
