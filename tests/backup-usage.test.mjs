import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { link, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createMcpServer } from '../packages/mcp-server/index.js'

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ab-backup-usage-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const workspace = join(root, 'workspace')
  const store = join(workspace, 'backup-store')
  const complete = join(store, 'backups', '2026-11-26T120000Z-abcd')
  const pending = join(store, 'backups', '2026-11-26T120001Z-abcd')
  const objects = join(store, 'objects')
  for (const directory of [complete, pending, objects]) await mkdir(directory, { recursive: true })
  const manifest = JSON.stringify({ complete: true, reason: 'SYNTHETIC_PRIVATE_REASON' })
  await writeFile(join(complete, 'manifest.json'), manifest)
  await writeFile(join(complete, 'data.json'), '1234')
  await writeFile(join(pending, 'manifest.json'), '{"complete":false}')
  await writeFile(join(pending, 'uncommitted.json'), 'ignore pending bytes')
  await writeFile(join(objects, 'object'), Buffer.alloc(256))
  await writeFile(join(store, 'unlisted.txt'), 'do not count unrelated data')
  const principal = { id: 'backup-usage-test', kind: 'local-user', workspaces: [workspace] }
  const { server, engine } = await createMcpServer({ principal, workspaceId: workspace, stateRoot: join(root, 'mcp-state') })
  t.after(() => engine.close())
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const run = async (target, options = {}) => JSON.parse(await server.handleLine(JSON.stringify({
    jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'maintenance.backup_usage', target, options } },
  })))
  return { root, workspace, store, objects, complete, manifest, run }
}

test('backup usage measures a complete-declared snapshot and object storage through real CLI and MCP', async t => {
  const f = await fixture(t)
  const mcp = await f.run(f.store)
  assert.equal(mcp.result.isError, false)
  const result = JSON.parse(mcp.result.content[0].text)
  assert.ok(result.evidenceIds.length && result.reportPath)
  const { count, bytes, snapshots, objects, unconfirmedSnapshots, ignoredFiles, restoreVerified } = result.data
  assert.deepEqual({ count, bytes, snapshots, objects, unconfirmedSnapshots, ignoredFiles, restoreVerified }, {
    count: 1, bytes: Buffer.byteLength(f.manifest) + 260, snapshots: Buffer.byteLength(f.manifest) + 4,
    objects: 256, unconfirmedSnapshots: 1, ignoredFiles: 1, restoreVerified: false,
  })
  const cli = execFileSync(process.execPath, ['packages/cli/index.js', 'maintenance', 'backup-usage', '--root', f.store, '--json'], {
    encoding: 'utf8', timeout: 30000, env: { ...process.env, ARMORBREAK_WORKSPACE: f.workspace, ARMORBREAK_STATE_ROOT: join(f.root, 'cli-state') },
  })
  assert.deepEqual(JSON.parse(cli).data, result.data)
  assert.doesNotMatch(cli + await readFile(result.reportPath, 'utf8'), /SYNTHETIC_PRIVATE_REASON/)
  assert.equal(await readFile(join(f.complete, 'manifest.json'), 'utf8'), f.manifest)
})

test('backup usage denies mutation flags, external roots and linked objects', async t => {
  const f = await fixture(t)
  assert.equal((await f.run(f.store, { prune: true })).result.isError, true)
  assert.equal((await f.run(f.root)).result.isError, true)
  const outside = join(f.root, 'outside')
  await writeFile(outside, 'private fixture')
  await link(outside, join(f.objects, 'aliased-object'))
  const denied = await f.run(f.store)
  assert.equal(denied.result.isError, true)
  assert.match(denied.result.content[0].text, /multiple hard links/)
  assert.equal(await readFile(outside, 'utf8'), 'private fixture')
})

test('verification measures an exact snapshot closure and its shared objects, but grants no restore', async t => {
  const f = await fixture(t)
  const id = '2026-11-26T120000Z-abcd', bytes = '1234'
  const digest = createHash('sha256').update(bytes).digest('hex')
  const object = Buffer.alloc(40 * 1024, 0x61), objectDigest = createHash('sha256').update(object).digest('hex')
  const expected = { schema: 2, complete: true, id, sums: { 'data.json': digest }, blobs: { 'settings/large.txt': objectDigest }, home: 'PRIVATE_HOST_DIR' }
  const manifest = join(f.complete, 'manifest.json'), blob = join(f.objects, objectDigest)
  await writeFile(manifest, JSON.stringify(expected))
  await writeFile(blob, object)
  const verify = () => f.run(f.store, { verifySnapshot: id })
  const { result } = await verify()
  assert.equal(result.isError, false)
  const value = JSON.parse(result.content[0].text)
  assert.equal(value.data.status, 'DECLARED_CONTENT_MATCH')
  assert.equal(value.data.snapshotFiles, 1)
  assert.equal(value.data.referencedObjects, 1)
  assert.equal(value.data.restoreVerified, false)
  assert.equal(value.data.manifestAuthenticated, false)
  assert.doesNotMatch(JSON.stringify(value) + await readFile(value.reportPath, 'utf8'), /PRIVATE_HOST_DIR|data\.json/)

  const output = execFileSync(process.execPath, ['packages/cli/index.js','maintenance','verify-snapshot','--root',f.store,'--snapshot',id,'--json'], {
    encoding: 'utf8', timeout: 30000, env: { ...process.env, ARMORBREAK_WORKSPACE: f.workspace, ARMORBREAK_STATE_ROOT: join(f.root, 'verify-cli-state') },
  })
  assert.deepEqual(JSON.parse(output).data, value.data)

  const reject = async pattern => {
    const { result } = await verify()
    assert.equal(result.isError, true)
    assert.match(result.content[0].text, pattern)
  }
  await writeFile(blob, 'changed')
  await reject(/object content does not match/)
  await writeFile(blob, object)
  await writeFile(join(f.complete, 'extra.txt'), 'extra')
  await reject(/files differ from the declared file set/)
  await rm(join(f.complete, 'extra.txt'))
  await writeFile(manifest, JSON.stringify({ ...expected, blobs: {'DATA.json': objectDigest} }))
  await reject(/declared both inline and as an object/)
  await writeFile(manifest, JSON.stringify({ ...expected, sums: { '../outside.txt': digest } }))
  await reject(/invalid maintenance relative path/)
  await writeFile(manifest, JSON.stringify(expected).replace('"sums":{', `"sums":{"data.json":"${digest}",`))
  await reject(/invalid backup manifest JSON/)
})
