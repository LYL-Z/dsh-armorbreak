import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
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
