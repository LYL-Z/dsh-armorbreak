import assert from 'node:assert/strict'
import fs, { link, mkdir, mkdtemp, readdir, readFile, symlink, writeFile } from 'node:fs/promises'
import fsSync from 'node:fs'
import { renameSync, symlinkSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createCoreDaemon } from '../packages/core-daemon/index.js'
import { ArmorBreakClient } from '../packages/sdk-ts/index.js'

test('Core daemon supports three clients and survives restart', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-daemon-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-ws-'))
  const principal = { id: 'daemon-test', kind: 'local-user', workspaces: [workspace] }
  await writeFile(join(workspace, 'sample.txt'), 'daemon sample')
  const daemon = await createCoreDaemon({ stateRoot, workspace, principal })
  const mcpToken = daemon.mcpToken
  const taskIds = []
  let restoredSessionId
  try {
    assert.equal(typeof mcpToken, 'string')
    assert.ok(Buffer.byteLength(mcpToken) >= 32)
    assert.equal(Object.keys(daemon).includes('mcpToken'), false, 'the bearer must not appear in enumerable daemon output')
    const lock = await readFile(join(stateRoot, 'daemon.json'), 'utf8')
    assert.equal(lock.includes(mcpToken), false, 'the bearer must not be written to daemon.json')
    const rejected = await fetch(daemon.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
    })
    assert.equal(rejected.status, 401, 'daemon must reject requests without its generated bearer')

    const clients = [1, 2, 3].map(() => new ArmorBreakClient({ baseUrl: daemon.url, token: mcpToken, principal, workspaceId: workspace }))
    const results = await Promise.all(clients.map((client) => client.analyze({ capability: 'forensics.hash', target: join(workspace, 'sample.txt') })))
    for (const result of results) {
      assert.equal(result.state, 'COMPLETED')
      assert.ok(result.evidenceIds.length >= 1)
      taskIds.push(result.taskId)
    }
    assert.equal(new Set(taskIds).size, 3)
    for (let index = 0; index < clients.length; index += 1) {
      const visibleTasks = await clients[index].tasks()
      assert.deepEqual(visibleTasks.map((task) => task.id), [taskIds[index]], 'each client session sees only its own tasks')
    }
    restoredSessionId = clients[0].sessionId
    const sessions = await readFile(join(stateRoot, 'mcp-http-sessions.json'), 'utf8')
    assert.ok(sessions.includes(restoredSessionId), 'daemon sessions persist so an authorized client can reconnect after restart')
    assert.equal(sessions.includes(mcpToken), false, 'session persistence must not include the bearer')
    await assert.rejects(() => createCoreDaemon({ stateRoot, workspace, principal }), (error) => error.code === 'DAEMON_LOCKED')
  } finally {
    await daemon.stop()
  }
  const restarted = await createCoreDaemon({ stateRoot, workspace, principal, mcpToken })
  try {
    const client = new ArmorBreakClient({ baseUrl: restarted.url, token: restarted.mcpToken, sessionId: restoredSessionId, principal, workspaceId: workspace })
    const tasks = await client.tasks()
    assert.deepEqual(tasks.map((task) => task.id), [taskIds[0]], 'restored session keeps its own task scope across daemon restart')
    const fresh = new ArmorBreakClient({ baseUrl: restarted.url, token: restarted.mcpToken, principal, workspaceId: workspace })
    assert.deepEqual(await fresh.tasks(), [], 'a new session cannot see tasks from previous clients')
  } finally {
    await restarted.stop()
  }
})

test('concurrent Core daemon startup atomically grants one lock owner', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-daemon-race-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-race-ws-'))
  const principal = { id: 'daemon-race-test', kind: 'local-user', workspaces: [workspace] }
  const outcomes = await Promise.allSettled([
    createCoreDaemon({ stateRoot, workspace, principal }),
    createCoreDaemon({ stateRoot, workspace, principal }),
  ])
  const daemons = outcomes.filter((item) => item.status === 'fulfilled').map((item) => item.value)
  const rejected = outcomes.filter((item) => item.status === 'rejected')
  try {
    assert.equal(daemons.length, 1, 'only the process that created daemon.json may start')
    assert.equal(rejected.length, 1)
    assert.equal(rejected[0].reason.code, 'DAEMON_LOCKED')
  } finally {
    await Promise.all(daemons.map((daemon) => daemon.stop()))
  }
})

test('Core daemon refuses a hard-linked stale lock instead of reusing it', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-daemon-linked-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-linked-ws-'))
  const principal = { id: 'daemon-linked-test', kind: 'local-user', workspaces: [workspace] }
  const protectedPath = join(stateRoot, 'protected.json')
  const lockPath = join(stateRoot, 'daemon.json')
  const original = `${JSON.stringify({ schemaVersion: 'armorbreak.core-daemon/v1', pid: 2147483647, startedAt: 'stale' })}\n`
  await writeFile(protectedPath, original)
  await link(protectedPath, lockPath)

  await assert.rejects(
    () => createCoreDaemon({ stateRoot, workspace, principal }),
    (error) => error.code === 'DAEMON_LOCK_UNSAFE',
  )
  assert.equal(await readFile(protectedPath, 'utf8'), original)
})

test('Core daemon leaves stale locks untouched when the stateRoot could be swapped before stale recovery', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'abm-daemon-stale-swap-'))
  const stateRoot = join(parent, 'state')
  const retained = join(parent, 'state-retained')
  const outside = await mkdtemp(join(tmpdir(), 'abm-daemon-stale-outside-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-stale-ws-'))
  const principal = { id: 'daemon-stale-swap-test', kind: 'local-user', workspaces: [workspace] }
  await mkdir(stateRoot)
  const stale = `${JSON.stringify({ schemaVersion: 'armorbreak.core-daemon/v1', pid: 2147483647, startedAt: 'stale-internal-lock' })}\n`
  const outsideSentinel = `${JSON.stringify({ schemaVersion: 'armorbreak.core-daemon/v1', pid: 2147483647, startedAt: 'outside-sentinel-must-survive' })}\n`
  await writeFile(join(stateRoot, 'daemon.json'), stale)
  await writeFile(join(outside, 'daemon.json'), outsideSentinel)

  let swapped = false
  const originalRename = fsSync.renameSync
  fsSync.renameSync = (from, to) => {
    if (!swapped && String(from).toLowerCase() === join(stateRoot, 'daemon.json').toLowerCase()) {
      originalRename(stateRoot, retained)
      symlinkSync(outside, stateRoot, process.platform === 'win32' ? 'junction' : 'dir')
      swapped = true
    }
    return originalRename(from, to)
  }
  syncBuiltinESMExports()

  try {
    await assert.rejects(
      () => createCoreDaemon({ stateRoot, workspace, principal }),
      (error) => error.code === 'DAEMON_LOCK_STALE',
    )
    assert.equal(swapped, false, 'stale-lock recovery must not perform a path-based rename')
    assert.equal(await readFile(join(stateRoot, 'daemon.json'), 'utf8'), stale)
    assert.equal(await readFile(join(outside, 'daemon.json'), 'utf8'), outsideSentinel)
  } finally {
    fsSync.renameSync = originalRename
    syncBuiltinESMExports()
    await fs.rm(parent, { recursive: true, force: true })
    await fs.rm(outside, { recursive: true, force: true })
    await fs.rm(workspace, { recursive: true, force: true })
  }
})

test('Core daemon refuses a symlinked or junction state root before writing outside it', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'abm-daemon-junction-state-'))
  const linkedStateRoot = join(parent, 'configured-state')
  const outsideTarget = join(parent, 'outside-target')
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-junction-ws-'))
  const principal = { id: 'daemon-junction-test', kind: 'local-user', workspaces: [workspace] }
  await mkdir(outsideTarget)
  await symlink(outsideTarget, linkedStateRoot, process.platform === 'win32' ? 'junction' : 'dir')

  await assert.rejects(
    () => createCoreDaemon({ stateRoot: linkedStateRoot, workspace, principal }),
    (error) => error.code === 'DAEMON_PATH_UNSAFE',
  )
  assert.deepEqual(await readdir(outsideTarget), [], 'a linked state root must not receive daemon or approval files')
})

test('Core daemon rejects a stateRoot junction swapped at lock creation before writing state outside it', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'abm-daemon-parent-swap-'))
  const stateRoot = join(parent, 'state')
  const retained = join(parent, 'state-retained')
  const outside = join(parent, 'outside')
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-parent-swap-ws-'))
  const principal = { id: 'daemon-parent-swap-test', kind: 'local-user', workspaces: [workspace] }
  await mkdir(stateRoot)
  await mkdir(outside)

  let swapped = false
  const originalOpen = fsSync.openSync
  fsSync.openSync = (file, ...args) => {
    if (!swapped && String(file).toLowerCase() === join(stateRoot, 'daemon.json').toLowerCase()) {
      renameSync(stateRoot, retained)
      symlinkSync(outside, stateRoot, process.platform === 'win32' ? 'junction' : 'dir')
      swapped = true
    }
    return originalOpen(file, ...args)
  }
  syncBuiltinESMExports()

  try {
    await assert.rejects(
      () => createCoreDaemon({ stateRoot, workspace, principal }),
      (error) => error.code === 'DAEMON_PATH_UNSAFE',
    )
    assert.equal(swapped, true)
    assert.deepEqual(await readdir(outside), [], 'a swapped stateRoot must not receive a lock or daemon state')
  } finally {
    fsSync.openSync = originalOpen
    syncBuiltinESMExports()
    await fs.rm(parent, { recursive: true, force: true })
    await fs.rm(workspace, { recursive: true, force: true })
  }
})

test('Core daemon cleanup preserves an outside lock when stateRoot is swapped before rename', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'abm-daemon-stop-swap-'))
  const stateRoot = join(parent, 'state')
  const retained = join(parent, 'state-retained')
  const outside = join(parent, 'outside')
  const workspace = await mkdtemp(join(tmpdir(), 'abm-daemon-stop-swap-ws-'))
  const principal = { id: 'daemon-stop-swap-test', kind: 'local-user', workspaces: [workspace] }
  await mkdir(stateRoot)
  await mkdir(outside)
  const daemon = await createCoreDaemon({ stateRoot, workspace, principal })
  const outsideLock = join(outside, 'daemon.json')
  const outsideSentinel = '{"sentinel":"must-survive-parent-swap"}\n'
  await writeFile(outsideLock, outsideSentinel)
  const originalLock = await readFile(join(stateRoot, 'daemon.json'), 'utf8')

  let swapped = false
  const originalRename = fsSync.renameSync
  fsSync.renameSync = (from, to) => {
    if (!swapped && String(from).toLowerCase() === join(stateRoot, 'daemon.json').toLowerCase()) {
      originalRename(stateRoot, retained)
      symlinkSync(outside, stateRoot, process.platform === 'win32' ? 'junction' : 'dir')
      swapped = true
    }
    return originalRename(from, to)
  }
  syncBuiltinESMExports()

  try {
    await daemon.stop()
    assert.equal(swapped, true, 'the parent swap must land at the lock rename boundary')
    assert.equal(await readFile(outsideLock, 'utf8'), outsideSentinel)
    assert.equal(await readFile(join(retained, 'daemon.json'), 'utf8'), originalLock)
  } finally {
    fsSync.renameSync = originalRename
    syncBuiltinESMExports()
    await fs.rm(parent, { recursive: true, force: true })
    await fs.rm(workspace, { recursive: true, force: true })
  }
})
