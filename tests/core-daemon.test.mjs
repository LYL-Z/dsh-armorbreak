import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
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
  const taskIds = []
  try {
    const clients = [1, 2, 3].map(() => new ArmorBreakClient({ baseUrl: daemon.url, principal, workspaceId: workspace }))
    const results = await Promise.all(clients.map((client) => client.analyze({ capability: 'forensics.hash', target: join(workspace, 'sample.txt') })))
    for (const result of results) {
      assert.equal(result.state, 'COMPLETED')
      assert.ok(result.evidenceIds.length >= 1)
      taskIds.push(result.taskId)
    }
    assert.equal(new Set(taskIds).size, 3)
    assert.ok((await clients[0].tasks()).length >= 3)
    await assert.rejects(() => createCoreDaemon({ stateRoot, workspace, principal }), (error) => error.code === 'DAEMON_LOCKED')
  } finally {
    await daemon.stop()
  }
  const restarted = await createCoreDaemon({ stateRoot, workspace, principal })
  try {
    const client = new ArmorBreakClient({ baseUrl: restarted.url, principal, workspaceId: workspace })
    const tasks = await client.tasks()
    for (const taskId of taskIds) assert.ok(tasks.some((task) => task.id === taskId))
  } finally {
    await restarted.stop()
  }
})
