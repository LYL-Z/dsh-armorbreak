import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { NetworkStateMachine } from '../lib/connectivity/networkState.js'
import { ConnectorHealth } from '../lib/connectivity/connectorHealth.js'
import { ResourceFetcher } from '../lib/connectivity/resourceFetcher.js'
import { ResourceSyncManager } from '../lib/connectivity/syncManager.js'

function fetcher(fetchImpl) {
  return new ResourceFetcher({
    allowNetwork: true,
    connectors: {
      good: { title: 'good', url: 'https://fixture.example/good', license: 'test' },
      bad: { title: 'bad', url: 'https://fixture.example/bad', license: 'test' },
    },
    fetchImpl,
  })
}

test('sync stages/activates one source and isolates a failed source', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-sync-'))
  const fetchImpl = async (url) => {
    if (url.includes('/bad')) return { ok: false, status: 503, headers: new Map(), arrayBuffer: async () => new ArrayBuffer(0) }
    return { ok: true, status: 200, headers: new Map([['content-type', 'application/json'], ['etag', '"v1"']]), arrayBuffer: async () => new TextEncoder().encode('{"items":[1,2]}').buffer }
  }
  const network = new NetworkStateMachine({ failThreshold: 2, recoverThreshold: 1 })
  network.probe(true)
  const manager = new ResourceSyncManager({ fetcher: fetcher(fetchImpl), networkState: network, connectorHealth: new ConnectorHealth(), cacheRoot: root })
  const good = await manager.sync('good')
  assert.equal(good.state, 'SYNCED')
  assert.equal(good.activeTesting, false)
  assert.equal((await manager.cache.active('cloud')).version, good.activeVersion)
  const bad = await manager.sync('bad')
  assert.equal(bad.state, 'FAILED')
  assert.equal(network.state, 'OFFLINE')
  const all = await manager.syncAll(['good', 'bad'])
  assert.equal(all.synced, 1)
  assert.equal(all.failed, 1)
})

test('sync refuses to run when RESOURCE_READ is disabled', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-sync-off-'))
  const disabled = new ResourceFetcher({ allowNetwork: false, connectors: { x: { title: 'x', url: 'https://fixture.example/x', license: 'test' } } })
  const manager = new ResourceSyncManager({ fetcher: disabled, networkState: new NetworkStateMachine(), connectorHealth: new ConnectorHealth(), cacheRoot: root })
  await assert.rejects(() => manager.sync('x'), /disabled by policy/)
})
