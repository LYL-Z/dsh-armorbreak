import assert from 'node:assert/strict'
import test from 'node:test'
import { createServer } from 'node:http'
import { ResourceFetcher } from '../lib/connectivity/resourceFetcher.js'

async function server(handler) {
  const instance = createServer(handler)
  await new Promise((resolve) => instance.listen(0, '127.0.0.1', resolve))
  const port = instance.address().port
  return { instance, url: `http://127.0.0.1:${port}/feed` }
}

test('RESOURCE_READ is disabled by default and unknown connectors are rejected', async () => {
  const fetcher = new ResourceFetcher({ allowNetwork: false })
  await assert.rejects(() => fetcher.fetch('cisa-kev'), /disabled by policy/)
  await assert.rejects(() => new ResourceFetcher({ allowNetwork: true }).fetch('unknown'), /not allowlisted/)
})

test('only a fixed https connector registry is fetched; arbitrary URLs cannot be passed', async () => {
  const fetcher = new ResourceFetcher({ allowNetwork: true, fetchImpl: async () => ({ ok: true, status: 200, headers: new Map(), arrayBuffer: async () => new ArrayBuffer(2) }) })
  await assert.rejects(() => fetcher.fetch('https://evil.example/'), /not allowlisted/)
  // A test connector may use http via injected fetch; production registry is https-only.
  const custom = new ResourceFetcher({ allowNetwork: true, connectors: { test: { title: 'test', url: 'https://fixture.example/x', license: 'test' } }, fetchImpl: async (url, init) => ({ ok: true, status: 200, headers: new Map([['content-type', 'application/json'], ['etag', 'v1']]), arrayBuffer: async () => new TextEncoder().encode('{"ok":true}').buffer }) })
  const result = await custom.fetch('test')
  assert.equal(result.connector, 'test')
  assert.equal(result.permission, 'RESOURCE_READ')
  assert.equal(result.activeTesting, false)
  assert.equal(result.data.ok, true)
  assert.equal(result.sha256.length, 64)
})

test('redirects, HTTP errors and size limits are rejected', async () => {
  const redirect = new ResourceFetcher({ allowNetwork: true, connectors: { r: { title: 'r', url: 'https://fixture.example/r', license: 'x' } }, fetchImpl: async () => ({ ok: false, status: 302, headers: new Map(), arrayBuffer: async () => new ArrayBuffer(0) }) })
  await assert.rejects(() => redirect.fetch('r'), /redirect/)
  const error = new ResourceFetcher({ allowNetwork: true, connectors: { e: { title: 'e', url: 'https://fixture.example/e', license: 'x' } }, fetchImpl: async () => ({ ok: false, status: 503, headers: new Map(), arrayBuffer: async () => new ArrayBuffer(0) }) })
  await assert.rejects(() => error.fetch('e'), /HTTP 503/)
  const tooLarge = new ResourceFetcher({ allowNetwork: true, maxBytes: 1024, connectors: { l: { title: 'l', url: 'https://fixture.example/l', license: 'x' } }, fetchImpl: async () => ({ ok: true, status: 200, headers: new Map([['content-length', '999999']]), arrayBuffer: async () => new ArrayBuffer(10) }) })
  await assert.rejects(() => tooLarge.fetch('l'), /exceeds/)
})

test('non-json resources are still bounded and hashed', async () => {
  const fetcher = new ResourceFetcher({ allowNetwork: true, connectors: { t: { title: 't', url: 'https://fixture.example/t', license: 'x' } }, fetchImpl: async () => ({ ok: true, status: 200, headers: new Map(), arrayBuffer: async () => new TextEncoder().encode('hello').buffer }) })
  const result = await fetcher.fetch('t')
  assert.equal(result.bytes, 5)
  assert.match(result.sha256, /^[a-f0-9]{64}$/)
  assert.equal(result.text, 'hello')
  assert.equal(result.activeTesting, false)
})
