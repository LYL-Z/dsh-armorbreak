import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as httpRequest } from 'node:http'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { createMcpHttpServer } from '../packages/mcp-server/http.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-http-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-http-ws-'))
  const principal = { id: 'http-tester', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  return { stateRoot, workspace, principal, engine }
}

async function rpc(url, id, method, params, token) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  })
  return { status: response.status, body: await response.json(), headers: response.headers }
}

test('MCP HTTP transport serves initialize and tools over loopback', async () => {
  const f = await fixture()
  const server = await createMcpHttpServer({ engine: f.engine, principal: f.principal, workspaceId: f.workspace })
  try {
    const init = await rpc(server.url, 1, 'initialize')
    assert.equal(init.status, 200)
    assert.equal(init.body.result.protocolVersion, '2025-06-18')
    assert.match(init.headers.get('mcp-session-id'), /^[a-f0-9-]{36}$/)
    const list = await rpc(server.url, 2, 'tools/list')
    assert.ok(list.body.result.tools.some((tool) => tool.name === 'armorbreak_analyze'))
    const call = await rpc(server.url, 3, 'tools/call', { name: 'armorbreak_capabilities', arguments: {} })
    assert.equal(call.status, 200)
    assert.equal(JSON.parse(call.body.result.content[0].text).length, 46)
    const health = await fetch(`http://${server.host}:${server.port}/health`)
    assert.equal(health.status, 200)
  } finally {
    await server.close()
    await f.engine.close()
  }
})

test('MCP HTTP rejects non-loopback binding and enforces configured bearer token', async () => {
  const f = await fixture()
  await assert.rejects(() => createMcpHttpServer({ engine: f.engine, principal: f.principal, workspaceId: f.workspace, host: '0.0.0.0' }), /loopback/)
  const server = await createMcpHttpServer({ engine: f.engine, principal: f.principal, workspaceId: f.workspace, token: 'test-token' })
  try {
    const unauthorized = await rpc(server.url, 1, 'initialize')
    assert.equal(unauthorized.status, 401)
    const authorized = await rpc(server.url, 2, 'initialize', undefined, 'test-token')
    assert.equal(authorized.status, 200)
  } finally {
    await server.close()
    await f.engine.close()
  }
})


test('MCP HTTP rejects cross-site Origin and malicious Host', async () => {
  const f = await fixture()
  const server = await createMcpHttpServer({ engine: f.engine, principal: f.principal, workspaceId: f.workspace })
  try {
    const evilOrigin = await fetch(server.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://evil.example' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
    })
    assert.equal(evilOrigin.status, 403)
    const status = await new Promise((resolve, reject) => {
      const req = httpRequest({ hostname: server.host, port: server.port, path: '/mcp', method: 'POST', headers: { host: 'evil.example', 'content-type': 'application/json' } }, (res) => { res.resume(); resolve(res.statusCode) })
      req.on('error', reject)
      req.end(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize' }))
    })
    assert.equal(status, 403)
  } finally {
    await server.close()
    await f.engine.close()
  }
})
