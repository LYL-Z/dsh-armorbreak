import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm } from 'node:fs/promises'
import { request as httpRequest } from 'node:http'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { createMcpHttpServer } from '../packages/mcp-server/http.js'

const runtimeTemp = process.env.TEMP ?? join(process.cwd(), '.runtime', 'tmp')

function request(server, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: server.host,
      port: server.port,
      path: '/mcp',
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
    }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => resolve({ status: res.statusCode, body }))
    })
    req.on('error', reject)
    req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  })
}

function requestHealth(server, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: server.host,
      port: server.port,
      path: '/health',
      method: 'GET',
      headers,
    }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => resolve({ status: res.statusCode, body }))
    })
    req.on('error', reject)
    req.end()
  })
}

test('MCP HTTP requires Host and Origin to match the listening authority', async () => {
  const root = await mkdtemp(join(runtimeTemp, 'mcp-http-origin-authority-'))
  const stateRoot = join(root, 'state')
  const workspace = join(root, 'workspace')
  await mkdir(workspace, { recursive: true })
  const principal = { id: 'origin-authority-tester', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  const server = await createMcpHttpServer({
    engine,
    principal,
    workspaceId: workspace,
    token: 'origin-test-token',
  })

  try {
    const endpoint = new URL(server.url)
    const authority = endpoint.host
    const validHeaders = {
      host: authority,
      origin: endpoint.origin,
      authorization: 'Bearer origin-test-token',
    }

    const accepted = await request(server, validHeaders)
    assert.equal(accepted.status, 200)

    const wrongPort = server.port === 65535 ? server.port - 1 : server.port + 1
    const wrongPortOrigin = await request(server, {
      host: authority,
      origin: `http://127.0.0.1:${wrongPort}`,
    })
    assert.equal(wrongPortOrigin.status, 403, 'wrong-port loopback Origin must be denied before authentication')
    assert.deepEqual(JSON.parse(wrongPortOrigin.body), { error: 'origin not allowed' })

    const wrongHostPort = await request(server, {
      host: `127.0.0.1:${wrongPort}`,
      authorization: 'Bearer origin-test-token',
    })
    assert.equal(wrongHostPort.status, 403, 'a loopback Host with a different port must be denied')
    assert.deepEqual(JSON.parse(wrongHostPort.body), { error: 'host not allowed' })

    const originWithPath = await request(server, {
      ...validHeaders,
      origin: `${endpoint.origin}/untrusted-path`,
    })
    assert.equal(originWithPath.status, 403, 'Origin must be an origin value, not a URL path')

    const wrongScheme = await request(server, {
      ...validHeaders,
      origin: `https://${authority}`,
    })
    assert.equal(wrongScheme.status, 403, 'Origin scheme must match the local endpoint scheme')

    const noOrigin = await request(server, {
      host: authority,
      authorization: 'Bearer origin-test-token',
    })
    assert.equal(noOrigin.status, 200, 'non-browser clients without Origin remain supported')

    const health = await requestHealth(server, { host: authority, origin: endpoint.origin })
    assert.equal(health.status, 200)
    assert.deepEqual(JSON.parse(health.body), { ok: true })
    const badHealthOrigin = await requestHealth(server, { host: authority, origin: 'http://127.0.0.1:' + wrongPort })
    assert.equal(badHealthOrigin.status, 403, 'health must validate Origin before its early response')
    assert.deepEqual(JSON.parse(badHealthOrigin.body), { error: 'origin not allowed' })
    const badHealthHost = await requestHealth(server, { host: '127.0.0.1:' + wrongPort })
    assert.equal(badHealthHost.status, 403, 'health must validate Host before its early response')
    assert.deepEqual(JSON.parse(badHealthHost.body), { error: 'host not allowed' })
  } finally {
    await server.close()
    await engine.close()
    await rm(root, { recursive: true, force: true })
  }
})
