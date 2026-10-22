import assert from 'node:assert/strict'
import { readFile, mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { request as httpsRequest } from 'node:https'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { createMcpHttpServer } from '../packages/mcp-server/http.js'

test('MCP HTTP supports explicit TLS with a test certificate', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-tls-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tls-ws-'))
  const principal = { id: 'tls-test', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  const tls = { key: await readFile('tests/fixtures/tls/key.pem', 'utf8'), cert: await readFile('tests/fixtures/tls/cert.pem', 'utf8') }
  const server = await createMcpHttpServer({ engine, principal, workspaceId: workspace, tls })
  try {
    assert.match(server.url, /^https:\/\//)
    const result = await new Promise((resolve, reject) => {
      const req = httpsRequest({ hostname: server.host, port: server.port, path: '/mcp', method: 'POST', rejectUnauthorized: false, headers: { 'content-type': 'application/json' } }, (res) => {
        let body = ''
        res.on('data', (chunk) => { body += chunk })
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(body) }))
      })
      req.on('error', reject)
      req.end(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
    })
    assert.equal(result.status, 200)
    assert.equal(result.body.result.protocolVersion, '2025-06-18')
  } finally {
    await server.close()
    await engine.close()
  }
})
