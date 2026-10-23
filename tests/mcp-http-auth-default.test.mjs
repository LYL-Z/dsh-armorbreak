import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { createMcpHttpServer } from '../packages/mcp-server/http.js'

const runtimeTemp = process.env.TEMP ?? join(process.cwd(), '.runtime', 'tmp')

async function fixture() {
  const root = await mkdtemp(join(runtimeTemp, 'mcp-http-auth-default-'))
  const stateRoot = join(root, 'state')
  const workspace = join(root, 'workspace')
  await mkdir(workspace, { recursive: true })
  const target = join(workspace, 'auth-sample.txt')
  await writeFile(target, 'synthetic MCP authentication fixture\n')
  const principal = { id: 'mcp-auth-tester', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  return { root, stateRoot, workspace, target, principal, engine }
}

async function rpc(url, id, method, params, token) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  })
  return { status: response.status, sessionId: response.headers.get('mcp-session-id'), body: await response.json() }
}

test('MCP HTTP denies unauthenticated identity binding by default', async () => {
  const f = await fixture()
  const server = await createMcpHttpServer({ engine: f.engine, principal: f.principal, workspaceId: f.workspace })
  try {
    const initialize = await rpc(server.url, 1, 'initialize')
    assert.equal(initialize.status, 401)
    assert.deepEqual(initialize.body, { error: 'unauthorized' })
    assert.equal(initialize.sessionId, null, 'unauthenticated requests must not receive a session')

    const taskCall = await rpc(server.url, 2, 'tools/call', {
      name: 'armorbreak_analyze',
      arguments: { capability: 'forensics.hash', target: f.target },
    })
    assert.equal(taskCall.status, 401)
    assert.deepEqual(taskCall.body, { error: 'unauthorized' })
    assert.equal(taskCall.sessionId, null, 'unauthenticated tool calls must not create a session')
  } finally {
    await server.close()
    await f.engine.close()
    await rm(f.root, { recursive: true, force: true })
  }
})

test('unauthenticated loopback mode works only with explicit development opt-in', async () => {
  const f = await fixture()
  const server = await createMcpHttpServer({
    engine: f.engine,
    principal: f.principal,
    workspaceId: f.workspace,
    allowUnauthenticatedLoopback: true,
  })
  try {
    const initialize = await rpc(server.url, 1, 'initialize')
    assert.equal(initialize.status, 200)
    assert.equal(initialize.body.result.protocolVersion, '2025-06-18')
    assert.ok(initialize.sessionId)
  } finally {
    await server.close()
    await f.engine.close()
    await rm(f.root, { recursive: true, force: true })
  }
})
