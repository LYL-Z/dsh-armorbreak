import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { createMcpHttpServer } from '../packages/mcp-server/http.js'
import { ArmorBreakClient } from '../packages/sdk-ts/index.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-sdk-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-sdk-ws-'))
  const principal = { id: 'sdk-tester', kind: 'local-user', workspaces: [workspace] }
  const engine = await createEngine({ stateRoot, principals: [principal] })
  await writeFile(join(workspace, 'sample.txt'), 'sdk sample')
  return { stateRoot, workspace, principal, engine }
}

test('typed SDK works over direct Engine transport', async () => {
  const f = await fixture()
  const client = new ArmorBreakClient({ engine: f.engine, principal: f.principal, workspaceId: f.workspace })
  assert.equal((await client.capabilities()).length, 46)
  const result = await client.analyze({ capability: 'forensics.hash', target: join(f.workspace, 'sample.txt') })
  assert.equal(result.state, 'COMPLETED')
  assert.match(result.targetSha256, /^[a-f0-9]{64}$/)
  const task = await client.task(result.taskId)
  assert.equal(task.id, result.taskId)
  const evidence = await client.evidence(result.taskId)
  assert.ok(evidence.evidence.length >= 1)
  const report = await client.report(result.taskId)
  assert.match(report.markdown, /ArmorBreak/)
  assert.ok(Array.isArray(await client.tasks()))
  await f.engine.close()
})

test('typed SDK works over MCP HTTP transport', async () => {
  const f = await fixture()
  const token = 'sdk-mcp-http-integration-token-32-bytes'
  const server = await createMcpHttpServer({ engine: f.engine, principal: f.principal, workspaceId: f.workspace, token })
  try {
    const client = new ArmorBreakClient({ baseUrl: server.url, token, principal: f.principal, workspaceId: f.workspace })
    assert.equal((await client.capabilities()).length, 46)
    const result = await client.analyze({ capability: 'forensics.hash', target: join(f.workspace, 'sample.txt') })
    assert.equal(result.state, 'COMPLETED')
    const report = await client.report(result.taskId)
    assert.match(report.markdown, /ArmorBreak/)
  } finally {
    await server.close()
    await f.engine.close()
  }
})
