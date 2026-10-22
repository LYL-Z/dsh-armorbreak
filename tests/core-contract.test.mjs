import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import * as coreModule from '../packages/core/index.js'

test('Core public API contract, dependency graph and result shapes are frozen', async () => {
  const contract = JSON.parse(await readFile('packages/core/api-contract.json', 'utf8'))
  assert.equal(contract.schemaVersion, 'armorbreak.core-contract/v1')
  assert.deepEqual(Object.keys(coreModule).sort(), [...contract.exports].sort())
  assert.equal(coreModule.CORE_VERSION, contract.version)
  assert.equal(coreModule.PROTOCOL_VERSION, contract.protocolVersion)

  const graph = JSON.parse(await readFile('packages/core/dependency-graph.json', 'utf8'))
  assert.deepEqual(graph.roots, ['packages/core/index.js', 'packages/core/evidenceEnvelope.js'])
  assert.equal(graph.forbiddenHits.length, 0)
  assert.ok(graph.files.includes('packages/core/src/runtime.js'))
  assert.ok(graph.files.includes('packages/core/index.js'))

  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-core-contract-'))
  const core = await coreModule.createCore({ stateRoot })
  for (const method of contract.coreMethods) assert.equal(typeof core[method], 'function')
  const ctx = { principal: { id: 'contract-tester', kind: 'local-user' }, workspaceId: stateRoot, requestId: 'req-contract', traceId: 'trace-contract' }
  const capabilities = await core.capabilities(ctx)
  assert.equal(capabilities.length, 46)
  for (const field of contract.invocationResultFields.capability) assert.ok(field in capabilities[0], `capability missing ${field}`)
  const health = await core.health(ctx)
  for (const field of contract.invocationResultFields.health) assert.ok(field in health, `health missing ${field}`)
  await core.close()
})
