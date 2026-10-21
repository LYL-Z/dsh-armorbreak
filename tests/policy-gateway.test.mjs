/**
 * AB2-M1-03 tests: every registered tool has exactly one route; model identities
 * cannot authorize; L3 always denied; RESOURCE_READ is not L2; L1/L2 require
 * approvals; file containment uses the real ScopePolicy.
 */
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { PERMISSIONS, PolicyGateway, TOOL_ROUTES, routeOf } from '../lib/control/policyGateway.js'
import { ScopePolicy } from '../lib/core/scope.js'

async function temp(prefix) {
  return mkdtemp(join(tmpdir(), prefix))
}

function fakeScope(overrides = {}) {
  return {
    checkFile: async () => ({ allowed: true, code: 'L0_OK', reason: 'fake file ok' }),
    checkExecution: async () => ({ allowed: true, code: 'L1_OK', reason: 'fake exec ok' }),
    checkNetwork: async () => ({ allowed: true, code: 'L2_OK', reason: 'fake network ok' }),
    ...overrides,
  }
}

test('catalog covers every model-facing armorbreak tool exactly once', () => {
  const source = readFileSync(new URL('../tools.js', import.meta.url), 'utf8')
  const names = [...source.matchAll(/name:\s*'(armorbreak_[a-z_]+)'/g)].map((match) => match[1])
  assert.equal(new Set(names).size, 10)
  assert.deepEqual([...new Set(names)].sort(), Object.keys(TOOL_ROUTES).sort())
  for (const name of names) assert.ok(routeOf(name), `route missing for ${name}`)
})

test('unknown actions and model-supplied authorization are denied', async () => {
  const gateway = new PolicyGateway({ scope: fakeScope() })
  const unknown = await gateway.decide({ action: 'made.up.action', identity: { kind: 'model' } })
  assert.equal(unknown.allowed, false)
  assert.equal(unknown.code, 'UNKNOWN_ACTION')
  const modelAuth = await gateway.decide({ action: 'tool.armorbreak_scope', identity: { kind: 'model' } })
  assert.equal(modelAuth.allowed, false)
  assert.equal(modelAuth.code, 'MODEL_CANNOT_AUTHORIZE')
  const operatorAuth = await gateway.decide({ action: 'tool.armorbreak_scope', identity: { kind: 'operator' } })
  assert.equal(operatorAuth.allowed, true, 'operator control action is allowed; target authorization remains in ScopePolicy')
  const install = await gateway.decide({ action: 'supplychain.install', identity: { kind: 'model' } })
  assert.equal(install.allowed, false)
})

test('L3 has no route; installation stays blocked until M2', async () => {
  const gateway = new PolicyGateway({ scope: fakeScope() })
  const l3 = await gateway.decide({ action: 'tool.armorbreak_analyze', riskLevel: 'L3', identity: { kind: 'model' } })
  assert.equal(l3.allowed, false)
  assert.equal(l3.code, 'L3_DENIED')
  const install = await gateway.decide({ action: 'supplychain.install', planHash: 'abc', identity: { kind: 'operator' } })
  assert.equal(install.allowed, false)
  assert.equal(install.code, 'INSTALLER_NOT_IMPLEMENTED')
})

test('RESOURCE_READ is connector-gated and never grants L2 network execution', async () => {
  const gateway = new PolicyGateway({ scope: fakeScope(), resourceConnectors: ['cisa-kev'] })
  const denied = await gateway.decide({ action: 'resource.read', connector: 'random-blog', identity: { kind: 'model' } })
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, 'RESOURCE_CONNECTOR_DENIED')
  const allowed = await gateway.decide({ action: 'resource.read', connector: 'cisa-kev', identity: { kind: 'model' } })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.code, 'RESOURCE_READ_ALLOWED')
  assert.equal(allowed.riskLevel, 'L0')
  const l2 = await gateway.decide({ action: 'tool.armorbreak_analyze', riskLevel: 'L2', target: 'lab.example.test', identity: { kind: 'model' } })
  assert.equal(l2.allowed, false)
  assert.equal(l2.code, 'NETWORK_APPROVAL_REQUIRED')
})

test('L0 file actions use real ScopePolicy containment; L1/L2 approvals are enforced', async () => {
  const stateRoot = await temp('abm-pg-state-')
  const workspace = await temp('abm-pg-ws-')
  const outside = await temp('abm-pg-outside-')
  const inside = join(workspace, 'sample.txt')
  const outsideFile = join(outside, 'secret.txt')
  await writeFile(inside, 'inside')
  await writeFile(outsideFile, 'outside')
  const scope = new ScopePolicy({ stateRoot })
  const gateway = new PolicyGateway({ scope })

  const ok = await gateway.decide({ action: 'armorbreak_analyze', riskLevel: 'L0', target: inside, workspaceRoot: workspace, taskId: 't1', identity: { kind: 'model' } })
  assert.equal(ok.allowed, true)
  const escape = await gateway.decide({ action: 'armorbreak_analyze', riskLevel: 'L0', target: outsideFile, workspaceRoot: workspace, taskId: 't1', identity: { kind: 'model' } })
  assert.equal(escape.allowed, false)

  const noApproval = await gateway.decide({ action: 'armorbreak_analyze', riskLevel: 'L1', target: inside, workspaceRoot: workspace, taskId: 't1', identity: { kind: 'model' } })
  assert.equal(noApproval.allowed, false)
  assert.equal(noApproval.code, 'EXECUTION_APPROVAL_REQUIRED')
  const approval = await scope.recordApproval({ kind: 'L1', taskId: 't1', target: inside, outcome: 'allowed-once', source: 'test' })
  const withApproval = await gateway.decide({ action: 'armorbreak_analyze', riskLevel: 'L1', target: inside, workspaceRoot: workspace, taskId: 't1', approvalId: approval.id, identity: { kind: 'model' }, context: { isolationAvailable: true } })
  assert.equal(withApproval.allowed, true)
  assert.ok(['EXECUTION_AUTHORIZED', 'L1_OK'].includes(withApproval.code))
})
