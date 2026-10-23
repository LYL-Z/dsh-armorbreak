/**
 * Core policy engine tests: authorization records, path confinement, network
 * matching, approval gates, rate limiting, and the L1 isolation gate.
 */
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ScopePolicy, networkTargetMatches, parseNetworkTarget } from '../lib/core/scope.js'

async function tempDir(prefix = 'abm-policy-') {
  return mkdtemp(join(tmpdir(), prefix))
}

test('authorize creates a signed durable record and list shows it active', async () => {
  const stateRoot = await tempDir()
  const workspace = await tempDir()
  const scope = new ScopePolicy({ stateRoot })
  const record = await scope.authorize({
    purpose: 'authorized lab research on sample set A',
    operator: 'alice',
    paths: [workspace],
    networkTargets: ['lab.example.test', '10.20.0.0/16'],
    riskCeiling: 'L2',
    ttlMs: 60_000,
  })
  assert.match(record.id, /^authz_/)
  assert.equal(record.signature.length, 64)
  const listed = await scope.listAuthorizations()
  assert.equal(listed.length, 1)
  assert.equal(listed[0].active, true)
  // Reload from disk keeps the signature valid.
  const reloaded = new ScopePolicy({ stateRoot })
  const listedAgain = await reloaded.listAuthorizations()
  assert.equal(listedAgain[0].active, true)
  assert.equal(listedAgain[0].signature, record.signature)
})

test('authorize rejects empty authorization and short purpose', async () => {
  const scope = new ScopePolicy({ stateRoot: await tempDir() })
  await assert.rejects(() => scope.authorize({ purpose: 'abc', operator: 'alice', paths: ['C:\\tmp'] }), /purpose/)
  await assert.rejects(() => scope.authorize({ purpose: 'valid purpose', operator: 'a', paths: ['C:\\tmp'] }), /operator/)
  await assert.rejects(() => scope.authorize({ purpose: 'valid purpose', operator: 'alice' }), /empty authorizations/i)
})

test('file check allows workspace targets and denies outside/sensitive targets', async () => {
  const workspace = await tempDir()
  const outside = await tempDir()
  const scope = new ScopePolicy({ stateRoot: await tempDir() })
  const insideFile = join(workspace, 'sample.bin')
  await writeFile(insideFile, 'sample')
  const allowed = await scope.checkFile({ taskId: 't1', targetPath: insideFile, workspaceRoot: workspace })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.code, 'WORKSPACE_ALLOWED')

  const outsideFile = join(outside, 'secret.txt')
  await writeFile(outsideFile, 'secret')
  const denied = await scope.checkFile({ taskId: 't1', targetPath: outsideFile, workspaceRoot: workspace })
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, 'OUT_OF_SCOPE')

  // An authorization record covering the outside path lifts the denial.
  await scope.authorize({ purpose: 'engagement scope', operator: 'alice', paths: [outside], ttlMs: 60_000 })
  const allowedAgain = await scope.checkFile({ taskId: 't1', targetPath: outsideFile, workspaceRoot: workspace })
  assert.equal(allowedAgain.allowed, true)
  assert.equal(allowedAgain.code, 'AUTHORIZED_PATH')
  assert.match(allowedAgain.authorizationId, /^authz_/)
})

test('sensitive host paths are denied even inside an authorized tree', async () => {
  const workspace = await tempDir()
  const scope = new ScopePolicy({ stateRoot: await tempDir() })
  const sensitive = process.platform === 'win32'
    ? 'C:\\Windows\\System32\\config\\SAM'
    : '/etc/shadow'
  const check = await scope.checkFile({ taskId: 't1', targetPath: sensitive, workspaceRoot: workspace })
  assert.equal(check.allowed, false)
  assert.equal(check.code, 'SENSITIVE_PATH_DENIED')
})

test('network target parsing and matching (exact, wildcard, CIDR, ports)', () => {
  assert.deepEqual(parseNetworkTarget('https://API.Example.com:8443/v1'), { host: 'api.example.com', port: 8443 })
  assert.deepEqual(parseNetworkTarget('[::1]:8080'), { host: '::1', port: 8080 })
  const target = { host: 'api.example.com', port: 443 }
  assert.equal(networkTargetMatches({ host: 'api.example.com' }, target), true)
  assert.equal(networkTargetMatches({ host: '*.example.com' }, target), true)
  assert.equal(networkTargetMatches({ host: '*.other.test' }, target), false)
  assert.equal(networkTargetMatches({ host: '10.20.0.0/16' }, { host: '10.20.31.7', port: null }), true)
  assert.equal(networkTargetMatches({ host: '10.20.0.0/16' }, { host: '10.21.0.1', port: null }), false)
  assert.equal(networkTargetMatches({ host: '10.20.0.0/16', ports: [443] }, { host: '10.20.0.2', port: 80 }), false)
})

test('L2 network execution requires authorization and an active approval', async () => {
  const scope = new ScopePolicy({ stateRoot: await tempDir() })
  const noScope = await scope.checkNetwork({ taskId: 't1', target: '10.20.0.5:443' })
  assert.equal(noScope.allowed, false)
  assert.equal(noScope.code, 'NETWORK_OUT_OF_SCOPE')

  await scope.authorize({ purpose: 'authorized internal lab scan', operator: 'alice', networkTargets: ['10.20.0.0/16'], riskCeiling: 'L2', ttlMs: 60_000 })
  const noApproval = await scope.checkNetwork({ taskId: 't1', target: '10.20.0.5:443' })
  assert.equal(noApproval.allowed, false)
  assert.equal(noApproval.code, 'NETWORK_APPROVAL_REQUIRED')

  const approval = await scope.recordApproval({ kind: 'L2', taskId: 't1', target: '10.20.0.5', outcome: 'allowed-once', source: 'test' })
  const allowed = await scope.checkNetwork({ taskId: 't1', target: '10.20.0.5:443', approvalId: approval.id })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.code, 'NETWORK_AUTHORIZED')

  const wrongTask = await scope.checkNetwork({ taskId: 't2', target: '10.20.0.5', approvalId: approval.id })
  assert.equal(wrongTask.allowed, false)
  assert.equal(wrongTask.code, 'NETWORK_APPROVAL_TASK_MISMATCH')
})

test('checkNetwork fails closed when hostname DNS fails or returns no usable addresses', async () => {
  const failingResolvers = [
    async () => { throw new Error('synthetic resolver failure') },
    async () => [],
    async () => ['not-an-ip-address'],
  ]
  for (const dnsLookup of failingResolvers) {
    const target = 'dns-fail-closed.example.invalid:443'
    const scope = new ScopePolicy({ stateRoot: await tempDir(), dnsLookup })
    await scope.authorize({ purpose: 'synthetic DNS fail-closed test', operator: 'audit-user', networkTargets: [target], riskCeiling: 'L2' })
    const approval = await scope.recordApproval({ kind: 'L2', taskId: 'dns-fail-closed', target, outcome: 'allowed-once', source: 'test' })

    const result = await scope.checkNetwork({ taskId: 'dns-fail-closed', target, approvalId: approval.id })
    assert.equal(result.allowed, false)
    assert.equal(result.code, 'NETWORK_DNS_FAILED')
    assert.deepEqual(result.resolvedIps, [])
  }
})

test('checkNetwork rejects DNS answers containing private, reserved, or mixed public/private addresses', async () => {
  const answers = [
    ['127.0.0.1'],
    ['10.20.0.5'],
    ['172.16.1.5'],
    ['192.168.1.5'],
    ['169.254.10.2'],
    ['::1'],
    ['fc00::1'],
    ['fe80::1'],
    ['2001:db8::1'],
    ['8.8.8.8', '127.0.0.1'],
  ]
  for (const resolvedIps of answers) {
    const target = 'dns-private-denied.example.invalid:443'
    const scope = new ScopePolicy({ stateRoot: await tempDir(), dnsLookup: async () => resolvedIps })
    await scope.authorize({ purpose: 'synthetic DNS address test', operator: 'audit-user', networkTargets: [target], riskCeiling: 'L2' })
    const approval = await scope.recordApproval({ kind: 'L2', taskId: 'dns-private-denied', target, outcome: 'allowed-once', source: 'test' })

    const result = await scope.checkNetwork({ taskId: 'dns-private-denied', target, approvalId: approval.id })
    assert.equal(result.allowed, false, `${resolvedIps.join(', ')} must be denied`)
    assert.equal(result.code, 'NETWORK_NON_PUBLIC_ADDRESS_DENIED')
  }
})

test('checkNetwork accepts public DNS answers and still permits explicitly authorized private IP literals', async () => {
  const target = 'dns-public.example.invalid:443'
  const scope = new ScopePolicy({ stateRoot: await tempDir(), dnsLookup: async () => ['8.8.8.8', '2606:4700:4700::1111'] })
  await scope.authorize({ purpose: 'synthetic public DNS test', operator: 'audit-user', networkTargets: [target, '10.20.0.0/16'], riskCeiling: 'L2' })
  const approval = await scope.recordApproval({ kind: 'L2', taskId: 'dns-public', target, outcome: 'allowed-once', source: 'test' })

  const publicResult = await scope.checkNetwork({ taskId: 'dns-public', target, approvalId: approval.id })
  assert.equal(publicResult.allowed, true)
  assert.deepEqual(publicResult.resolvedIps, ['8.8.8.8', '2606:4700:4700::1111'])

  const privateLiteral = '10.20.0.5:443'
  const literalApproval = await scope.recordApproval({ kind: 'L2', taskId: 'dns-public', target: privateLiteral, outcome: 'allowed-once', source: 'test' })
  const literalResult = await scope.checkNetwork({ taskId: 'dns-public', target: privateLiteral, approvalId: literalApproval.id })
  assert.equal(literalResult.allowed, true)
  assert.deepEqual(literalResult.resolvedIps, ['10.20.0.5'])
})

test('recordApproval refuses non-grant outcomes', async () => {
  const scope = new ScopePolicy({ stateRoot: await tempDir() })
  await assert.rejects(() => scope.recordApproval({ kind: 'L2', taskId: 't1', target: 'x', outcome: 'rejected' }), /not a grant/)
  await assert.rejects(() => scope.recordApproval({ kind: 'L2', taskId: 't1', target: 'x', outcome: 'unavailable' }), /not a grant/)
})

test('L1 execution is denied without an isolation provider', async () => {
  const workspace = await tempDir()
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, 'MZ')
  const scope = new ScopePolicy({ stateRoot: await tempDir() })
  const denied = await scope.checkExecution({ taskId: 't1', targetPath: sample, workspaceRoot: workspace, isolationAvailable: false })
  assert.equal(denied.allowed, false)
  assert.equal(denied.code, 'ISOLATION_UNAVAILABLE')

  const noApproval = await scope.checkExecution({ taskId: 't1', targetPath: sample, workspaceRoot: workspace, isolationAvailable: true })
  assert.equal(noApproval.allowed, false)
  assert.equal(noApproval.code, 'EXECUTION_APPROVAL_REQUIRED')

  const approval = await scope.recordApproval({ kind: 'L1', taskId: 't1', target: sample, outcome: 'allowed-once', source: 'test' })
  const allowed = await scope.checkExecution({ taskId: 't1', targetPath: sample, workspaceRoot: workspace, isolationAvailable: true, approvalId: approval.id })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.code, 'EXECUTION_AUTHORIZED')
})

test('token bucket rate-limits an authorized host', async () => {
  const scope = new ScopePolicy({ stateRoot: await tempDir(), clock: (() => { let now = 1_000_000; return () => now })() })
  let granted = 0
  for (let index = 0; index < 40; index += 1) {
    if (scope.takeToken('lab.example.test').allowed) granted += 1
  }
  assert.ok(granted <= 20, `granted ${granted} tokens above capacity`)
  assert.ok(granted >= 19, `expected nearly-full bucket, granted ${granted}`)
  const limited = scope.takeToken('lab.example.test')
  assert.equal(limited.allowed, false)
  assert.ok(limited.retryAfterMs > 0)
})
