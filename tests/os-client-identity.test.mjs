/**
 * Deterministic tests for the in-memory OS-client grant boundary.
 * They do not read a Windows token or POSIX credentials.
 */
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { OS_CLIENT_GRANT_TTL_MS, createOsClientIdentity } from '../lib/auth/osClientIdentity.js'

const SID_A = 'S-1-5-21-100-200-300-1001'
const SID_B = 'S-1-5-21-100-200-300-1002'
const WORKSPACE = 'D:\\work\\sample'
const ACTION = 'files.read'

function sequence() {
  let n = 0
  return () => `grant-${++n}`
}

function fixedBoundary(clock, ttlMs = 5_000) {
  return createOsClientIdentity({
    clock: () => clock.now,
    randomId: sequence(),
    ttlMs,
  })
}

function windowsPrincipal(userSid = SID_A, sessionId = '4', extra = {}) {
  return { platform: 'win32', userSid, sessionId, ...extra }
}

function present(boundary, grantId, principal, workspace = WORKSPACE, action = ACTION) {
  return boundary.present({ grantId, principal, workspace, action })
}

test('binds a grant to the host OS principal, session, workspace, and action', () => {
  const clock = { now: 1_700_000_000_000 }
  const boundary = fixedBoundary(clock)
  const isolated = fixedBoundary(clock)
  const inputPrincipal = windowsPrincipal(SID_A.toLowerCase(), '4', {
    operator: 'model-operator',
    csrfToken: 'csrf-1',
    remoteAddress: '127.0.0.1',
  })
  const grant = boundary.issue({ principal: inputPrincipal, workspace: `  ${WORKSPACE}  `, action: ACTION })
  inputPrincipal.userSid = SID_B
  assert.equal(grant.id, 'grant-1')
  assert.equal(grant.userSid, undefined)
  assert.equal(grant.uid, undefined)
  assert.equal(grant.operator, undefined)
  assert.equal(grant.csrfToken, undefined)
  assert.equal(grant.workspace, WORKSPACE)
  assert.equal(grant.action, ACTION)
  assert.equal(grant.sessionId, '4')
  assert.equal(grant.platform, 'win32')
  assert.equal(grant.principalKind, 'sid')
  assert.equal(grant.issuedAt, clock.now)
  assert.equal(grant.expiresAt, clock.now + 5_000)
  assert.throws(() => {
    grant.workspace = 'D:\\mutated'
  }, TypeError)

  const presented = windowsPrincipal(SID_A, '4', {
    operator: 'someone-else',
    csrfToken: 'csrf-2',
    remoteAddress: '10.1.1.1',
  })
  assert.equal(present(boundary, grant.id, presented).ok, true)
  assert.equal(present(boundary, grant.id, presented).ok, true)
  assert.equal(present(isolated, grant.id, presented).code, 'GRANT_NOT_FOUND')

  const linux = fixedBoundary(clock)
  const linuxGrant = linux.issue({
    principal: { platform: 'linux', uid: 0, sessionId: 'c1' },
    workspace: '/srv/lab',
    action: 'task.read',
  })
  assert.equal(linux.present({
    grantId: linuxGrant.id,
    principal: { platform: 'Linux', uid: '0', sessionId: 'c1' },
    workspace: '/srv/lab',
    action: 'task.read',
  }).ok, true)
})

test('rejects a different SID, uid, platform, or identifier kind', () => {
  const boundary = fixedBoundary({ now: 10 })
  const grant = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  assert.equal(present(boundary, grant.id, windowsPrincipal(SID_B)).code, 'PRINCIPAL_MISMATCH')
  assert.equal(present(boundary, grant.id, { platform: 'linux', userSid: SID_A, sessionId: '4' }).code, 'PRINCIPAL_MISMATCH')
  assert.equal(present(boundary, grant.id, { platform: 'win32', uid: 1001, sessionId: '4' }).code, 'PRINCIPAL_MISMATCH')
  assert.equal(boundary.present({
    grantId: grant.id,
    principal: windowsPrincipal(SID_B, '4', { operator: 'alice', csrfToken: 'same', remoteAddress: '127.0.0.1' }),
    workspace: WORKSPACE,
    action: ACTION,
    toolArguments: { userSid: SID_A },
    arguments: { principal: windowsPrincipal() },
  }).code, 'PRINCIPAL_MISMATCH')
  assert.equal(present(boundary, grant.id, windowsPrincipal()).ok, true)

  const posix = fixedBoundary({ now: 10 })
  const uidGrant = posix.issue({
    principal: { platform: 'linux', uid: 1000, sessionId: '9' },
    workspace: '/srv/lab',
    action: ACTION,
  })
  assert.equal(posix.present({
    grantId: uidGrant.id,
    principal: { platform: 'linux', uid: 1001, sessionId: '9' },
    workspace: '/srv/lab',
    action: ACTION,
  }).code, 'PRINCIPAL_MISMATCH')
  assert.equal(posix.present({
    grantId: uidGrant.id,
    principal: { platform: 'linux', uid: '1000', sessionId: '9' },
    workspace: '/srv/lab',
    action: ACTION,
  }).ok, true)
})

test('rejects a different OS session', () => {
  const boundary = fixedBoundary({ now: 10 })
  const grant = boundary.issue({ principal: windowsPrincipal(SID_A, '4'), workspace: WORKSPACE, action: ACTION })
  const denied = boundary.present({
    grantId: grant.id,
    principal: windowsPrincipal(SID_A, '5', { csrfToken: '4' }),
    workspace: WORKSPACE,
    action: ACTION,
  })
  assert.equal(denied.ok, false)
  assert.equal(denied.code, 'SESSION_MISMATCH')
  assert.equal(present(boundary, grant.id, windowsPrincipal(SID_A, '4')).ok, true)
})

test('rejects an expired grant at the injected timestamp', () => {
  const clock = { now: 10_000 }
  const boundary = fixedBoundary(clock, 5_000)
  const grant = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  clock.now = grant.expiresAt - 1
  assert.equal(present(boundary, grant.id, windowsPrincipal()).ok, true)
  clock.now = grant.expiresAt
  const expired = present(boundary, grant.id, windowsPrincipal())
  assert.equal(expired.ok, false)
  assert.equal(expired.code, 'EXPIRED')

  const defaults = createOsClientIdentity({ clock: () => clock.now, randomId: sequence() })
  clock.now = 20_000
  const short = defaults.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  assert.equal(short.expiresAt - short.issuedAt, OS_CLIENT_GRANT_TTL_MS)
  clock.now = short.expiresAt
  assert.equal(present(defaults, short.id, windowsPrincipal()).code, 'EXPIRED')
  clock.now = short.expiresAt + 1
  assert.equal(present(defaults, short.id, windowsPrincipal()).code, 'EXPIRED')
})

test('rejects a grant after explicit revoke', () => {
  const clock = { now: 10 }
  const boundary = fixedBoundary(clock)
  const grant = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  const other = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: 'task.read' })
  assert.equal(present(boundary, grant.id, windowsPrincipal()).ok, true)
  const revoked = boundary.revoke(grant.id)
  assert.equal(revoked.ok, true)
  assert.equal(revoked.grantId, grant.id)
  const denied = present(boundary, grant.id, windowsPrincipal())
  assert.equal(denied.ok, false)
  assert.equal(denied.code, 'REVOKED')
  assert.equal(boundary.revoke(grant.id).ok, true)
  assert.equal(boundary.present({
    grantId: other.id,
    principal: windowsPrincipal(),
    workspace: WORKSPACE,
    action: 'task.read',
  }).ok, true)
  assert.equal(boundary.revoke('missing').code, 'GRANT_NOT_FOUND')
  clock.now = grant.expiresAt + 1
  assert.equal(present(boundary, grant.id, windowsPrincipal()).code, 'REVOKED')
})

test('rejects a different workspace path', () => {
  const boundary = fixedBoundary({ now: 10 })
  const grant = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  const at = (workspace, extra = {}) => boundary.present({
    grantId: grant.id,
    principal: windowsPrincipal(),
    workspace,
    action: ACTION,
    ...extra,
  })
  assert.equal(at('D:\\work\\other').code, 'WORKSPACE_MISMATCH')
  assert.equal(at('D:/work/sample').code, 'WORKSPACE_MISMATCH')
  assert.equal(at(`${WORKSPACE}\\`).code, 'WORKSPACE_MISMATCH')
  assert.equal(at(undefined).code, 'WORKSPACE_MISMATCH')
  assert.equal(at('C:\\elsewhere', { grant: { id: grant.id, workspace: WORKSPACE, action: ACTION } }).code, 'WORKSPACE_MISMATCH')
  assert.equal(at(WORKSPACE).ok, true)
})

test('rejects a different action name', () => {
  const boundary = fixedBoundary({ now: 10 })
  const grant = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  const asAction = (action) => boundary.present({
    grantId: grant.id,
    principal: windowsPrincipal(),
    workspace: WORKSPACE,
    action,
  })
  assert.equal(asAction('files.write').code, 'ACTION_MISMATCH')
  assert.equal(asAction('Files.Read').code, 'ACTION_MISMATCH')
  assert.equal(asAction('files.read,files.write').code, 'ACTION_MISMATCH')
  assert.equal(asAction('').code, 'ACTION_MISMATCH')
  assert.equal(asAction(ACTION).ok, true)
})

test('does not treat loopback, CSRF, operator strings, or tool arguments as OS identity', () => {
  const boundary = fixedBoundary({ now: 10 })
  const attempts = [
    'alice',
    { operator: 'alice' },
    { platform: 'win32', sessionId: '4', operator: 'SYSTEM' },
    { platform: 'win32', sessionId: '4', csrfToken: 'token' },
    { platform: 'win32', sessionId: '4', csrf: 'token' },
    { platform: 'win32', sessionId: '4', remoteAddress: '127.0.0.1' },
    { platform: 'win32', sessionId: '4', loopback: true },
    { platform: 'win32', sessionId: '4', arguments: { userSid: SID_A } },
    { platform: 'win32', sessionId: '4', toolArguments: { userSid: SID_A, uid: 0 } },
    { platform: 'win32', userSid: SID_A, sessionId: '127.0.0.1' },
    { platform: 'win32', userSid: SID_A, sessionId: 'localhost' },
    { platform: 'win32', userSid: SID_A, sessionId: '::1' },
    { platform: 'win32', userSid: SID_A, sessionId: '0.0.0.0' },
    { platform: 'win32', userSid: SID_A, sessionId: '::ffff:127.0.0.1' },
  ]
  for (const principal of attempts) {
    assert.throws(
      () => boundary.issue({ principal, workspace: WORKSPACE, action: ACTION }),
      (error) => error.code === 'OS_PRINCIPAL_REQUIRED',
    )
  }
  assert.throws(
    () => boundary.issue({
      toolArguments: { platform: 'win32', userSid: SID_A, sessionId: '4' },
      arguments: { platform: 'win32', userSid: SID_A, sessionId: '4' },
      workspace: WORKSPACE,
      action: ACTION,
    }),
    (error) => error.code === 'OS_PRINCIPAL_REQUIRED',
  )
  assert.throws(
    () => boundary.issue({
      principal: { platform: 'win32', userSid: '127.0.0.1', sessionId: '4' },
      workspace: WORKSPACE,
      action: ACTION,
    }),
    (error) => error.code === 'INVALID_SID',
  )
  assert.throws(
    () => boundary.issue({
      principal: { platform: 'win32', userSid: SID_A, uid: 1000, sessionId: '4' },
      workspace: WORKSPACE,
      action: ACTION,
    }),
    (error) => error.code === 'AMBIGUOUS_PRINCIPAL',
  )
  const grant = boundary.issue({
    principal: windowsPrincipal(SID_A, '4', { operator: 'alice', csrfToken: 't', remoteAddress: '127.0.0.1' }),
    workspace: WORKSPACE,
    action: ACTION,
  })
  assert.equal(boundary.present({
    grantId: grant.id,
    principal: { operator: 'alice', csrfToken: 't', remoteAddress: '127.0.0.1', sessionId: '4', platform: 'win32' },
    workspace: WORKSPACE,
    action: ACTION,
  }).code, 'OS_PRINCIPAL_REQUIRED')
})

test('does not replace a bound grant when the injected id collides', () => {
  const boundary = createOsClientIdentity({ clock: () => 10, randomId: () => 'same-id', ttlMs: 1_000 })
  const first = boundary.issue({ principal: windowsPrincipal(), workspace: WORKSPACE, action: ACTION })
  assert.throws(
    () => boundary.issue({
      principal: windowsPrincipal(SID_B, '8'),
      workspace: 'D:\\other',
      action: 'files.write',
    }),
    (error) => error.code === 'GRANT_ID_COLLISION',
  )
  assert.equal(present(boundary, first.id, windowsPrincipal()).ok, true)
  assert.equal(present(boundary, first.id, windowsPrincipal(SID_B, '8'), 'D:\\other', 'files.write').code, 'PRINCIPAL_MISMATCH')
})

test('imports no OS credential or network modules', async () => {
  const source = await readFile(fileURLToPath(new URL('../lib/auth/osClientIdentity.js', import.meta.url)), 'utf8')
  const imports = [...source.matchAll(/from '([^']+)'/g)].map((match) => match[1])
  assert.deepEqual(imports, ['node:crypto'])
})
