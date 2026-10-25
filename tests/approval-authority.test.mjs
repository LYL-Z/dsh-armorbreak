import assert from 'node:assert/strict'
import { mkdtemp, writeFile, access, link, readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { pathToFileURL } from 'node:url'
import { ApprovalAuthority, makeApprovalId } from '../lib/control/approvalAuthority.js'

async function authority(options = {}) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-appr-'))
  return new ApprovalAuthority({ stateRoot, clock: () => 1_700_000_000_000, ...options })
}

test('approval tokens are signed and bound to task/target/risk/operator', async () => {
  const manager = await authority()
  const { token, payload } = manager.issue({ id: 'appr_1', riskLevel: 'L2', taskId: 'task_1', target: 'lab.example.test:443', operator: 'operator-a' })
  assert.equal(payload.id, 'appr_1')
  assert.equal(manager.verify(token, { id: 'appr_1', taskId: 'task_1', target: 'lab.example.test:443', riskLevel: 'L2', operator: 'operator-a' }).valid, true)
  assert.equal(manager.verify(token, { taskId: 'task_2' }).valid, false)
  assert.equal(manager.verify(`${token}x`, { id: 'appr_1' }).valid, false)
  assert.equal(manager.verify(token, { operator: 'operator-b' }).valid, false)
})

test('tampering, expiry, revocation and replay are rejected', async () => {
  let now = 1_700_000_000_000
  const manager = await authority({ clock: () => now, ttlMs: 60_000 })
  const { token } = manager.issue({ id: 'appr_x', riskLevel: 'L1', taskId: 't', target: 'sample.bin', operator: 'op' })
  const [version, body, sig] = token.split('.')
  const forged = { ...JSON.parse(Buffer.from(body, 'base64url').toString('utf8')), target: 'other.bin' }
  const forgedToken = `${version}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${sig}`
  assert.equal(manager.verify(forgedToken, { id: 'appr_x' }).valid, false)
  now += 61_000
  assert.equal(manager.verify(token, { id: 'appr_x' }).code, 'TOKEN_EXPIRED')
  now -= 61_000
  manager.revoke('appr_x')
  assert.equal(manager.verify(token, { id: 'appr_x' }).code, 'TOKEN_REVOKED')
})

test('consumption is single-use and a second consume is replay', async () => {
  const manager = await authority()
  const { token } = manager.issue({ id: 'appr_once', riskLevel: 'L2', taskId: 't', target: 'lab.test', operator: 'op' })
  assert.equal(manager.consume(token, { id: 'appr_once', taskId: 't', target: 'lab.test' }).valid, true)
  assert.equal(manager.consume(token, { id: 'appr_once', taskId: 't', target: 'lab.test' }).code, 'TOKEN_REPLAYED')
})

test('separate stale instances reload approval state and preserve revocations', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-appr-shared-'))
  const clock = () => 1_700_000_000_000
  const first = new ApprovalAuthority({ stateRoot, clock })
  const stale = new ApprovalAuthority({ stateRoot, clock })
  const { token } = first.issue({ id: 'appr_shared_once', riskLevel: 'L2', taskId: 't', target: 'lab.test', operator: 'op' })
  assert.equal(first.consume(token).valid, true)
  assert.equal(stale.consume(token).code, 'TOKEN_REPLAYED')

  const revoked = first.issue({ id: 'appr_shared_revoke', riskLevel: 'L2', taskId: 't', target: 'lab.test', operator: 'op' })
  first.revoke(revoked.payload.id)
  const other = stale.issue({ id: 'appr_other_revoke', riskLevel: 'L2', taskId: 't2', target: 'lab.test', operator: 'op2' })
  stale.revoke(other.payload.id)
  const fresh = new ApprovalAuthority({ stateRoot, clock })
  assert.equal(fresh.verify(revoked.token).code, 'TOKEN_REVOKED')
})

test('approval key refuses a hard-linked invalid file without overwriting its other name', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-appr-linked-key-'))
  const protectedPath = join(stateRoot, 'protected.data')
  const keyPath = join(stateRoot, 'approval.key')
  const original = Buffer.from('short protected data')
  await writeFile(protectedPath, original)
  await link(protectedPath, keyPath)

  assert.throws(() => new ApprovalAuthority({ stateRoot }), /approval key is unreadable|hard links/i)
  assert.deepEqual(await readFile(protectedPath), original)
})

test('concurrent approval authority initialization preserves one stable signing key', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-appr-init-race-'))
  const start = join(stateRoot, 'start.signal')
  const moduleUrl = new URL('../lib/control/approvalAuthority.js', import.meta.url).href
  const source = `import { createHash } from 'node:crypto';\nimport fs from 'node:fs';\nconst { ApprovalAuthority } = await import(${JSON.stringify(moduleUrl)});\nfs.writeFileSync(process.env.READY, 'ready');\nconst wait = new Int32Array(new SharedArrayBuffer(4));\nconst until = Date.now() + 10000;\nwhile (!fs.existsSync(process.env.START) && Date.now() < until) Atomics.wait(wait, 0, 0, 5);\nif (!fs.existsSync(process.env.START)) process.exit(3);\nconst authority = new ApprovalAuthority({ stateRoot: process.env.STATE_ROOT });\nconsole.log(createHash('sha256').update(authority.secret).digest('hex'));\n`
  const launch = (name) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', source], {
      env: { ...process.env, STATE_ROOT: stateRoot, START: start, READY: join(stateRoot, `${name}.ready`) },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk })
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => code === 0 ? resolve(stdout.trim()) : reject(new Error(`child exited ${code}: ${stderr}`)))
  })
  const names = ['one', 'two', 'three', 'four']
  const resultsPromise = Promise.all(names.map(launch))
  const readyPaths = names.map((name) => join(stateRoot, `${name}.ready`))
  const deadline = Date.now() + 20000
  while (Date.now() < deadline) {
    const ready = await Promise.all(readyPaths.map(async (file) => access(file).then(() => true, () => false)))
    if (ready.every(Boolean)) break
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  const ready = await Promise.all(readyPaths.map(async (file) => access(file).then(() => true, () => false)))
  assert.ok(ready.every(Boolean), 'both child processes reached the barrier')
  await writeFile(start, 'go')
  const hashes = await resultsPromise
  const parent = new ApprovalAuthority({ stateRoot })
  hashes.push(createHash('sha256').update(parent.secret).digest('hex'))
  assert.equal(new Set(hashes).size, 1, 'every initializer and later process must use the persisted key')
})

test('two processes cannot consume the same approval nonce', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-appr-process-'))
  const manager = new ApprovalAuthority({ stateRoot })
  const { token } = manager.issue({ id: 'appr_cross_process', riskLevel: 'L2', taskId: 't', target: 'lab.test', operator: 'op' })
  const start = join(stateRoot, 'start.signal')
  const moduleUrl = new URL('../lib/control/approvalAuthority.js', import.meta.url).href
  const source = `import fs from 'node:fs';\nconst { ApprovalAuthority } = await import(${JSON.stringify(moduleUrl)});\nfs.writeFileSync(process.env.READY, 'ready');\nconst wait = new Int32Array(new SharedArrayBuffer(4));\nconst until = Date.now() + 10000;\nwhile (!fs.existsSync(process.env.START) && Date.now() < until) Atomics.wait(wait, 0, 0, 5);\nif (!fs.existsSync(process.env.START)) process.exit(3);\nconst result = new ApprovalAuthority({ stateRoot: process.env.STATE_ROOT }).consume(process.env.TOKEN);\nconsole.log(JSON.stringify({ valid: result.valid, code: result.code ?? null }));\n`
  const launch = (name) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', source], {
      env: { ...process.env, STATE_ROOT: stateRoot, TOKEN: token, START: start, READY: join(stateRoot, `${name}.ready`) },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk })
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code) => code === 0 ? resolve(JSON.parse(stdout.trim())) : reject(new Error(`child exited ${code}: ${stderr}`)))
  })
  const resultsPromise = Promise.all([launch('one'), launch('two')])
  const readyPaths = [join(stateRoot, 'one.ready'), join(stateRoot, 'two.ready')]
  const deadline = Date.now() + 10000
  while (Date.now() < deadline) {
    const ready = await Promise.all(readyPaths.map(async (file) => access(file).then(() => true, () => false)))
    if (ready.every(Boolean)) break
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  const ready = await Promise.all(readyPaths.map(async (file) => access(file).then(() => true, () => false)))
  assert.ok(ready.every(Boolean), 'both child processes reached the barrier')
  await writeFile(start, 'go')
  const results = await resultsPromise
  assert.equal(results.filter((item) => item.valid).length, 1)
  assert.equal(results.filter((item) => item.code === 'TOKEN_REPLAYED').length, 1)
})

test('approval ids are unique', () => {
  assert.notEqual(makeApprovalId(), makeApprovalId())
})
