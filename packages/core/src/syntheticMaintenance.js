/** Trusted-host-only synthetic transaction executor. Never accepts an existing host root. */
import { constants } from 'node:fs'
import { mkdtemp, mkdir, open, lstat, realpath, readdir, rename } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve, parse, relative, sep } from 'node:path'
import { randomUUID } from 'node:crypto'
import { canonicalConfig } from '../../../lib/integrations/configOverlay.js'
import { sameFilesystemPath } from '../../../lib/core/pathBoundary.js'
import { AuditLog } from './audit.js'

const NAME = /^[a-z][a-z0-9_-]{0,48}\.txt$/
const identity = stat => ({ dev: stat.dev, ino: stat.ino })
const equal = (a, b) => a.dev === b.dev && a.ino === b.ino
const canonical = x => canonicalConfig(x)
async function noLinks(path) {
  let current = parse(resolve(path)).root
  for (const part of relative(current, resolve(path)).split(sep).filter(Boolean)) {
    current = join(current, part)
    if ((await lstat(current)).isSymbolicLink()) throw new Error('LAB_PATH_UNSAFE')
  }
}
async function writeNew(path, bytes) {
  const file = await open(path, 'wx', 0o600)
  try { await file.writeFile(bytes); await file.sync() } finally { await file.close() }
}
async function syncDirectory(path) {
  // Windows does not provide Node directory fsync. Never claim power-loss durability there.
  if (process.platform === 'win32') return
  const dir = await open(path, 'r'); try { await dir.sync() } finally { await dir.close() }
}
const CONSTRUCT = Symbol('fresh synthetic lab only')

export class SyntheticMaintenance {
  constructor(key, runtime, manifest) {
    if (key !== CONSTRUCT) throw new Error('use createSyntheticMaintenance or reopenSyntheticMaintenance')
    this.runtime = runtime
    this.manifest = manifest
    this.root = manifest.root
    this.control = join(this.root, 'control')
    this.data = join(this.root, 'data')
    this.audit = new AuditLog({ file: join(this.control, 'audit.jsonl') })
  }
  seal(value) { return canonical({ value, signature: this.runtime.approvalAuthority.sign(canonical(value)) }) }
  async readSealed(name) {
    const path = join(this.control, name)
    const before = await lstat(path)
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > 2 * 1024 * 1024) throw new Error('LAB_RECORD_UNSAFE')
    const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    try {
      if (!equal(identity(before), identity(await file.stat()))) throw new Error('LAB_RECORD_CHANGED')
      const record = JSON.parse(await file.readFile('utf8'))
      if (record.signature !== this.runtime.approvalAuthority.sign(canonical(record.value))) throw new Error('LAB_RECORD_INTEGRITY')
      return record.value
    } finally { await file.close() }
  }
  async boundary() {
    await noLinks(this.root)
    if (!sameFilesystemPath(await realpath(this.root), this.root)) throw new Error('LAB_ROOT_CHANGED')
    for (const [path, expected] of [[this.root, this.manifest.rootId], [this.data, this.manifest.dataId], [this.control, this.manifest.controlId]]) {
      const stat = await lstat(path)
      if (!stat.isDirectory() || stat.isSymbolicLink() || !equal(identity(stat), expected)) throw new Error('LAB_DIRECTORY_CHANGED')
    }
    const members = (await readdir(this.data)).sort()
    if (canonical(members) !== canonical(Object.keys(this.manifest.files).sort())) throw new Error('LAB_MEMBERS_CHANGED')
  }
  async file(name, operation) {
    if (!NAME.test(name) || !Object.hasOwn(this.manifest.files, name)) throw new Error('LAB_TARGET_DENIED')
    await this.boundary()
    const path = join(this.data, name), before = await lstat(path)
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || !equal(identity(before), this.manifest.files[name])) throw new Error('LAB_FILE_CHANGED')
    const file = await open(path, constants.O_RDWR | (constants.O_NOFOLLOW ?? 0))
    try {
      if (!equal(identity(await file.stat()), this.manifest.files[name])) throw new Error('LAB_FILE_CHANGED')
      await this.boundary()
      return await operation(file)
    } finally { await file.close() }
  }
  async locked(operation) {
    await this.boundary()
    const path = join(this.control, 'lock')
    const lock = await open(path, 'wx', 0o600).catch(() => { throw new Error('LAB_LOCKED_RECOVERY_REQUIRED') })
    try {
      await lock.writeFile(this.seal({ pid: process.pid, root: this.root })); await lock.sync()
      return await operation()
    } finally {
      await lock.close()
      // Preserve lease history; do not silently delete an abandoned lock after a crash.
      await this.boundary()
      await rename(path, join(this.control, `lease-${randomUUID()}.json`))
    }
  }
  async journal(event) {
    const path = join(this.control, 'journal.jsonl')
    const file = await open(path, constants.O_WRONLY | constants.O_APPEND | (constants.O_NOFOLLOW ?? 0))
    try { await file.writeFile(this.seal(event) + '\n'); await file.sync() } finally { await file.close() }
  }
  async events() {
    await this.boundary()
    const path = join(this.control, 'journal.jsonl'), stat = await lstat(path)
    if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1 || stat.size > 1024 * 1024) throw new Error('LAB_JOURNAL_UNSAFE')
    const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    try {
      const lines = (await file.readFile('utf8')).trim().split('\n').filter(Boolean)
      return lines.map(line => {
        const item = JSON.parse(line)
        if (item.signature !== this.runtime.approvalAuthority.sign(canonical(item.value))) throw new Error('LAB_JOURNAL_INTEGRITY')
        return item.value
      })
    } finally { await file.close() }
  }
  /** One immutable plan per fresh lab, only seeded .txt files and bounded replacement bytes. */
  async plan(changes) {
    return this.locked(async () => {
      if (!Array.isArray(changes) || !changes.length || changes.length > 16 || new Set(changes.map(x => x.name)).size !== changes.length) throw new Error('LAB_PLAN_INVALID')
      const rows = []
      for (const change of changes) {
        if (Object.keys(change).sort().join(',') !== 'content,name' || typeof change.content !== 'string' || Buffer.byteLength(change.content) > 65536) throw new Error('LAB_PLAN_INVALID')
        const before = await this.file(change.name, file => file.readFile())
        if (before.length > 65536) throw new Error('LAB_INPUT_EXCESSIVE')
        rows.push({ name: change.name, before: before.toString('base64'), after: Buffer.from(change.content).toString('base64') })
      }
      const plan = { id: randomUUID(), root: this.root, operator: this.manifest.operator, sessionId: this.manifest.sessionId, rows }
      await writeNew(join(this.control, 'plan.json'), this.seal(plan))
      await syncDirectory(this.control)
      await this.journal({ state: 'PLANNED', planId: plan.id })
      return { planId: plan.id, mode: 'SYNTHETIC_ONLY', changes: rows.length, approvalRequired: true, hostWrites: false }
    })
  }
  async approved(plan, operation, provider) {
    if (!provider || typeof provider.request !== 'function') throw new Error('TRUSTED_APPROVAL_PROVIDER_REQUIRED')
    const outcome = await provider.request({ toolName: 'armorbreak.synthetic-maintenance', riskLevel: 'L2',
      operation, taskId: plan.id, target: this.root, sessionId: plan.sessionId, operator: plan.operator, changes: plan.rows.length })
    if (outcome !== 'allowed-once') throw new Error('TRUSTED_APPROVAL_DENIED')
    const authority = this.runtime.approvalAuthority
    const target = authority.sign(canonical({ plan, operation }))
    const issued = authority.issue({ id: `lab:${randomUUID()}`, taskId: plan.id, target, riskLevel: 'L2', operator: plan.operator, sessionId: plan.sessionId })
    if (!authority.verify(issued.token, { sessionId: this.manifest.sessionId }).valid) throw new Error('LAB_SESSION_DENIED')
    const grant = await this.runtime.scope.recordApproval({ kind: 'L2', taskId: plan.id, target, source: 'platform', outcome, approvalId: issued.payload.id, approvalToken: issued.token, operator: plan.operator })
    await this.runtime.scope.consumeApproval(grant.id)
    await this.audit.append({ action: `synthetic-maintenance.${operation}.approved`, taskId: plan.id, approvalId: grant.id, riskLevel: 'L2' })
  }
  async execute(operation, planId, provider, checkpoint) {
    return this.locked(async () => {
      const plan = await this.readSealed('plan.json'), events = await this.events(), last = events.at(-1)
      if (plan.id !== planId || plan.root !== this.root || plan.operator !== this.manifest.operator || plan.sessionId !== this.manifest.sessionId) throw new Error('LAB_PLAN_BINDING')
      if (operation === 'apply' && last?.state !== 'PLANNED') throw new Error('LAB_STATE_DENIED')
      if (operation === 'rollback' && !['APPLYING', 'WRITE_INTENT', 'WROTE', 'COMMITTED', 'ROLLING_BACK', 'RESTORE_INTENT', 'RESTORED'].includes(last?.state)) throw new Error('LAB_STATE_DENIED')
      // Preflight every target before approval or the first write. Unknown bytes need manual diagnosis.
      for (const row of plan.rows) await this.file(row.name, async file => {
        const bytes = await file.readFile(), before = Buffer.from(row.before, 'base64'), after = Buffer.from(row.after, 'base64')
        if (!bytes.equals(before) && (operation === 'apply' || !bytes.equals(after))) throw new Error('LAB_CONTENT_DRIFT')
      })
      await this.approved(plan, operation, provider)
      await this.journal({ state: operation === 'apply' ? 'APPLYING' : 'ROLLING_BACK', planId })
      const rows = operation === 'apply' ? plan.rows : [...plan.rows].reverse()
      for (const [index, row] of rows.entries()) {
        await this.journal({ state: operation === 'apply' ? 'WRITE_INTENT' : 'RESTORE_INTENT', planId, index })
        await this.file(row.name, async file => {
          const bytes = Buffer.from(operation === 'apply' ? row.after : row.before, 'base64')
          const current = await file.readFile(), original = Buffer.from(row.before, 'base64'), candidate = Buffer.from(row.after, 'base64')
          if (!current.equals(original) && (operation === 'apply' || !current.equals(candidate))) throw new Error('LAB_CONTENT_DRIFT')
          // Same opened object throughout truncate/write/fsync/readback. Never follows a replacement name.
          await file.truncate(0)
          let offset = 0
          while (offset < bytes.length) offset += (await file.write(bytes, offset, bytes.length - offset, offset)).bytesWritten
          await file.sync()
          const readback = Buffer.alloc(bytes.length)
          if (bytes.length) await file.read(readback, 0, bytes.length, 0)
          if (!readback.equals(bytes) || (await file.stat()).size !== bytes.length) throw new Error('LAB_WRITE_VERIFY_FAILED')
        })
        await this.journal({ state: operation === 'apply' ? 'WROTE' : 'RESTORED', planId, index })
        if (checkpoint) await checkpoint(index) // Trusted test instrumentation only; never accepted from model input.
      }
      const state = operation === 'apply' ? 'COMMITTED' : 'ROLLED_BACK'
      await this.journal({ state, planId })
      await this.audit.append({ action: `synthetic-maintenance.${state}`, taskId: planId, changes: rows.length })
      return { state, planId, mode: 'SYNTHETIC_ONLY', byteVerified: true, hostWrites: false,
        powerLossDurability: process.platform === 'win32' ? 'NOT_VERIFIED_DIRECTORY_FSYNC_UNAVAILABLE' : 'NOT_POWER_LOSS_TESTED' }
    })
  }
  apply(planId, provider, checkpoint) { return this.execute('apply', planId, provider, checkpoint) }
  rollback(planId, provider, checkpoint) { return this.execute('rollback', planId, provider, checkpoint) }
  /** Explicit trusted recovery, never automatic expiry or optimistic lock deletion. */
  async releaseExitedProcessLock(expectedPid) {
    await this.boundary()
    const lease = await this.readSealed('lock')
    if (!Number.isSafeInteger(expectedPid) || lease.pid !== expectedPid || lease.root !== this.root) throw new Error('LAB_LOCK_IDENTITY')
    try { process.kill(expectedPid, 0); throw new Error('LAB_PROCESS_STILL_ALIVE') }
    catch (error) { if (error.code !== 'ESRCH') throw error }
    await rename(join(this.control, 'lock'), join(this.control, `abandoned-lease-${randomUUID()}.json`))
    await syncDirectory(this.control)
  }
}

export async function createSyntheticMaintenance(runtime, { operator, sessionId, seeds }) {
  if (!runtime?.approvalAuthority || !runtime?.scope || typeof operator !== 'string' || !operator || typeof sessionId !== 'string' || !sessionId || !seeds || Object.keys(seeds).length < 1 || Object.keys(seeds).length > 16) throw new Error('LAB_CONTEXT_REQUIRED')
  for (const [name, content] of Object.entries(seeds)) if (!NAME.test(name) || typeof content !== 'string' || Buffer.byteLength(content) > 65536) throw new Error('LAB_SEED_INVALID')
  await noLinks(await realpath(tmpdir()))
  const root = await mkdtemp(join(await realpath(tmpdir()), 'armorbreak-synthetic-'))
  const data = join(root, 'data'), control = join(root, 'control')
  await mkdir(data, { mode: 0o700 }); await mkdir(control, { mode: 0o700 })
  const files = {}
  for (const [name, content] of Object.entries(seeds)) { await writeNew(join(data, name), content); files[name] = identity(await lstat(join(data, name))) }
  const manifest = { schema: 'armorbreak.synthetic-maintenance/v1', root, operator, sessionId, files,
    rootId: identity(await lstat(root)), dataId: identity(await lstat(data)), controlId: identity(await lstat(control)) }
  const lab = new SyntheticMaintenance(CONSTRUCT, runtime, manifest)
  await writeNew(join(control, 'manifest.json'), lab.seal(manifest))
  await writeNew(join(control, 'journal.jsonl'), '')
  await syncDirectory(control)
  return lab
}
export async function reopenSyntheticMaintenance(runtime, root, { operator, sessionId }) {
  // Parse only after no-link checks; the sealed manifest binds the exact root and object identities.
  await noLinks(root)
  const provisional = new SyntheticMaintenance(CONSTRUCT, runtime, { root: resolve(root) })
  const manifest = await provisional.readSealed('manifest.json')
  if (manifest.schema !== 'armorbreak.synthetic-maintenance/v1' || manifest.root !== resolve(root) || manifest.operator !== operator || manifest.sessionId !== sessionId) throw new Error('LAB_CONTEXT_BINDING')
  const lab = new SyntheticMaintenance(CONSTRUCT, runtime, manifest)
  await lab.boundary(); await lab.events()
  return lab
}
