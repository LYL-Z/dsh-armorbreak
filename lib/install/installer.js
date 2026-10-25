/**
 * AB2-M2-11 transactional installer (metadata/artifact copy only).
 *
 * It never runs npm/pip/package scripts. States:
 * PLANNED -> STAGED -> APPROVED -> ACTIVE -> ROLLED_BACK, with FAILED cleanup.
 * Approval needs a Host-bound token over the immutable planHash.
 */
import { createHash } from 'node:crypto'
import { copyFile, lstat, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { isAbsolute, join, parse, relative, resolve, sep } from 'node:path'
import { assessPlan } from '../catalog/licenseGate.js'
import { hashFileStream } from '../workers/contentStore.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')
const PLAN_ID = /^plan-[a-f0-9]{16}$/

function checkedPlanId(value) {
  const planId = String(value ?? '')
  if (!PLAN_ID.test(planId)) throw new Error('invalid installer planId')
  return planId
}

function isWithin(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate))
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

/** Reject symlinks and Windows junctions in managed paths before file operations. */
async function assertNoReparseComponents(path) {
  const absolute = resolve(path)
  const volumeRoot = parse(absolute).root
  let current = volumeRoot
  for (const part of relative(volumeRoot, absolute).split(sep).filter(Boolean)) {
    current = join(current, part)
    try {
      const info = await lstat(current)
      if (info.isSymbolicLink()) throw new Error(`managed path contains a symlink or junction: ${current}`)
    } catch (error) {
      if (error?.code === 'ENOENT') break
      throw error
    }
  }
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  return JSON.stringify(value)
}

async function atomicWrite(file, content) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await assertNoReparseComponents(file)
  await writeFile(tmp, content, { flag: 'wx' })
  await assertNoReparseComponents(file)
  // On failure, leave the temp path for trusted cleanup. A name-based rm() here
  // could follow an ancestor replaced after validation into an external tree.
  await rename(tmp, file)
}

export class TransactionalInstaller {
  /**
   * @param {{root:string, approvalAuthority:any, clock?:()=>number}} input
   */
  constructor(input) {
    this.root = resolve(input.root)
    this.approvalAuthority = input.approvalAuthority
    this.clock = input.clock ?? Date.now
    this.plans = join(this.root, 'plans')
    this.staging = join(this.root, 'staging')
    this.installed = join(this.root, 'installed')
    this.activePointer = join(this.root, 'active.json')
  }

  async plan(input) {
    const assessment = assessPlan({ components: input.components ?? [] })
    if (!assessment.allowed) {
      return { status: 'REJECTED', code: 'SUPPLYCHAIN_DENIED', assessment, stages: [] }
    }
    const artifactPath = String(input.artifactPath ?? '')
    if (!artifactPath) throw new Error('installer plan needs artifactPath')
    const artifactHash = await hashFileStream(artifactPath)
    const candidate = {
      repo: String(input.repo ?? '').slice(0, 300),
      commit: String(input.commit ?? '').slice(0, 100),
      version: String(input.version ?? '').slice(0, 100),
      license: String(input.license ?? '').slice(0, 100),
      permissions: Array.isArray(input.permissions) ? input.permissions.map(String).slice(0, 50) : [],
      dependencies: Array.isArray(input.dependencies) ? input.dependencies.map(String).slice(0, 200) : [],
      rollback: { previousActive: null },
    }
    const planBody = {
      schemaVersion: 'armorbreak.installation-plan/v1',
      candidate,
      artifact: { path: artifactPath, sha256: artifactHash.sha256, bytes: artifactHash.bytes },
      steps: ['plan', 'stage', 'verify', 'approve', 'activate'],
      approvalRequired: true,
      executePackageCode: false,
      createdAt: new Date(this.clock()).toISOString(),
      assessment,
    }
    const planHash = sha256(canonical(planBody))
    const planId = `plan-${planHash.slice(0, 16)}`
    const plan = { ...planBody, planId, planHash, status: 'PLANNED' }
    return plan
  }

  planFile(planId) {
    return join(this.plans, `${checkedPlanId(planId)}.json`)
  }

  stateFile(planId) {
    return join(this.root, 'installations', `${checkedPlanId(planId)}.json`)
  }

  async list() {
    const { readdir } = await import('node:fs/promises')
    await assertNoReparseComponents(this.plans)
    let files = []
    try { files = await readdir(this.plans) } catch { return [] }
    const plans = []
    for (const file of files.filter((name) => name.endsWith('.json'))) {
      try { plans.push(JSON.parse(await readFile(join(this.plans, file), 'utf8'))) } catch { /* skip corrupt */ }
    }
    return plans.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).map((plan) => ({
      planId: plan.planId,
      planHash: plan.planHash,
      status: plan.status,
      candidate: plan.candidate,
      artifact: { sha256: plan.artifact?.sha256, bytes: plan.artifact?.bytes },
      approvedBy: plan.approvedBy ?? null,
      createdAt: plan.createdAt,
      active: plan.active === true,
    }))
  }

  async get(planId) {
    const file = this.planFile(planId)
    await assertNoReparseComponents(file)
    return JSON.parse(await readFile(file, 'utf8'))
  }

  async persist(plan) {
    checkedPlanId(plan?.planId)
    await assertNoReparseComponents(this.root)
    await assertNoReparseComponents(this.plans)
    await assertNoReparseComponents(join(this.root, 'installations'))
    await mkdir(this.plans, { recursive: true })
    await mkdir(join(this.root, 'installations'), { recursive: true })
    await atomicWrite(this.planFile(plan.planId), `${JSON.stringify(plan, null, 2)}\n`)
    await atomicWrite(this.stateFile(plan.planId), `${JSON.stringify({ planId: plan.planId, status: plan.status, updatedAt: new Date(this.clock()).toISOString(), approvedBy: plan.approvedBy ?? null, active: plan.active ?? false }, null, 2)}\n`)
    return plan
  }

  async stage(plan) {
    const planId = checkedPlanId(plan?.planId)
    if (plan.status !== 'PLANNED') throw new Error(`cannot stage plan in ${plan.status}`)
    const artifact = await hashFileStream(plan.artifact.path)
    if (artifact.sha256 !== plan.artifact.sha256) throw new Error('artifact changed since plan')
    const dir = join(this.staging, planId)
    if (!isWithin(this.root, dir)) throw new Error('installer staging path is outside installer root')
    await assertNoReparseComponents(this.root)
    await assertNoReparseComponents(this.staging)
    await mkdir(dir, { recursive: true })
    await copyFile(plan.artifact.path, join(dir, 'artifact.bin'))
    await writeFile(join(dir, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`)
    const staged = { ...plan, status: 'STAGED', stagingDir: dir, stagedAt: new Date(this.clock()).toISOString() }
    await this.persist(staged)
    return staged
  }

  async verify(plan) {
    const planId = checkedPlanId(plan?.planId)
    if (plan.status !== 'STAGED') throw new Error(`cannot verify plan in ${plan.status}`)
    const stagingDir = join(this.staging, planId)
    await assertNoReparseComponents(stagingDir)
    const artifact = await hashFileStream(join(stagingDir, 'artifact.bin'))
    if (artifact.sha256 !== plan.artifact.sha256) throw new Error('staged artifact hash mismatch')
    if (plan.executePackageCode !== false) throw new Error('installer must not execute package code')
    const verified = { ...plan, status: 'VERIFIED', verifiedAt: new Date(this.clock()).toISOString() }
    await this.persist(verified)
    return verified
  }

  async approve(plan, approval) {
    checkedPlanId(plan?.planId)
    if (plan.status !== 'VERIFIED') throw new Error(`cannot approve plan in ${plan.status}`)
    if (!this.approvalAuthority) throw new Error('installer approval authority missing')
    const token = approval?.approvalToken
    if (!token) throw new Error('approval token required')
    const operator = String(approval.operator ?? approval.approvedBy ?? '').trim()
    if (operator.length < 2) throw new Error('operator required')
    const expected = { id: `install:${plan.planId}`, riskLevel: 'L2', taskId: plan.planId, target: plan.planHash, operator }
    const consumed = this.approvalAuthority.consume(token, expected)
    if (!consumed.valid) throw new Error(`install approval rejected: ${consumed.code}: ${consumed.reason}`)
    const approved = { ...plan, status: 'APPROVED', approvedBy: operator, approvalId: expected.id, approvedAt: new Date(this.clock()).toISOString() }
    await this.persist(approved)
    return approved
  }

  async activate(plan) {
    const planId = checkedPlanId(plan?.planId)
    if (plan.status !== 'APPROVED') throw new Error('activation requires explicit approval')
    const stagingDir = join(this.staging, planId)
    await assertNoReparseComponents(stagingDir)
    const artifact = await hashFileStream(join(stagingDir, 'artifact.bin'))
    if (artifact.sha256 !== plan.artifact.sha256) throw new Error('staged artifact changed before activation')
    await assertNoReparseComponents(this.root)
    await assertNoReparseComponents(this.activePointer)
    await assertNoReparseComponents(join(this.root, 'previous-active.json'))
    const previous = await readFile(this.activePointer, 'utf8').catch(() => null)
    if (previous) await writeFile(join(this.root, 'previous-active.json'), previous)
    const dir = join(this.installed, planId)
    await assertNoReparseComponents(this.root)
    await assertNoReparseComponents(this.installed)
    await mkdir(dir, { recursive: true })
    await copyFile(join(stagingDir, 'artifact.bin'), join(dir, 'artifact.bin'))
    await writeFile(join(dir, 'manifest.json'), `${JSON.stringify({ planId: plan.planId, planHash: plan.planHash, approvedBy: plan.approvedBy, artifactSha256: artifact.sha256, executePackageCode: false, activatedAt: new Date(this.clock()).toISOString() }, null, 2)}\n`)
    await atomicWrite(this.activePointer, `${JSON.stringify({ planId: plan.planId, planHash: plan.planHash, installedDir: dir }, null, 2)}\n`)
    const active = { ...plan, status: 'ACTIVE', active: true, installedDir: dir, activatedAt: new Date(this.clock()).toISOString() }
    await this.persist(active)
    return active
  }

  async rollback(plan) {
    const planId = checkedPlanId(plan?.planId)
    await assertNoReparseComponents(this.root)
    await assertNoReparseComponents(this.activePointer)
    await assertNoReparseComponents(join(this.root, 'previous-active.json'))
    const deferredCleanup = []
    if (plan.status === 'ACTIVE') {
      const previous = await readFile(join(this.root, 'previous-active.json'), 'utf8').catch(() => null)
      if (previous) await atomicWrite(this.activePointer, previous)
      else await atomicWrite(this.activePointer, `${JSON.stringify({ schemaVersion: 'armorbreak.installer-active-pointer/v1', active: false, rolledBackPlanId: planId, rolledBackAt: new Date(this.clock()).toISOString() }, null, 2)}\n`)
      deferredCleanup.push('installed')
    }
    deferredCleanup.push('staging')
    const rolled = {
      ...plan,
      status: 'ROLLED_BACK',
      active: false,
      rolledBackAt: new Date(this.clock()).toISOString(),
      cleanup: {
        status: 'DEFERRED',
        targets: deferredCleanup,
        reason: 'portable-handle-relative-recursive-delete-unavailable',
      },
    }
    await this.persist(rolled)
    return rolled
  }

  async fail(plan, error) {
    const planId = checkedPlanId(plan?.planId)
    const failed = {
      ...plan,
      status: 'FAILED',
      error: String(error?.message ?? error).slice(0, 500),
      failedAt: new Date(this.clock()).toISOString(),
      cleanup: {
        status: 'DEFERRED',
        targets: ['staging'],
        reason: 'portable-handle-relative-recursive-delete-unavailable',
      },
    }
    await this.persist(failed)
    return failed
  }
}
