/**
 * AB2-M2-11 transactional installer (metadata/artifact copy only).
 *
 * It never runs npm/pip/package scripts. States:
 * PLANNED -> STAGED -> APPROVED -> ACTIVE -> ROLLED_BACK, with FAILED cleanup.
 * Approval needs a Host-bound token over the immutable planHash.
 */
import { createHash } from 'node:crypto'
import { copyFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assessPlan } from '../catalog/licenseGate.js'
import { hashFileStream } from '../workers/contentStore.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
  return JSON.stringify(value)
}

async function atomicWrite(file, content) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, content)
  await rename(tmp, file)
}

export class TransactionalInstaller {
  /**
   * @param {{root:string, approvalAuthority:any, clock?:()=>number}} input
   */
  constructor(input) {
    this.root = input.root
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
    return join(this.plans, `${planId}.json`)
  }

  stateFile(planId) {
    return join(this.root, 'installations', `${planId}.json`)
  }

  async persist(plan) {
    await mkdir(this.plans, { recursive: true })
    await mkdir(join(this.root, 'installations'), { recursive: true })
    await atomicWrite(this.planFile(plan.planId), `${JSON.stringify(plan, null, 2)}\n`)
    await atomicWrite(this.stateFile(plan.planId), `${JSON.stringify({ planId: plan.planId, status: plan.status, updatedAt: new Date(this.clock()).toISOString(), approvedBy: plan.approvedBy ?? null, active: plan.active ?? false }, null, 2)}\n`)
    return plan
  }

  async stage(plan) {
    if (plan.status !== 'PLANNED') throw new Error(`cannot stage plan in ${plan.status}`)
    const artifact = await hashFileStream(plan.artifact.path)
    if (artifact.sha256 !== plan.artifact.sha256) throw new Error('artifact changed since plan')
    const dir = join(this.staging, plan.planId)
    await mkdir(dir, { recursive: true })
    await copyFile(plan.artifact.path, join(dir, 'artifact.bin'))
    await writeFile(join(dir, 'plan.json'), `${JSON.stringify(plan, null, 2)}\n`)
    const staged = { ...plan, status: 'STAGED', stagingDir: dir, stagedAt: new Date(this.clock()).toISOString() }
    await this.persist(staged)
    return staged
  }

  async verify(plan) {
    if (plan.status !== 'STAGED') throw new Error(`cannot verify plan in ${plan.status}`)
    const artifact = await hashFileStream(join(plan.stagingDir, 'artifact.bin'))
    if (artifact.sha256 !== plan.artifact.sha256) throw new Error('staged artifact hash mismatch')
    if (plan.executePackageCode !== false) throw new Error('installer must not execute package code')
    const verified = { ...plan, status: 'VERIFIED', verifiedAt: new Date(this.clock()).toISOString() }
    await this.persist(verified)
    return verified
  }

  async approve(plan, approval) {
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
    if (plan.status !== 'APPROVED') throw new Error('activation requires explicit approval')
    const artifact = await hashFileStream(join(plan.stagingDir, 'artifact.bin'))
    if (artifact.sha256 !== plan.artifact.sha256) throw new Error('staged artifact changed before activation')
    const previous = await readFile(this.activePointer, 'utf8').catch(() => null)
    if (previous) await writeFile(join(this.root, 'previous-active.json'), previous)
    const dir = join(this.installed, plan.planId)
    await mkdir(dir, { recursive: true })
    await copyFile(join(plan.stagingDir, 'artifact.bin'), join(dir, 'artifact.bin'))
    await writeFile(join(dir, 'manifest.json'), `${JSON.stringify({ planId: plan.planId, planHash: plan.planHash, approvedBy: plan.approvedBy, artifactSha256: artifact.sha256, executePackageCode: false, activatedAt: new Date(this.clock()).toISOString() }, null, 2)}\n`)
    await atomicWrite(this.activePointer, `${JSON.stringify({ planId: plan.planId, planHash: plan.planHash, installedDir: dir }, null, 2)}\n`)
    const active = { ...plan, status: 'ACTIVE', active: true, installedDir: dir, activatedAt: new Date(this.clock()).toISOString() }
    await this.persist(active)
    return active
  }

  async rollback(plan) {
    if (plan.status === 'ACTIVE') {
      const previous = await readFile(join(this.root, 'previous-active.json'), 'utf8').catch(() => null)
      if (previous) await atomicWrite(this.activePointer, previous)
      else await rm(this.activePointer, { force: true })
      await rm(plan.installedDir ?? join(this.installed, plan.planId), { recursive: true, force: true })
    }
    if (plan.stagingDir) await rm(plan.stagingDir, { recursive: true, force: true })
    const rolled = { ...plan, status: 'ROLLED_BACK', active: false, rolledBackAt: new Date(this.clock()).toISOString() }
    await this.persist(rolled)
    return rolled
  }

  async fail(plan, error) {
    if (plan.stagingDir) await rm(plan.stagingDir, { recursive: true, force: true })
    const failed = { ...plan, status: 'FAILED', error: String(error?.message ?? error).slice(0, 500), failedAt: new Date(this.clock()).toISOString() }
    await this.persist(failed)
    return failed
  }
}
