import assert from 'node:assert/strict'
import fs from 'node:fs'
import { mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ApprovalAuthority } from '../lib/control/approvalAuthority.js'
import { TransactionalInstaller } from '../lib/install/installer.js'

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'abm-install-'))
  const artifact = join(root, 'bundle.tgz')
  await writeFile(artifact, 'ARMORBREAK-BUNDLE')
  const authority = new ApprovalAuthority({ stateRoot: join(root, 'state') })
  const installer = new TransactionalInstaller({ root: join(root, 'install-root'), approvalAuthority: authority })
  return { root, artifact, authority, installer }
}

const goodComponent = { name: 'bundle', version: '1.0.0', license: 'MIT', commit: 'abc123', digest: 'sha256:abc', scripts: {} }

test('plan rejects unknown license before any staging/execution', async () => {
  const { artifact, installer } = await fixture()
  const rejected = await installer.plan({ artifactPath: artifact, components: [{ ...goodComponent, license: 'Proprietary-X' }] })
  assert.equal(rejected.status, 'REJECTED')
  assert.equal(rejected.code, 'SUPPLYCHAIN_DENIED')
})

test('install transaction requires stage/verify/approval before activation and rolls back', async () => {
  const { artifact, authority, installer } = await fixture()
  const plan = await installer.plan({ artifactPath: artifact, components: [goodComponent], repo: 'github.com/a/b', commit: 'abc123', version: '1.0.0', license: 'MIT' })
  assert.equal(plan.status, 'PLANNED')
  assert.equal(plan.executePackageCode, false)
  await assert.rejects(() => installer.activate(plan), /requires explicit approval/)
  const staged = await installer.stage(plan)
  assert.equal(staged.status, 'STAGED')
  const verified = await installer.verify(staged)
  assert.equal(verified.status, 'VERIFIED')
  await assert.rejects(() => installer.approve(verified, {}), /approval token required/)
  const token = authority.issue({ id: `install:${plan.planId}`, riskLevel: 'L2', taskId: plan.planId, target: plan.planHash, operator: 'alice' }).token
  const approved = await installer.approve(verified, { approvalToken: token, operator: 'alice' })
  assert.equal(approved.status, 'APPROVED')
  const active = await installer.activate(approved)
  assert.equal(active.status, 'ACTIVE')
  assert.equal(JSON.parse(await readFile(join(installer.root, 'active.json'), 'utf8')).planId, plan.planId)
  const rolled = await installer.rollback(active)
  assert.equal(rolled.status, 'ROLLED_BACK')
  assert.equal(rolled.cleanup.status, 'DEFERRED')
  const pointer = JSON.parse(await readFile(join(installer.root, 'active.json'), 'utf8'))
  assert.equal(pointer.active, false)
  assert.equal(pointer.rolledBackPlanId, plan.planId)
})

test('installer rollback defers recursive cleanup instead of following a swapped installed ancestor', async () => {
  const { root, installer } = await fixture()
  const planId = 'plan-0123456789abcdef'
  const installedRoot = installer.installed
  const retainedRoot = `${installedRoot}-retained`
  const outsideRoot = join(root, 'outside-installed')
  const managed = join(installedRoot, planId)
  const outsidePlan = join(outsideRoot, planId)
  const sentinel = join(outsidePlan, 'sentinel.txt')
  const originalRm = fs.promises.rm
  let swapped = false
  let linked = false

  try {
    await mkdir(managed, { recursive: true })
    await mkdir(outsidePlan, { recursive: true })
    await writeFile(join(managed, 'owned.txt'), 'SYNTHETIC-IN-ROOT')
    await writeFile(sentinel, 'SYNTHETIC-OUTSIDE-INSTALLER-SENTINEL')

    fs.promises.rm = async function (path, options) {
      if (!swapped && String(path) === managed) {
        await rename(installedRoot, retainedRoot)
        await symlink(outsideRoot, installedRoot, process.platform === 'win32' ? 'junction' : 'dir')
        swapped = true
        linked = true
      }
      return originalRm.call(this, path, options)
    }
    syncBuiltinESMExports()

    const rolled = await installer.rollback({ planId, status: 'ACTIVE', active: true })

    assert.equal(rolled.status, 'ROLLED_BACK')
    assert.equal(rolled.cleanup.status, 'DEFERRED')
    assert.deepEqual(rolled.cleanup.targets, ['installed', 'staging'])
    assert.equal(swapped, false, 'rollback must not attempt a path-based recursive delete')
    assert.equal(await readFile(sentinel, 'utf8'), 'SYNTHETIC-OUTSIDE-INSTALLER-SENTINEL')
    assert.equal(await readFile(join(managed, 'owned.txt'), 'utf8'), 'SYNTHETIC-IN-ROOT')
  } finally {
    fs.promises.rm = originalRm
    syncBuiltinESMExports()
    if (linked) await rm(installedRoot, { recursive: true, force: true }).catch(() => {})
    if (await import('node:fs').then(({ existsSync }) => existsSync(retainedRoot))) {
      await rename(retainedRoot, installedRoot).catch(() => {})
    }
    await rm(root, { recursive: true, force: true }).catch(() => {})
  }
})

test('failed pre-activation transaction records deferred cleanup and leaves no half install active', async () => {
  const { artifact, installer } = await fixture()
  const plan = await installer.plan({ artifactPath: artifact, components: [goodComponent] })
  const staged = await installer.stage(plan)
  const failed = await installer.fail(staged, new Error('simulated copy failure'))
  assert.equal(failed.status, 'FAILED')
  assert.equal(failed.cleanup.status, 'DEFERRED')
  await assert.rejects(() => readFile(join(installer.root, 'active.json')), /ENOENT/)
  const { existsSync } = await import('node:fs')
  assert.equal(existsSync(join(installer.staging, plan.planId)), true)
  assert.equal(existsSync(join(installer.installed, plan.planId)), false)
})
