import assert from 'node:assert/strict'
import fs, { existsSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { TransactionalInstaller } from '../lib/install/installer.js'

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'abm-installer-path-'))
  const installer = new TransactionalInstaller({ root: join(root, 'installer') })
  return { root, installer }
}

test('installer rejects traversal plan IDs before reading plans or rolling back', async () => {
  const { root, installer } = await fixture()
  const victim = join(root, 'victim')
  await mkdir(victim)
  const marker = join(victim, 'sentinel.txt')
  await writeFile(marker, 'SYNTHETIC-OUTSIDE-INSTALLER-ROOT')

  await assert.rejects(() => installer.get('..\\..\\victim'), /invalid installer planId/)
  await assert.rejects(() => installer.rollback({ planId: '..\\..\\victim', status: 'ACTIVE', installedDir: victim }), /invalid installer planId/)
  assert.equal(await readFile(marker, 'utf8'), 'SYNTHETIC-OUTSIDE-INSTALLER-ROOT')
})

test('rollback ignores external plan paths and defers unsafe recursive cleanup', async () => {
  const { root, installer } = await fixture()
  const planId = 'plan-0123456789abcdef'
  const external = join(root, 'external-victim')
  const externalMarker = join(external, 'sentinel.txt')
  const managedInstalled = join(installer.installed, planId)
  const managedStaging = join(installer.staging, planId)
  await mkdir(external, { recursive: true })
  await mkdir(managedInstalled, { recursive: true })
  await mkdir(managedStaging, { recursive: true })
  await writeFile(externalMarker, 'KEEP-EXTERNAL')
  await writeFile(join(managedInstalled, 'artifact.bin'), 'managed installed')
  await writeFile(join(managedStaging, 'artifact.bin'), 'managed staging')

  const result = await installer.rollback({
    planId,
    status: 'ACTIVE',
    installedDir: external,
    stagingDir: external,
  })

  assert.equal(result.status, 'ROLLED_BACK')
  assert.deepEqual(result.cleanup, {
    status: 'DEFERRED',
    targets: ['installed', 'staging'],
    reason: 'portable-handle-relative-recursive-delete-unavailable',
  })
  assert.equal(await readFile(externalMarker, 'utf8'), 'KEEP-EXTERNAL')
  assert.equal(existsSync(managedInstalled), true)
  assert.equal(existsSync(managedStaging), true)
})

test('installer rollback never reaches recursive delete after a parent junction swap opportunity', async (t) => {
  const { root, installer } = await fixture()
  t.after(() => rm(root, { recursive: true, force: true }))
  const planId = 'plan-0123456789abcdef'
  const installedRoot = installer.installed
  const retainedInstalled = `${installedRoot}-retained`
  const outsideInstalled = join(root, 'outside-installed')
  const managedInstalled = join(installedRoot, planId)
  const outsidePlan = join(outsideInstalled, planId)
  const sentinel = join(outsidePlan, 'sentinel.txt')
  let injected = false
  const originalRm = fs.promises.rm

  await mkdir(managedInstalled, { recursive: true })
  await mkdir(join(installer.staging, planId), { recursive: true })
  await mkdir(outsidePlan, { recursive: true })
  await writeFile(sentinel, 'SYNTHETIC_OUTSIDE_INSTALLER_SENTINEL')

  fs.promises.rm = async function (path, options) {
    if (!injected && String(path).toLowerCase() === managedInstalled.toLowerCase() && options?.recursive) {
      await rename(installedRoot, retainedInstalled)
      await symlink(outsideInstalled, installedRoot, process.platform === 'win32' ? 'junction' : 'dir')
      injected = true
    }
    return originalRm.call(this, path, options)
  }
  syncBuiltinESMExports()
  let result
  try {
    result = await installer.rollback({ planId, status: 'ACTIVE' })
  } finally {
    fs.promises.rm = originalRm
    syncBuiltinESMExports()
  }

  assert.equal(injected, false, 'rollback must not invoke recursive deletion on the attacker-controlled path')
  assert.equal(result.cleanup.status, 'DEFERRED')
  assert.equal(await readFile(sentinel, 'utf8'), 'SYNTHETIC_OUTSIDE_INSTALLER_SENTINEL')
  assert.equal(existsSync(managedInstalled), true)
  assert.equal(existsSync(join(installer.staging, planId)), true)
  assert.equal(existsSync(retainedInstalled), false)
})

test('installer rollback fails closed if the root is replaced before active-pointer rename', async (t) => {
  const { root, installer } = await fixture()
  t.after(() => rm(root, { recursive: true, force: true }))
  const retainedRoot = `${installer.root}-retained`
  const outsideRoot = join(root, 'outside-installer-root')
  const outsidePointer = join(outsideRoot, 'active.json')
  await mkdir(installer.root, { recursive: true })
  await mkdir(outsideRoot, { recursive: true })
  await writeFile(join(installer.root, 'active.json'), 'CURRENT-POINTER')
  await writeFile(outsidePointer, 'KEEP-EXTERNAL-POINTER')

  const originalRename = fs.promises.rename
  let injected = false
  fs.promises.rename = async function (from, to) {
    if (!injected && String(to).toLowerCase() === installer.activePointer.toLowerCase()) {
      await originalRename(installer.root, retainedRoot)
      await symlink(outsideRoot, installer.root, process.platform === 'win32' ? 'junction' : 'dir')
      injected = true
    }
    return originalRename.call(this, from, to)
  }
  syncBuiltinESMExports()
  try {
    await assert.rejects(
      () => installer.rollback({ planId: 'plan-0123456789abcdef', status: 'ACTIVE' }),
      /ENOENT|managed path contains a symlink or junction/,
    )
    assert.equal(injected, true)
    assert.equal(await readFile(outsidePointer, 'utf8'), 'KEEP-EXTERNAL-POINTER')
    assert.equal(await readFile(join(retainedRoot, 'active.json'), 'utf8'), 'CURRENT-POINTER')
  } finally {
    fs.promises.rename = originalRename
    syncBuiltinESMExports()
    await fs.promises.unlink(installer.root).catch(() => {})
    if (existsSync(retainedRoot)) await originalRename(retainedRoot, installer.root)
  }
})

test('installer failure does not recurse through a replaced staging junction or symlink', async (t) => {
  const { root, installer } = await fixture()
  const victim = join(root, 'junction-victim')
  const marker = join(victim, 'sentinel.txt')
  await mkdir(victim, { recursive: true })
  await writeFile(marker, 'KEEP-JUNCTION-TARGET')
  await mkdir(installer.root, { recursive: true })
  try {
    await symlink(victim, installer.staging, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    t.skip(`could not create isolated directory link: ${String(error?.code ?? error)}`)
    return
  }

  const failed = await installer.fail({ planId: 'plan-fedcba9876543210', status: 'STAGED' }, new Error('synthetic failure'))
  assert.equal(failed.status, 'FAILED')
  assert.equal(failed.cleanup.status, 'DEFERRED')
  assert.equal(await readFile(marker, 'utf8'), 'KEEP-JUNCTION-TARGET')
})
