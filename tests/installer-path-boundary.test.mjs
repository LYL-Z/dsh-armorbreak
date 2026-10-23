import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises'
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

test('rollback deletes only derived managed paths and ignores external plan directory fields', async () => {
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
  assert.equal(await readFile(externalMarker, 'utf8'), 'KEEP-EXTERNAL')
  assert.equal(existsSync(managedInstalled), false)
  assert.equal(existsSync(managedStaging), false)
})

test('installer cleanup refuses a staging junction or symlink that points outside its root', async (t) => {
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

  await assert.rejects(
    () => installer.fail({ planId: 'plan-fedcba9876543210', status: 'STAGED' }, new Error('synthetic failure')),
    /symlink or junction/,
  )
  assert.equal(await readFile(marker, 'utf8'), 'KEEP-JUNCTION-TARGET')
})
