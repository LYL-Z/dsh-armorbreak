import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { inspectDshRuntimeLayout } from '../lib/integrations/dshRuntimeLayout.js'

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'armorbreak-layout-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const resources = join(root, 'resources')
  await mkdir(resources)
  return { root, resources }
}

async function official(resources, location = 'app', version = '1.2.3') {
  const dir = join(resources, location, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host')
  await mkdir(dir, { recursive: true })
  const file = join(dir, 'package.json')
  await writeFile(file, JSON.stringify({ name: '@deepseek-ai/dsh-desktop-host', version, token: 'NEVER_LEAK_TOKEN' }))
  return file
}

async function next(resources, location = 'app') {
  const dir = join(resources, location)
  await mkdir(dir, { recursive: true })
  return writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'dsh-desktop-next', main: 'main.js', version: '0.9.0', apiKey: 'NEVER_LEAK_TOKEN' }))
}

test('official package is recognized as on-disk evidence, never a loaded runtime', async t => {
  const { resources } = await fixture(t)
  await writeFile(join(resources, 'app.asar'), 'sealed archive')
  await official(resources)
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'DISK_PACKAGE_FOUND')
  assert.equal(report.disk.archive, 'PRESENT')
  assert.equal(report.identity.family, 'OFFICIAL_DISK_PACKAGE')
  assert.equal(report.identity.version, '1.2.3')
  assert.equal(report.runtime, 'NOT_VERIFIED')
  assert.equal(report.patch, 'NOT_ASSESSED')
  assert.doesNotMatch(JSON.stringify(report), /NEVER_LEAK_TOKEN/)
})

test('NEXT family is detected separately and not asserted as official', async t => {
  const { resources } = await fixture(t)
  await next(resources)
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.identity.family, 'NEXT_DISK_PACKAGE')
  assert.equal(report.status, 'DISK_PACKAGE_FOUND')
  assert.equal(report.runtime, 'NOT_VERIFIED')
})

test('both upstream family markers produce a conflict, not auto-selection', async t => {
  const { resources } = await fixture(t)
  await official(resources)
  await next(resources)
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'CONFLICTING_IDENTITIES')
  assert.equal(report.identity.family, 'UNVERIFIED')
})

test('different official package versions produce a conflict', async t => {
  const { resources } = await fixture(t)
  await official(resources, 'app', '1.0.0')
  await official(resources, 'app.asar.unpacked', '2.0.0')
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'CONFLICTING_VERSIONS')
  assert.equal(report.identity.version, null)
})

test('archive presence alone does not establish package identity or runtime', async t => {
  const { resources } = await fixture(t)
  await writeFile(join(resources, 'app.asar'), 'archive exists')
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'NO_VERIFIED_PACKAGE')
  assert.equal(report.identity.family, 'UNVERIFIED')
  assert.equal(report.runtime, 'NOT_VERIFIED')
})

test('symlinked metadata is not followed, even if it points to a valid package', async t => {
  const { root, resources } = await fixture(t)
  const external = join(root, 'outside.json')
  await writeFile(external, JSON.stringify({ name: '@deepseek-ai/dsh-desktop-host' }))
  const dir = join(resources, 'app', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host')
  if (process.platform === 'win32') {
    const outsideDir = join(root, 'outside-dir')
    await mkdir(outsideDir)
    await writeFile(join(outsideDir, 'package.json'), await readFile(external))
    await mkdir(join(dir, '..'), { recursive: true })
    await symlink(outsideDir, dir, 'junction')
  } else {
    await mkdir(dir, { recursive: true })
    await symlink(external, join(dir, 'package.json'))
  }
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'INCOMPLETE')
  assert.equal(report.identity.family, 'UNVERIFIED')
})

test('symlinked resources directory is rejected without inspecting outside files', async t => {
  const { root, resources } = await fixture(t)
  await official(resources)
  await symlink(resources, join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir')
  const report = await inspectDshRuntimeLayout({ resources: join(root, 'alias') })
  assert.equal(report.directory, 'SYMLINK_NOT_FOLLOWED')
  assert.equal(report.disk.archive, 'NOT_INSPECTED')
})

test('unknown package identity and private metadata are never included', async t => {
  const { resources } = await fixture(t)
  await mkdir(join(resources, 'app'))
  await writeFile(join(resources, 'app', 'package.json'), JSON.stringify({ name: 'private-client', version: 'https://token@host', main: 'SECRET_CODE' }))
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'NO_VERIFIED_PACKAGE')
  assert.doesNotMatch(JSON.stringify(report), /private-client|SECRET_CODE|token@host/)
})

test('oversized metadata cannot be parsed as valid package', async t => {
  const { resources } = await fixture(t)
  const file = await official(resources)
  await writeFile(file, JSON.stringify({ name: '@deepseek-ai/dsh-desktop-host', padding: 'X'.repeat(70_000) }))
  const report = await inspectDshRuntimeLayout({ resources })
  assert.equal(report.status, 'INCOMPLETE')
  assert.equal(report.identity.family, 'UNVERIFIED')
})

test('invalid and relative resources paths are rejected', async () => {
  await assert.rejects(() => inspectDshRuntimeLayout({ resources: 'relative' }), /absolute/)
  await assert.rejects(() => inspectDshRuntimeLayout({ resources: '/' + 'x'.repeat(5000) }), /absolute/)
})

test('successful inspection does not modify any host metadata', async t => {
  const { resources } = await fixture(t)
  const file = await official(resources)
  const before = await stat(file)
  const contents = await readFile(file)
  await inspectDshRuntimeLayout({ resources })
  const after = await stat(file)
  assert.deepEqual(await readFile(file), contents)
  assert.equal(after.mtimeMs, before.mtimeMs)
})
