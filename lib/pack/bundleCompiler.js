/**
 * AB2-M2-12 DSH bundle compiler + isolated profile adapter.
 *
 * Compiles the bundle manifest from real repo files (no package execution) and
 * applies a profile upgrade only against a test profile: other bundles/presets
 * are preserved, the target preset id is unchanged, and rollback restores exact
 * bytes. This is not a claim that the real DSH Desktop profile was upgraded.
 */
import { createHash } from 'node:crypto'
import { copyFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { buildCorePack } from './corePack.js'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

async function atomicWrite(file, content) {
  await mkdir(dirname(file), { recursive: true })
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, content)
  await rename(tmp, file)
}

export const BUNDLE_INCLUDE = ['package.json', 'index.js', 'tools.js', 'skills.js', 'client.js', 'cordis.patch.yml', 'icon.svg', 'lib', 'skills', 'locale']

export async function compileBundle(input) {
  const root = input.root
  const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
  const patch = await readFile(join(root, 'cordis.patch.yml'), 'utf8')
  const presetMatch = patch.match(/\bid:\s*armorbreak\b/)
  if (!presetMatch) throw new Error('bundle patch does not declare preset id armorbreak')
  if (/\boverride\s*:/.test(patch)) throw new Error('bundle patch contains override rows; refusing to compile a destructive adapter')
  const pack = await buildCorePack({ root, include: BUNDLE_INCLUDE })
  return {
    schemaVersion: 'armorbreak.bundle/v1',
    name: String(pkg.name ?? ''),
    version: String(pkg.version ?? ''),
    preset: { id: 'armorbreak', preserved: true },
    entries: pack.entries,
    aggregateSha256: pack.aggregateSha256,
    fileCount: pack.fileCount,
    totalBytes: pack.totalBytes,
    executable: false,
  }
}

/** @param {{profileDir:string, bundle:any}} input */
export async function planProfileUpgrade(input) {
  const profilePath = join(input.profileDir, 'profile.json')
  const currentText = await readFile(profilePath, 'utf8')
  const current = JSON.parse(currentText)
  const otherBundles = (current.bundles ?? []).filter((bundle) => bundle.name !== input.bundle.name)
  const targetPreset = (current.presets ?? []).find((preset) => preset.id === 'armorbreak')
  if (!targetPreset) throw new Error('test profile does not have the armorbreak preset')
  const next = {
    ...current,
    bundles: [...otherBundles, { name: input.bundle.name, version: input.bundle.version, aggregateSha256: input.bundle.aggregateSha256 }],
    presets: (current.presets ?? []).map((preset) => preset.id === 'armorbreak' ? { ...preset, bundle: input.bundle.name } : preset),
  }
  const currentSha256 = sha256(currentText)
  const nextText = `${JSON.stringify(next, null, 2)}\n`
  return {
    schemaVersion: 'armorbreak.profile-plan/v1',
    planHash: sha256(`${currentSha256}\n${input.bundle.aggregateSha256}\n${nextText}`),
    profileDir: input.profileDir,
    currentSha256,
    bundleSha256: input.bundle.aggregateSha256,
    nextText,
    preserved: { bundles: otherBundles.map((bundle) => bundle.name), presetId: 'armorbreak' },
    executable: false,
  }
}

export async function applyProfileUpgrade(plan) {
  const expectedPlanHash = sha256(`${plan.currentSha256}\n${plan.bundleSha256}\n${plan.nextText}`)
  if (plan.planHash !== expectedPlanHash) throw new Error('profile plan hash mismatch')
  if (plan.preserved.presetId !== 'armorbreak') throw new Error('plan would change the armorbreak preset id')
  const profilePath = join(plan.profileDir, 'profile.json')
  const current = await readFile(profilePath, 'utf8')
  if (sha256(current) !== plan.currentSha256) throw new Error('profile changed after planning; refusing to overwrite')
  const backupDir = join(plan.profileDir, '.backup')
  await mkdir(backupDir, { recursive: true })
  const backup = join(backupDir, `profile-${Date.now()}.json`)
  await copyFile(profilePath, backup)
  const backupSha = sha256(await readFile(backup))
  if (backupSha !== plan.currentSha256) throw new Error('backup hash mismatch')
  await atomicWrite(profilePath, plan.nextText)
  return { applied: true, backup, planHash: plan.planHash }
}

export async function rollbackProfileUpgrade({ backup, profileDir }) {
  const profilePath = join(profileDir, 'profile.json')
  const backupText = await readFile(backup, 'utf8')
  await atomicWrite(profilePath, backupText)
  return { restored: true, sha256: sha256(backupText) }
}
