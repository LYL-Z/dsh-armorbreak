/**
 * Read-only inventory of an explicitly selected DeepSeek Harness profile.
 *
 * This is an independent ArmorBreak implementation. It does not load plugin
 * code, parse instructions from profile YAML, or mutate a host installation.
 */
import { lstat, open } from 'node:fs/promises'
import { constants } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'

const PROFILE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/
const MAX_BYTES = 1024 * 1024
const PACKAGES = Object.freeze(['dsh-armorbreak', 'dsh-purge', 'dsh-purge-community'])

async function regularFile(path) {
  try {
    const stat = await lstat(path)
    if (stat.isSymbolicLink()) return { status: 'SYMLINK_NOT_FOLLOWED' }
    if (!stat.isFile()) return { status: 'NOT_REGULAR_FILE' }
    if (stat.size > MAX_BYTES) return { status: 'TOO_LARGE' }
    return { status: 'OK', bytes: stat.size }
  } catch (error) {
    if (error?.code === 'ENOENT') return { status: 'MISSING' }
    return { status: 'UNREADABLE' }
  }
}

async function regularDirectory(path) {
  try {
    const stat = await lstat(path)
    return stat.isSymbolicLink() ? 'SYMLINK_NOT_FOLLOWED' : stat.isDirectory() ? 'OK' : 'NOT_DIRECTORY'
  } catch (error) {
    return error?.code === 'ENOENT' ? 'MISSING' : 'UNREADABLE'
  }
}

async function readBounded(path) {
  const file = await regularFile(path)
  if (file.status !== 'OK') return { status: file.status }
  let handle
  try {
    // O_NOFOLLOW closes the final-component symlink swap window where supported.
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const current = await handle.stat()
    if (!current.isFile()) return { status: 'NOT_REGULAR_FILE' }
    if (current.size > MAX_BYTES) return { status: 'TOO_LARGE' }
    const bytes = await handle.readFile()
    if (bytes.length > MAX_BYTES) return { status: 'TOO_LARGE' }
    return { status: 'OK', bytes: bytes.length, content: bytes.toString('utf8') }
  } catch {
    return { status: 'UNREADABLE' }
  } finally {
    await handle?.close()
  }
}

/**
 * Inventory one profile; a package dependency is never reported as proof that
 * its runtime code is currently loaded or that a host patch has taken effect.
 */
export async function inspectDshHostProfile({ home, profile } = {}) {
  if (typeof home !== 'string' || !isAbsolute(home)) throw new Error('host inspect requires an absolute --home path')
  if (typeof profile !== 'string' || !PROFILE_NAME.test(profile)) throw new Error('invalid --profile name')

  const root = resolve(home)
  const profiles = join(root, 'profiles')
  const directory = join(profiles, profile)
  const directories = [root, profiles, directory]
  const directoryStatuses = []
  for (const path of directories) directoryStatuses.push(await regularDirectory(path))
  if (directoryStatuses.some((status) => status !== 'OK')) {
    return {
      schemaVersion: 'armorbreak.dsh-host-inspection/v1', mode: 'READ_ONLY',
      target: { home: root, profile }, status: 'INCOMPLETE',
      directoryStatuses: ['home', 'profiles', 'profile'].map((name, i) => ({ name, status: directoryStatuses[i] })),
      manifest: { status: 'NOT_INSPECTED', declaredPackages: [] },
      config: { status: 'NOT_INSPECTED', packageMentions: [] },
      observations: ['Profile directory was not safely accessible; no plugin status is inferred.'],
    }
  }

  const manifestData = await readBounded(join(directory, 'package.json'))
  const manifest = { status: manifestData.status, declaredPackages: [] }
  if (manifestData.status === 'OK') {
    try {
      const parsed = JSON.parse(manifestData.content)
      if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('invalid')
      for (const name of PACKAGES) {
        const value = parsed.dependencies?.[name] ?? parsed.optionalDependencies?.[name] ?? parsed.devDependencies?.[name]
        // Version specifiers can be private registry URLs containing credentials.
        if (typeof value === 'string') manifest.declaredPackages.push({ name })
      }
    } catch {
      manifest.status = 'INVALID_JSON'
    }
  }

  const configData = await readBounded(join(directory, 'cordis.patch.yml'))
  const config = { status: configData.status, packageMentions: [] }
  if (configData.status === 'OK') {
    // Mere textual mentions are intentionally not interpreted as active entries.
    for (const name of PACKAGES) {
      if (configData.content.includes(name)) config.packageMentions.push(name)
    }
  }

  const declared = new Set(manifest.declaredPackages.map((pkg) => pkg.name))
  const otherDeclared = [...declared].filter((name) => name !== 'dsh-armorbreak')
  const observations = []
  if (declared.has('dsh-armorbreak') && otherDeclared.length) {
    observations.push('ArmorBreak and Purge package dependencies coexist; inspect actual Cordis IDs and configuration before changing anything.')
  }
  if (manifest.status !== 'OK' || config.status !== 'OK') {
    observations.push('Incomplete profile evidence; do not infer installation or patch status.')
  }
  observations.push('Declared dependencies and text mentions do not prove active plugin registration or successful injection.')

  return {
    schemaVersion: 'armorbreak.dsh-host-inspection/v1', mode: 'READ_ONLY',
    target: { home: root, profile },
    status: manifest.status === 'OK' && config.status === 'OK' ? 'INSPECTED' : 'INCOMPLETE',
    directoryStatuses: ['home', 'profiles', 'profile'].map((name) => ({ name, status: 'OK' })),
    manifest, config, observations,
  }
}
