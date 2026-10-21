/**
 * AB2-M2-14 offline tier manifests: mini / standard / full.
 *
 * Deterministic manifests over already-collected files; this module never
 * downloads. Installation of these manifests is handled by M2-11, so these are
 * size/capability contracts, not opaque archives.
 */
import { createHash } from 'node:crypto'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

function manifestFor(tier, files, capabilities) {
  const entries = files.map((file) => ({ path: String(file.path), sha256: String(file.sha256 ?? sha256(String(file.content ?? ''))), bytes: Number(file.bytes ?? Buffer.byteLength(String(file.content ?? ''))) })).sort((a, b) => a.path.localeCompare(b.path))
  const aggregate = sha256(JSON.stringify(entries))
  return {
    schemaVersion: 'armorbreak.offline-pack/v1',
    tier,
    entries,
    fileCount: entries.length,
    totalBytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
    capabilities: [...new Set(capabilities)].sort(),
    aggregateSha256: aggregate,
  }
}

export function buildOfflinePacks(input = {}) {
  const core = Array.isArray(input.core) ? input.core : []
  const extension = Array.isArray(input.extension) ? input.extension : []
  const cloud = Array.isArray(input.cloud) ? input.cloud : []
  const caps = input.capabilities ?? {}
  const mini = manifestFor('mini', core, caps.core ?? [])
  const standard = manifestFor('standard', [...core, ...extension], [...(caps.core ?? []), ...(caps.extension ?? [])])
  const full = manifestFor('full', [...core, ...extension, ...cloud], [...(caps.core ?? []), ...(caps.extension ?? []), ...(caps.cloud ?? [])])
  return { schemaVersion: 'armorbreak.offline-packs/v1', packs: { mini, standard, full } }
}

export function comparePacks(packs) {
  const tiers = ['mini', 'standard', 'full']
  return tiers.map((tier, index) => ({
    tier,
    totalBytes: packs[tier].totalBytes,
    fileCount: packs[tier].fileCount,
    capabilities: packs[tier].capabilities.length,
    deltaBytesFromPrevious: index === 0 ? 0 : packs[tier].totalBytes - packs[tiers[index - 1]].totalBytes,
    deltaCapabilitiesFromPrevious: index === 0 ? 0 : packs[tier].capabilities.length - packs[tiers[index - 1]].capabilities.length,
  }))
}

/**
 * Materialize one tier under root/<tier>; verify every supplied file hash and
 * clean up on failure. Installation/removal is metadata + file copy only.
 */
export async function installOfflinePack({ pack, root, files }) {
  const { mkdir, writeFile, rm, readFile } = await import('node:fs/promises')
  const { join } = await import('node:path')
  const dir = join(root, pack.tier)
  await rm(dir, { recursive: true, force: true })
  await mkdir(dir, { recursive: true })
  try {
    for (const entry of pack.entries) {
      const source = files.find((file) => file.path === entry.path)
      if (!source) throw new Error('missing pack file: ' + entry.path)
      const content = Buffer.isBuffer(source.content) ? source.content : Buffer.from(source.content)
      if (sha256(content) !== entry.sha256) throw new Error('pack file hash mismatch: ' + entry.path)
      const target = join(dir, entry.path)
      await mkdir(join(target, '..'), { recursive: true })
      await writeFile(target, content)
    }
    await writeFile(join(dir, 'manifest.json'), JSON.stringify(pack, null, 2))
    return { installed: true, tier: pack.tier, dir, files: pack.entries.length }
  } catch (error) {
    await rm(dir, { recursive: true, force: true })
    throw error
  }
}

export async function uninstallOfflinePack({ root, tier }) {
  const { rm } = await import('node:fs/promises')
  const { join } = await import('node:path')
  await rm(join(root, tier), { recursive: true, force: true })
  return { removed: true, tier }
}
