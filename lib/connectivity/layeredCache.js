/**
 * AB2-M2-03 layered cache + staging.
 *
 * core / extension / cloud layers each have an atomically switched active
 * pointer. Staging is written under a separate path; activation verifies every
 * file hash before the pointer moves. Core resolves to the previous version if a
 * new activation fails, so an interrupted download cannot break offline work.
 */
import { createHash } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const LAYERS = ['core', 'extension', 'cloud']
const sha256 = (value) => createHash('sha256').update(value).digest('hex')

async function atomicWrite(file, content) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, content)
  await rename(tmp, file)
}

async function hashTree(files) {
  const names = Object.keys(files).sort()
  const entries = names.map((name) => ({ name, sha256: sha256(files[name]), bytes: files[name].length }))
  return { entries, manifestSha256: sha256(JSON.stringify(entries)) }
}

export class LayeredCache {
  /** @param {{root: string}} input */
  constructor(input) {
    this.root = input.root
    this.layersRoot = join(this.root, 'layers')
    this.stagingRoot = join(this.root, 'staging')
  }

  layerPath(layer) {
    if (!LAYERS.includes(layer)) throw new Error(`unknown cache layer: ${layer}`)
    return join(this.layersRoot, layer)
  }

  activePointer(layer) {
    return join(this.layerPath(layer), 'active.json')
  }

  /** @param {{layer:string, version:string, files:Record<string,Buffer|string>}} input */
  async stage(input) {
    if (!LAYERS.includes(input.layer)) throw new Error(`unknown cache layer: ${input.layer}`)
    const version = String(input.version ?? '').trim()
    if (!version) throw new Error('stage needs a version')
    const files = {}
    for (const [name, value] of Object.entries(input.files ?? {})) files[name] = Buffer.isBuffer(value) ? value : Buffer.from(String(value))
    const tree = await hashTree(files)
    const stagingId = `${input.layer}-${version}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`
    const dir = join(this.stagingRoot, stagingId)
    await mkdir(dir, { recursive: true })
    for (const [name, content] of Object.entries(files)) await writeFile(join(dir, name), content)
    const manifest = { schemaVersion: 'armorbreak.cache-staging/v1', layer: input.layer, version, stagingId, ...tree }
    await writeFile(join(dir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`)
    return { stagingId, dir, manifest }
  }

  async activate({ layer, stagingId, expectedManifestSha256 = null }) {
    if (!LAYERS.includes(layer)) throw new Error(`unknown cache layer: ${layer}`)
    const dir = join(this.stagingRoot, stagingId)
    const manifest = JSON.parse(await readFile(join(dir, 'manifest.json'), 'utf8'))
    if (manifest.layer !== layer) throw new Error('staging layer mismatch')
    if (expectedManifestSha256 && manifest.manifestSha256 !== expectedManifestSha256) throw new Error('staging manifest hash mismatch')
    for (const entry of manifest.entries) {
      const content = await readFile(join(dir, entry.name))
      if (sha256(content) !== entry.sha256) throw new Error(`staged file hash mismatch: ${entry.name}`)
    }
    await mkdir(this.layerPath(layer), { recursive: true })
    const previous = existsSync(this.activePointer(layer)) ? JSON.parse(await readFile(this.activePointer(layer), 'utf8')) : null
    if (previous) await writeFile(join(this.layerPath(layer), 'previous.json'), `${JSON.stringify(previous, null, 2)}\n`)
    const pointer = { ...manifest, sourceDir: dir, activatedAt: new Date().toISOString() }
    await atomicWrite(this.activePointer(layer), `${JSON.stringify(pointer, null, 2)}\n`)
    return pointer
  }

  async active(layer) {
    if (!LAYERS.includes(layer)) throw new Error(`unknown cache layer: ${layer}`)
    try {
      const pointer = JSON.parse(await readFile(this.activePointer(layer), 'utf8'))
      for (const entry of pointer.entries) {
        const content = await readFile(join(pointer.sourceDir, entry.name))
        if (sha256(content) !== entry.sha256) throw new Error(`active file hash mismatch: ${entry.name}`)
      }
      return pointer
    } catch {
      return null
    }
  }

  async rollback(layer) {
    if (!LAYERS.includes(layer)) throw new Error(`unknown cache layer: ${layer}`)
    const previous = JSON.parse(await readFile(join(this.layerPath(layer), 'previous.json'), 'utf8'))
    await atomicWrite(this.activePointer(layer), `${JSON.stringify(previous, null, 2)}\n`)
    return previous
  }

  async cleanStaging() {
    if (!existsSync(this.stagingRoot)) return { removed: 0 }
    const entries = await readdir(this.stagingRoot)
    let removed = 0
    for (const entry of entries) {
      await rm(join(this.stagingRoot, entry), { recursive: true, force: true })
      removed += 1
    }
    return { removed }
  }
}
