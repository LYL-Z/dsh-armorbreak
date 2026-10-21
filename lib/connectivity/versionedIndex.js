/**
 * AB2-M2-04 versioned CAS index with atomic active pointer and rollback.
 * Signature fields are accepted but not cryptographically verified yet (M2-10).
 */
import { createHash, sign, verify } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, readFile, readdir, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const sha256 = (value) => createHash('sha256').update(value).digest('hex')

async function atomicWrite(file, content) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, content)
  await rename(tmp, file)
}

export class VersionedIndex {
  /** @param {{root: string}} input */
  constructor(input) {
    this.root = input.root
    this.versionsRoot = join(this.root, 'versions')
    this.pointer = join(this.root, 'active.json')
    this.previousPointer = join(this.root, 'previous.json')
  }

  async publish(entries, options = {}) {
    const body = JSON.stringify({ schemaVersion: 'armorbreak.index/v1', generatedAt: new Date().toISOString(), entries })
    const hash = sha256(body)
    const versionDir = join(this.versionsRoot, hash)
    await mkdir(versionDir, { recursive: true })
    await atomicWrite(join(versionDir, 'index.json'), body)
    const signature = options.signingKey ? { alg: 'ed25519', keyId: String(options.keyId ?? 'local'), signature: sign(null, Buffer.from(hash), options.signingKey).toString('base64') } : null
    const descriptor = { hash, path: join(versionDir, 'index.json'), bytes: Buffer.byteLength(body), signature, publishedAt: new Date().toISOString() }
    if (existsSync(this.pointer)) await writeFile(this.previousPointer, await readFile(this.pointer))
    await atomicWrite(this.pointer, `${JSON.stringify(descriptor, null, 2)}\n`)
    return descriptor
  }

  async read(options = {}) {
    const pointer = JSON.parse(await readFile(this.pointer, 'utf8'))
    const body = await readFile(pointer.path)
    if (sha256(body) !== pointer.hash) throw new Error('active index hash mismatch; refusing to load')
    if (options.requireSignature && !pointer.signature) throw new Error('active index has no signature; refusing to load')
    if (pointer.signature && options.publicKey) {
      const ok = verify(null, Buffer.from(pointer.hash), options.publicKey, Buffer.from(pointer.signature.signature, 'base64'))
      if (!ok) throw new Error('active index signature verification failed')
    }
    return { descriptor: pointer, index: JSON.parse(body.toString('utf8')) }
  }

  async rollback() {
    const previous = await readFile(this.previousPointer, 'utf8')
    await atomicWrite(this.pointer, previous)
    return JSON.parse(previous)
  }

  async listVersions() {
    try {
      return await readdir(this.versionsRoot)
    } catch {
      return []
    }
  }
}
