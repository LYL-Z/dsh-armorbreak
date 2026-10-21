/**
 * AB2-M1-09 streaming content-addressed store prototype.
 *
 * Large artifacts are hashed and copied with a bounded read stream; the host
 * never loads the whole file into memory. Objects are immutable and deduplicated
 * by SHA-256, with temp-file + rename atomic publication.
 */
import { createHash } from 'node:crypto'
import { createReadStream, createWriteStream } from 'node:fs'
import { mkdir, rename, stat } from 'node:fs/promises'
import { join } from 'node:path'

/**
 * @param {string} filePath
 * @param {{highWaterMark?: number}} [options]
 * @returns {Promise<{sha256:string, bytes:number}>}
 */
export async function hashFileStream(filePath, options = {}) {
  const hash = createHash('sha256')
  let bytes = 0
  await new Promise((resolve, reject) => {
    const stream = createReadStream(filePath, { highWaterMark: Math.max(64 * 1024, Math.min(Number(options.highWaterMark ?? 1024 * 1024), 8 * 1024 * 1024)) })
    stream.on('data', (chunk) => { bytes += chunk.length; hash.update(chunk) })
    stream.on('error', reject)
    stream.on('end', resolve)
  })
  return { sha256: hash.digest('hex'), bytes }
}

/**
 * Copy a file into the CAS while hashing it. Returns the immutable object path.
 * @param {{sourcePath:string, storeRoot:string, expectedSha256?:string|null}} input
 */
export async function importContent(input) {
  const objects = join(input.storeRoot, 'objects')
  await mkdir(objects, { recursive: true })
  const hash = createHash('sha256')
  let bytes = 0
  const temp = join(objects, `.incoming-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`)
  await new Promise((resolve, reject) => {
    const reader = createReadStream(input.sourcePath, { highWaterMark: 1024 * 1024 })
    const writer = createWriteStream(temp, { flags: 'wx' })
    reader.on('data', (chunk) => { bytes += chunk.length; hash.update(chunk) })
    reader.on('error', reject)
    writer.on('error', reject)
    writer.on('finish', resolve)
    reader.pipe(writer)
  })
  const sha256 = hash.digest('hex')
  if (input.expectedSha256 && input.expectedSha256 !== sha256) {
    const { unlink } = await import('node:fs/promises')
    await unlink(temp).catch(() => {})
    throw new Error(`content hash mismatch: expected ${input.expectedSha256}, got ${sha256}`)
  }
  const destination = join(objects, sha256)
  try {
    const existing = await stat(destination)
    if (existing.isFile()) {
      const { unlink } = await import('node:fs/promises')
      await unlink(temp).catch(() => {})
      return { sha256, bytes, path: destination, deduplicated: true }
    }
  } catch {
    /* not present */
  }
  await rename(temp, destination)
  return { sha256, bytes, path: destination, deduplicated: false }
}
