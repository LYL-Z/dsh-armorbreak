/** Read committed release evidence without following links or trusting path strings. */
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'

export const MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024

function fail(message) {
  const error = new Error(message)
  error.code = 'EVIDENCE_PATH_UNSAFE'
  throw error
}

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino !== 0n && left.ino === right.ino
}

function isWithin(root, candidate) {
  const rel = relative(root, candidate)
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

/**
 * Read a repository-relative regular file from a stable descriptor.
 * `requiredPrefix` keeps callers within a declared evidence subtree.
 */
export function readSafeRepoFile(repoRoot, relativePath, {
  requiredPrefix,
  maxBytes = MAX_EVIDENCE_FILE_BYTES,
} = {}) {
  if (typeof relativePath !== 'string' || !relativePath || relativePath.includes('\\') || relativePath.includes('\0')) {
    fail('evidence path must be a non-empty POSIX relative path')
  }
  const parts = relativePath.split('/')
  if (parts.some((part) => !part || part === '.' || part === '..' || part.includes(':') || /[. ]$/.test(part) || /[\x00-\x1f<>"|?*]/.test(part))) {
    fail(`evidence path contains an unsafe component: ${relativePath}`)
  }
  if (requiredPrefix && !relativePath.startsWith(requiredPrefix)) fail(`evidence path is outside ${requiredPrefix}: ${relativePath}`)
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) fail('evidence byte limit is invalid')

  const root = realpathSync(resolve(repoRoot))
  const absolute = resolve(root, ...parts)
  if (!isWithin(root, absolute)) fail(`evidence path escapes the repository: ${relativePath}`)

  const pathStats = []
  let current = root
  for (let index = 0; index < parts.length; index += 1) {
    current = resolve(current, parts[index])
    let info
    try { info = lstatSync(current, { bigint: true }) } catch (error) {
      if (error?.code === 'ENOENT') throw error
      fail(`could not inspect evidence path component: ${relativePath}`)
    }
    if (info.isSymbolicLink()) fail(`evidence path contains a symlink or junction: ${relativePath}`)
    const isFinal = index === parts.length - 1
    if (!isFinal && !info.isDirectory()) fail(`evidence parent is not a directory: ${relativePath}`)
    if (isFinal && !info.isFile()) fail(`evidence file is not a regular file: ${relativePath}`)
    pathStats.push({ path: current, info })
  }

  let canonical
  try { canonical = realpathSync(absolute) } catch { fail(`evidence path cannot be resolved: ${relativePath}`) }
  if (!samePath(canonical, absolute) || !isWithin(root, canonical)) fail(`evidence path resolves outside its declared location: ${relativePath}`)

  const initial = pathStats.at(-1).info
  if (initial.nlink > 1n) fail(`evidence file has multiple hard links: ${relativePath}`)
  if (initial.size > BigInt(maxBytes)) fail(`evidence file exceeds ${maxBytes} bytes: ${relativePath}`)

  let descriptor
  try {
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)
    descriptor = openSync(absolute, flags)
    const opened = fstatSync(descriptor, { bigint: true })
    if (!opened.isFile() || opened.nlink > 1n || opened.dev !== initial.dev || opened.ino === 0n || opened.ino !== initial.ino) {
      fail(`evidence file identity changed while opening: ${relativePath}`)
    }

    const bufferLimit = Math.min(maxBytes + 1, Number(initial.size) + 1)
    const buffer = Buffer.alloc(Math.max(1, bufferLimit))
    let bytesRead = 0
    while (bytesRead < buffer.length) {
      const count = readSync(descriptor, buffer, bytesRead, buffer.length - bytesRead, bytesRead)
      if (count === 0) break
      bytesRead += count
    }

    for (const prior of pathStats) {
      const latest = lstatSync(prior.path, { bigint: true })
      if (latest.isSymbolicLink() || latest.dev !== prior.info.dev || latest.ino === 0n || latest.ino !== prior.info.ino) {
        fail(`evidence path changed while reading: ${relativePath}`)
      }
    }
    const after = fstatSync(descriptor, { bigint: true })
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs) {
      fail(`evidence file changed while reading: ${relativePath}`)
    }
    if (bytesRead > maxBytes || BigInt(bytesRead) !== opened.size) fail(`evidence file size changed or exceeded its limit: ${relativePath}`)
    return buffer.subarray(0, bytesRead)
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

/**
 * Atomically replace a repository-relative regular output file after checking
 * every parent component. This rejects checked-in symlinks/junctions and
 * avoids following a symlink at the final output name.
 */
export function writeSafeRepoFile(repoRoot, relativePath, value, { requiredPrefix, mode = 0o600 } = {}) {
  if (typeof relativePath !== 'string' || !relativePath || relativePath.includes('\\') || relativePath.includes('\0')) {
    fail('output path must be a non-empty POSIX relative path')
  }
  const parts = relativePath.split('/')
  if (parts.some((part) => !part || part === '.' || part === '..' || part.includes(':') || /[. ]$/.test(part) || /[\x00-\x1f<>"|?*]/.test(part))) {
    fail(`output path contains an unsafe component: ${relativePath}`)
  }
  if (requiredPrefix && !relativePath.startsWith(requiredPrefix)) fail(`output path is outside ${requiredPrefix}: ${relativePath}`)
  const root = realpathSync(resolve(repoRoot))
  const absolute = resolve(root, ...parts)
  if (!isWithin(root, absolute)) fail(`output path escapes the repository: ${relativePath}`)

  const parents = []
  let current = root
  for (const part of parts.slice(0, -1)) {
    current = resolve(current, part)
    const info = lstatSync(current, { bigint: true })
    if (info.isSymbolicLink() || !info.isDirectory()) fail(`output parent is not a real directory: ${relativePath}`)
    parents.push({ path: current, info })
  }
  let original = null
  try {
    original = lstatSync(absolute, { bigint: true })
    if (original.isSymbolicLink() || !original.isFile() || original.nlink > 1n) fail(`output target is not a safe regular file: ${relativePath}`)
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }

  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value))
  const temporary = join(dirname(absolute), `.${basename(absolute)}.${process.pid}.${randomUUID()}.tmp`)
  let descriptor
  let temporaryIdentity
  try {
    const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0)
    descriptor = openSync(temporary, flags, mode)

    // Do not send evidence bytes to the descriptor until the opened temporary
    // file and every path component still resolve to the objects validated
    // above. In particular, a parent junction swapped at open time must be
    // detected before any content is written outside the repository.
    const opened = fstatSync(descriptor, { bigint: true })
    const openedPath = lstatSync(temporary, { bigint: true })
    if (!opened.isFile() || opened.nlink !== 1n || opened.ino === 0n
      || openedPath.isSymbolicLink() || !openedPath.isFile() || openedPath.nlink !== 1n
      || !sameFileIdentity(openedPath, opened)) {
      fail(`output temporary file identity changed while opening: ${relativePath}`)
    }
    temporaryIdentity = { dev: opened.dev, ino: opened.ino }
    for (const prior of parents) {
      const latest = lstatSync(prior.path, { bigint: true })
      if (latest.isSymbolicLink() || !latest.isDirectory() || !sameFileIdentity(latest, prior.info)) {
        fail(`output parent changed before writing: ${relativePath}`)
      }
    }

    let offset = 0
    while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset)
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = undefined

    for (const prior of parents) {
      const latest = lstatSync(prior.path, { bigint: true })
      if (latest.isSymbolicLink() || latest.dev !== prior.info.dev || latest.ino === 0n || latest.ino !== prior.info.ino) {
        fail(`output parent changed while writing: ${relativePath}`)
      }
    }
    let latestTarget = null
    try { latestTarget = lstatSync(absolute, { bigint: true }) } catch (error) { if (error?.code !== 'ENOENT') throw error }
    if (original && (!latestTarget || latestTarget.isSymbolicLink() || latestTarget.dev !== original.dev || latestTarget.ino !== original.ino)) {
      fail(`output target changed while writing: ${relativePath}`)
    }
    if (!original && latestTarget) fail(`output target appeared while writing: ${relativePath}`)

    renameSync(temporary, absolute)
    const written = lstatSync(absolute, { bigint: true })
    if (written.isSymbolicLink() || !written.isFile() || written.nlink !== 1n || written.size !== BigInt(bytes.length)) {
      fail(`output file identity is invalid after writing: ${relativePath}`)
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
    if (temporaryIdentity) {
      try {
        const latestTemporary = lstatSync(temporary, { bigint: true })
        if (!latestTemporary.isSymbolicLink() && latestTemporary.isFile() && latestTemporary.nlink === 1n
          && sameFileIdentity(latestTemporary, temporaryIdentity)) unlinkSync(temporary)
      } catch (error) { if (error?.code !== 'ENOENT') throw error }
    }
  }
}

