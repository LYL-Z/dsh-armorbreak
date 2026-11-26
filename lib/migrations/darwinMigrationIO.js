import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { lstat } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const helper = fileURLToPath(new URL('./safe-migration-posix.py', import.meta.url))
const limit = 64 * 1024 * 1024
const identity = (info) => [String(info.dev), String(info.ino)]
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
let available

export function darwinMigrationAvailable() {
  available ??= spawnSync('python3', ['-I', helper, '--probe'], { timeout: 5000 }).status === 0
  return available
}

function invoke(binding, operation, bytes = Buffer.alloc(0), beforeSha256 = null) {
  if (bytes.length > limit) throw new Error('migration data exceeds the Darwin file size limit')
  const header = Buffer.from(JSON.stringify({ ...binding, operation, beforeSha256, length: bytes.length }) + '\n')
  return new Promise((resolvePromise, reject) => {
    const child = spawn('python3', ['-I', helper], { stdio: ['pipe', 'pipe', 'pipe'] })
    const output = []
    let size = 0
    let stderr = ''
    const timeout = setTimeout(() => child.kill('SIGKILL'), 60000)
    child.stdout.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) child.kill('SIGKILL')
      else output.push(chunk)
    })
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr = (stderr + chunk).slice(-2048) })
    child.stdin.on('error', () => { /* child close reports the actual refusal */ })
    child.once('error', (error) => {
      clearTimeout(timeout)
      reject(new Error('Darwin migration helper could not start', { cause: error }))
    })
    child.once('close', (code, signal) => {
      clearTimeout(timeout)
      if (code === 0 && size <= limit) return resolvePromise(Buffer.concat(output, size))
      reject(Object.assign(new Error(`Darwin migration ${operation} refused: ${stderr.trim() || signal || code}`), {
        code: 'MIGRATION_POSIX_REFUSED',
      }))
    })
    child.stdin.write(header)
    child.stdin.end(bytes)
  })
}

async function bind(root, file, { create = false } = {}) {
  const absolute = resolve(file)
  const path = relative(root, absolute)
  if (!path || isAbsolute(path) || path.split('/').includes('..')) throw new Error('migration path is outside the workspace')
  const parents = []
  let current = '/'
  for (const part of ['', ...dirname(absolute).split('/').filter(Boolean)]) {
    current = join(current, part)
    const info = await lstat(current, { bigint: true })
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('migration directory contains a symlink or changed identity')
    parents.push(identity(info))
  }
  let target = null
  try {
    const info = await lstat(absolute, { bigint: true })
    if (create || !info.isFile() || info.nlink !== 1n) throw new Error('migration file is not a single-link regular file or already exists')
    target = identity(info)
  } catch (error) {
    if (!create || error.code !== 'ENOENT') throw error
  }
  return { root, path, parents, target }
}

export async function captureDarwinFile(root, file) {
  const binding = await bind(root, file)
  const bytes = await invoke(binding, 'read')
  return { binding, bytes, sha256: digest(bytes) }
}

export async function readBoundDarwinFile(snapshot) {
  return invoke(snapshot.binding, 'read')
}

export async function replaceDarwinFile(snapshot, bytes) {
  await invoke(snapshot.binding, 'replace', Buffer.from(bytes), snapshot.sha256)
}

export async function truncateDarwinFile(snapshot) {
  await invoke(snapshot.binding, 'truncate', undefined, snapshot.sha256)
  snapshot.sha256 = digest(Buffer.alloc(0))
}

export async function createDarwinFile(root, file, bytes) {
  const binding = await bind(root, file, { create: true })
  await invoke(binding, 'replace', Buffer.from(bytes))
}

export async function createDarwinDirectory(root, path) {
  await invoke(await bind(root, path, { create: true }), 'mkdir')
}
