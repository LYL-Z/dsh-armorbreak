/** Cross-process lock for read-tail-compute-append hash-chain updates. */
import { randomUUID } from 'node:crypto'
import { link, mkdir, readFile, unlink, writeFile } from 'node:fs/promises'
import { hostname } from 'node:os'
import { dirname, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

const DEFAULT_TIMEOUT_MS = 30_000

function fail(code, message, cause) {
  const error = new Error(message, cause ? { cause } : undefined)
  error.code = code
  return error
}

/**
 * Run a critical section under an exclusive same-directory hard-link lock.
 * Lock contention times out without running the callback. A leftover lock
 * after process termination also fails closed; recovery must verify the owner
 * is gone before removing that lock file.
 *
 * @template T
 * @param {string} file
 * @param {() => Promise<T>} task
 * @param {{timeoutMs?: number}} [options]
 * @returns {Promise<T>}
 */
export async function withAppendFileLock(file, task, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (typeof task !== 'function') throw fail('APPEND_LOCK_INVALID', 'append lock task must be a function')
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) throw fail('APPEND_LOCK_INVALID', 'append lock timeout must be a positive number')

  const target = resolve(file)
  const lockPath = `${target}.append.lock`
  const token = randomUUID()
  const tempPath = `${lockPath}.${process.pid}.${token}.tmp`
  await mkdir(dirname(target), { recursive: true })
  await writeFile(tempPath, JSON.stringify({ pid: process.pid, host: hostname(), token, createdAt: new Date().toISOString() }), { flag: 'wx', mode: 0o600 })

  let acquired = false
  let operationError = null
  try {
    const startedAt = Date.now()
    let attempt = 0
    while (!acquired) {
      try {
        // Linking a fully written owner record makes lock creation atomic and
        // prevents contenders from observing a partially written lock file.
        await link(tempPath, lockPath)
        acquired = true
      } catch (error) {
        if (error?.code !== 'EEXIST') {
          throw fail('APPEND_LOCK_UNAVAILABLE', `could not acquire append lock for ${target}`, error)
        }
        if (Date.now() - startedAt >= timeoutMs) {
          throw fail('APPEND_LOCK_TIMEOUT', `timed out waiting for append lock for ${target}`)
        }
        attempt += 1
        await delay(Math.min(25, 5 + Math.floor(attempt / 3) * 5))
      }
    }
    return await task()
  } catch (error) {
    operationError = error
    throw error
  } finally {
    let cleanupError = null
    if (acquired) {
      let current
      try {
        current = JSON.parse(await readFile(lockPath, 'utf8'))
      } catch (error) {
        cleanupError = fail('APPEND_LOCK_RELEASE_FAILED', `could not verify append lock ownership for ${target}`, error)
      }
      if (!cleanupError && (!current || typeof current !== 'object' || current.token !== token)) {
        cleanupError = fail('APPEND_LOCK_OWNERSHIP_LOST', `append lock ownership changed for ${target}`)
      }
      if (!cleanupError) {
        try {
          await unlink(lockPath)
        } catch (error) {
          cleanupError = fail('APPEND_LOCK_RELEASE_FAILED', `could not safely release append lock for ${target}`, error)
        }
      }
    }
    try {
      await unlink(tempPath)
    } catch (error) {
      if (error?.code !== 'ENOENT' && !cleanupError) cleanupError = fail('APPEND_LOCK_CLEANUP_FAILED', `could not remove append lock temporary file for ${target}`, error)
    }
    if (cleanupError) {
      if (operationError && typeof operationError === 'object') operationError.appendLockCleanupError = cleanupError
      else throw cleanupError
    }
  }
}
