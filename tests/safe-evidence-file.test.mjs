import assert from 'node:assert/strict'
import childProcess from 'node:child_process'
import fs, { linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { Worker } from 'node:worker_threads'

import { readSafeRepoFile, writeSafeRepoFile } from '../lib/release/safeEvidenceFile.js'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'abm-safe-evidence-'))
  mkdirSync(join(root, 'docs/v2/acceptance'), { recursive: true })
  return root
}

test('safe evidence reads stable regular files and atomically replaces regular outputs', () => {
  const root = fixture()
  try {
    const path = 'docs/v2/acceptance/result.json'
    writeFileSync(join(root, path), '{"before":true}')
    writeSafeRepoFile(root, path, '{"after":true}', { requiredPrefix: 'docs/v2/acceptance/' })
    assert.equal(readSafeRepoFile(root, path, { requiredPrefix: 'docs/v2/acceptance/' }).toString(), '{"after":true}')
    assert.equal(readFileSync(join(root, path), 'utf8'), '{"after":true}')
    assert.equal(lstatSync(join(root, path)).nlink, 1)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('safe evidence rejects hard links and symlink or junction output paths', (t) => {
  const root = fixture()
  try {
    const shared = join(root, 'shared.json')
    writeFileSync(shared, '{"shared":true}')
    linkSync(shared, join(root, 'docs/v2/acceptance/hardlinked.json'))
    assert.throws(() => readSafeRepoFile(root, 'docs/v2/acceptance/hardlinked.json'), /multiple hard links/)

    const outside = join(root, 'outside')
    mkdirSync(outside)
    writeFileSync(join(outside, 'result.json'), 'outside')
    rmSync(join(root, 'docs/v2/acceptance'), { recursive: true, force: true })
    try { symlinkSync(outside, join(root, 'docs/v2/acceptance'), process.platform === 'win32' ? 'junction' : 'dir') } catch (error) {
      t.skip(`isolated directory-link creation is unavailable: ${String(error?.code ?? error)}`)
      return
    }
    assert.throws(() => readSafeRepoFile(root, 'docs/v2/acceptance/result.json'), /symlink or junction/)
    assert.throws(() => writeSafeRepoFile(root, 'docs/v2/acceptance/result.json', 'blocked'), /real directory/)
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('safe evidence writes no bytes when a parent junction changes during temporary-file open', () => {
  const root = fixture()
  const acceptance = join(root, 'docs/v2/acceptance')
  const held = join(root, 'docs/v2/acceptance-held')
  const outside = join(root, 'outside')
  mkdirSync(outside)

  let swapped = false
  let writeCalls = 0
  const originalOpen = fs.openSync
  const originalWrite = fs.writeSync
  const originalSpawnSync = childProcess.spawnSync
  const swapParent = () => {
    renameSync(acceptance, held)
    symlinkSync(outside, acceptance, process.platform === 'win32' ? 'junction' : 'dir')
    swapped = true
  }
  if (process.platform === 'win32') {
    childProcess.spawnSync = function (command, args, options) {
      if (!swapped && args?.some((argument) => String(argument).endsWith('safe-evidence-write-windows.ps1'))) swapParent()
      return originalSpawnSync.call(this, command, args, options)
    }
  } else {
    fs.openSync = (file, ...args) => {
      if (!swapped && String(file).endsWith('.tmp')) swapParent()
      return originalOpen(file, ...args)
    }
  }
  fs.writeSync = (...args) => {
    writeCalls += 1
    return originalWrite(...args)
  }
  syncBuiltinESMExports()

  try {
    assert.throws(
      () => writeSafeRepoFile(root, 'docs/v2/acceptance/release-gates.json', 'SYNTHETIC-OUTSIDE-CAPTURE'),
      (error) => error.code === 'EVIDENCE_PATH_UNSAFE',
    )
    assert.equal(swapped, true)
    if (process.platform !== 'win32') assert.equal(writeCalls, 0, 'the helper must reject before writing bytes through a swapped parent')
    assert.deepEqual(readdirSync(outside), [], 'no temporary or final evidence file should remain outside the repository')
  } finally {
    fs.openSync = originalOpen
    fs.writeSync = originalWrite
    childProcess.spawnSync = originalSpawnSync
    syncBuiltinESMExports()
    if (swapped) {
      rmSync(acceptance, { recursive: true, force: true })
      renameSync(held, acceptance)
    }
    rmSync(root, { recursive: true, force: true })
  }
})

test('safe evidence replacement does not follow a parent swap at the final replace boundary', () => {
  const root = fixture()
  const acceptance = join(root, 'docs/v2/acceptance')
  const held = join(root, 'docs/v2/acceptance-held')
  const outside = join(root, 'outside')
  const outsideTarget = join(outside, 'result.json')
  mkdirSync(outside)
  writeFileSync(outsideTarget, 'SYNTHETIC-OUTSIDE-SENTINEL')

  let swapped = false
  let attackTempPath = null
  const originalRename = fs.renameSync
  const originalSpawnSync = childProcess.spawnSync
  const swapParent = () => {
    renameSync(acceptance, held)
    symlinkSync(outside, acceptance, process.platform === 'win32' ? 'junction' : 'dir')
    swapped = true
  }
  if (process.platform === 'win32') {
    childProcess.spawnSync = function (command, args, options) {
      if (!swapped && args?.some((argument) => String(argument).endsWith('safe-evidence-write-windows.ps1'))) swapParent()
      return originalSpawnSync.call(this, command, args, options)
    }
  } else {
    fs.renameSync = function (source, destination) {
      if (!swapped && String(destination).endsWith('/result.json')) {
        swapParent()
        attackTempPath = join(outside, String(source).split('/').at(-1))
        writeFileSync(attackTempPath, 'ATTACK')
      }
      return originalRename(source, destination)
    }
  }
  syncBuiltinESMExports()

  try {
    assert.throws(
      () => writeSafeRepoFile(root, 'docs/v2/acceptance/result.json', 'BENIGN', { requiredPrefix: 'docs/v2/acceptance/' }),
      (error) => error.code === 'EVIDENCE_PATH_UNSAFE',
    )
    assert.equal(swapped, true)
    assert.equal(readFileSync(outsideTarget, 'utf8'), 'SYNTHETIC-OUTSIDE-SENTINEL')
    if (process.platform === 'linux') {
      const retainedOutput = readdirSync(held).find((name) => name === 'result.json' || name.endsWith('.tmp'))
      assert.ok(retainedOutput, 'the anchored operation may complete in the original directory or leave its temp there')
      assert.notEqual(readFileSync(join(held, retainedOutput), 'utf8'), 'ATTACK')
    }
  } finally {
    fs.renameSync = originalRename
    childProcess.spawnSync = originalSpawnSync
    syncBuiltinESMExports()
    if (attackTempPath) rmSync(attackTempPath, { force: true })
    rmSync(acceptance, { recursive: true, force: true })
    renameSync(held, acceptance)
    rmSync(root, { recursive: true, force: true })
  }
})

test('safe evidence parent handle blocks or contains a concurrent rename during replacement', async () => {
  const root = fixture()
  const acceptance = join(root, 'docs/v2/acceptance')
  const held = join(root, 'docs/v2/acceptance-held')
  const outside = join(root, 'outside')
  const outsideTarget = join(outside, 'result.json')
  mkdirSync(outside)
  writeFileSync(outsideTarget, 'SYNTHETIC-OUTSIDE-SENTINEL')

  let attackAttempted = false
  let moved = false
  let linked = false
  let swapError = null
  const trySwap = () => {
    if (attackAttempted) return
    const temporary = readdirSync(acceptance).find((name) => name.endsWith('.tmp'))
    if (!temporary) return
    attackAttempted = true
    try {
      renameSync(acceptance, held)
      moved = true
      symlinkSync(outside, acceptance, process.platform === 'win32' ? 'junction' : 'dir')
      linked = true
    } catch (error) { swapError = error }
  }

  const watcher = fs.watch(acceptance, trySwap)
  const poll = setInterval(trySwap, 1)
  const worker = new Worker(new URL('./safe-evidence-write-worker.mjs', import.meta.url), {
    workerData: { root, relativePath: 'docs/v2/acceptance/result.json', bytes: 16 * 1024 * 1024 },
  })
  let result
  try {
    result = await new Promise((resolve, reject) => {
      worker.once('message', resolve)
      worker.once('error', reject)
      worker.once('exit', (code) => { if (code !== 0) reject(new Error(`evidence writer worker exited ${code}`)) })
    })
    assert.equal(attackAttempted, true, 'the concurrent rename attempt must occur after the temp file is opened')
    assert.equal(readFileSync(outsideTarget, 'utf8'), 'SYNTHETIC-OUTSIDE-SENTINEL')
    if (moved) {
      const retained = readdirSync(held)
      assert.ok(!retained.includes('result.json'), 'a swapped parent must not receive the final output name')
      assert.ok(retained.every((name) => name.endsWith('.tmp')), `unexpected files remain after refused write: ${retained.join(', ')}`)
      for (const name of retained) assert.notEqual(readFileSync(join(held, name), 'utf8'), 'ATTACK')
      assert.ok(['written', 'refused'].includes(result.status))
    } else {
      assert.ok(swapError, 'a failed rename attempt must report the platform refusal')
      assert.ok(['EPERM', 'EACCES', 'EBUSY'].includes(swapError.code), `unexpected rename refusal: ${swapError.code}`)
      assert.ok(['written', 'refused'].includes(result.status))
    }
  } finally {
    clearInterval(poll)
    watcher.close()
    await worker.terminate().catch(() => {})
    if (linked) rmSync(acceptance, { recursive: true, force: true })
    if (moved) renameSync(held, acceptance)
    rmSync(root, { recursive: true, force: true })
  }
})
