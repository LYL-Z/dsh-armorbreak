import assert from 'node:assert/strict'
import childProcess from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import fs, { linkSync, lstatSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import test from 'node:test'
import { Worker } from 'node:worker_threads'
import { makeTestTempDirectorySync } from './helpers/temporary.js'

import { readSafeRepoFile, writeSafeRepoFile } from '../lib/release/safeEvidenceFile.js'

function fixture() {
  const root = makeTestTempDirectorySync('abm-safe-evidence-')
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
  if (['win32', 'darwin'].includes(process.platform)) {
    childProcess.spawnSync = function (command, args, options) {
      if (!swapped && args?.some((argument) => String(argument).endsWith(process.platform === 'darwin' ? 'safe-evidence-write-posix.py' : 'safe-evidence-write-windows.ps1'))) swapParent()
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
  if (['win32', 'darwin'].includes(process.platform)) {
    childProcess.spawnSync = function (command, args, options) {
      if (!swapped && args?.some((argument) => String(argument).endsWith(process.platform === 'darwin' ? 'safe-evidence-write-posix.py' : 'safe-evidence-write-windows.ps1'))) swapParent()
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

test('native evidence writer distinguishes helper timeout, startup failure, termination, refusal and invalid response', {
  skip: !['win32', 'darwin'].includes(process.platform),
}, () => {
  const root = fixture()
  const originalSpawnSync = childProcess.spawnSync
  const cases = [
    [{ error: { code: 'ETIMEDOUT' } }, /helper timed out/],
    [{ error: { code: 'ENOENT' } }, /helper could not run \(ENOENT\)/],
    [{ status: null, signal: 'SIGTERM' }, /helper exited on signal SIGTERM/],
    [{ status: 1 }, /helper refused the write/],
    [{ status: 0, stdout: 'unexpected response' }, /helper did not confirm the write/],
  ]
  try {
    for (const [response, diagnostic] of cases) {
      childProcess.spawnSync = () => response
      syncBuiltinESMExports()
      assert.throws(() => writeSafeRepoFile(root, 'docs/v2/acceptance/result.json', 'evidence'), (error) => {
        assert.equal(error.code, 'EVIDENCE_PATH_UNSAFE')
        assert.match(error.message, diagnostic)
        return true
      })
      assert.deepEqual(readdirSync(join(root, 'docs/v2/acceptance')), [])
    }
  } finally {
    childProcess.spawnSync = originalSpawnSync
    syncBuiltinESMExports()
    rmSync(root, { recursive: true, force: true })
  }
})

async function listenForNativeCheckpoint(token, notify) {
  const sockets = new Set()
  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on('error', () => socket.destroy())
    socket.on('close', () => sockets.delete(socket))
    socket.setTimeout(15000, () => socket.destroy())
    socket.setEncoding('utf8')

    let notice = ''
    socket.on('data', (chunk) => {
      notice += chunk
      if (notice.length > 512) return socket.destroy()
      if (!notice.endsWith('\n')) return
      if (!notice.startsWith(`${token} `)) return socket.destroy()
      notify({ status: 'opened', temporaryName: notice.slice(token.length + 1, -1), release: () => socket.end('1') })
    })
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  return {
    port: server.address().port,
    close: () => {
      for (const socket of sockets) socket.destroy()
      return new Promise((resolve) => server.close(resolve))
    },
  }
}

test('darwin evidence helper finishes a declared payload while stdin stays open', async () => {
  const helper = fileURLToPath(new URL('../lib/release/safe-evidence-write-posix.py', import.meta.url))
  const python = process.platform === 'win32' ? 'python' : 'python3'
  const header = Buffer.from(JSON.stringify({
    root: '/tmp/armorbreak-evidence-root',
    relativePath: 'docs/v2/acceptance/result.json',
    mode: 0o644,
    length: 4,
    directories: [['1', '1'], ['1', '1'], ['1', '1'], ['1', '1']],
    original: null,
  }) + '\n')
  const child = spawn(python, ['-I', helper], { stdio: ['pipe', 'pipe', 'pipe'] })
  const finished = once(child, 'exit')
  child.stdin.write(Buffer.concat([header, Buffer.from('test')]))
  const exit = await Promise.race([
    finished,
    new Promise((_, reject) => setTimeout(() => reject(new Error('helper blocked while stdin remained open')), 2000)),
  ])
  child.kill()
  assert.notEqual(exit[0], null)
  if (process.platform !== 'win32') assert.notEqual(exit[0], 0)
})

test('safe evidence parent handle blocks or contains a concurrent rename during replacement', { timeout: 75000 }, async () => {
  const root = fixture()
  const acceptance = join(root, 'docs/v2/acceptance')
  const held = join(root, 'docs/v2/acceptance-held')
  const outside = join(root, 'outside')
  const outsideTarget = join(outside, 'result.json')
  mkdirSync(outside)
  writeFileSync(outsideTarget, 'SYNTHETIC-OUTSIDE-SENTINEL')

  let moved = false
  let linked = false
  let swapError = null
  let notifyOpened
  const opened = new Promise((resolve) => { notifyOpened = resolve })
  let listener
  let worker
  const acknowledgement = new Int32Array(new SharedArrayBuffer(4))
  const releaseWorker = () => {
    Atomics.store(acknowledgement, 0, 1)
    Atomics.notify(acknowledgement, 0)
  }

  try {
    let nativeCheckpoint
    if (['win32', 'darwin'].includes(process.platform)) {
      const token = randomUUID()
      listener = await listenForNativeCheckpoint(token, notifyOpened)
      nativeCheckpoint = { port: listener.port, token }
    }
    worker = new Worker(new URL('./safe-evidence-write-worker.mjs', import.meta.url), {
      workerData: {
        root, relativePath: 'docs/v2/acceptance/result.json', bytes: 16 * 1024 * 1024,
        nativeCheckpoint, acknowledgement: acknowledgement.buffer,
      },
    })
    const finished = new Promise((resolve, reject) => {
      worker.on('message', (event) => {
        if (event.status === 'opened') notifyOpened({ ...event, release: releaseWorker })
        else resolve(event)
      })
      worker.once('error', reject)
      worker.once('exit', (code) => reject(new Error(`evidence writer worker exited ${code} without a result`)))
    })
    const phase = await Promise.race([opened, finished])
    const phaseDiagnostic = phase.helperCheckpointFailed ? 'checkpoint handshake failed' : phase.message ?? phase.status
    assert.equal(phase.status, 'opened', `writer ended before the temporary-file checkpoint (${phaseDiagnostic})`)
    assert.match(phase.temporaryName, /^\.[^/\\]+\.tmp$/)
    assert.ok(readdirSync(acceptance).includes(phase.temporaryName), 'the temporary file must exist when the concurrent rename attempt starts')
    try {
      renameSync(acceptance, held)
      moved = true
      symlinkSync(outside, acceptance, process.platform === 'win32' ? 'junction' : 'dir')
      linked = true
    } catch (error) { swapError = error }
    phase.release()
    const result = await finished
    assert.ok(!result.helperCheckpointFailed, `test checkpoint failed (${result.message})`)
    if (result.status === 'refused') {
      assert.equal(result.code, 'EVIDENCE_PATH_UNSAFE')
      assert.match(result.message, nativeCheckpoint ? /helper refused the write/ : /output parent/)
    }
    assert.equal(readFileSync(outsideTarget, 'utf8'), 'SYNTHETIC-OUTSIDE-SENTINEL')
    if (moved) {
      assert.equal(linked, true, `the isolated replacement must succeed after the parent moves (${swapError?.code})`)
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
    releaseWorker()
    await listener?.close()
    await worker?.terminate()
    if (linked) rmSync(acceptance, { recursive: true, force: true })
    if (moved) renameSync(held, acceptance)
    rmSync(root, { recursive: true, force: true })
  }
})
