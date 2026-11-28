import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import test from 'node:test'
import { waitForWindowsWorkbench } from '../scripts/v24/verify-windows-experience.mjs'

function launcher() {
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  return child
}

test('Windows probe waits for the complete UTF-8 Workbench announcement and port', async () => {
  const child = launcher()
  const startup = waitForWindowsWorkbench(child)
  child.emit('spawn')
  const prefix = Buffer.from('ArmorBreak 工作台：')
  child.stdout.write(prefix.subarray(0, -1))
  child.stdout.write(Buffer.concat([prefix.subarray(-1), Buffer.from('http://127.0.0.1:12')]))
  const state = await Promise.race([startup, Promise.resolve('waiting')])
  assert.equal(state, 'waiting')
  child.stdout.write('345\r\n')
  assert.equal(await startup, 'http://127.0.0.1:12345')
})

test('Windows probe rejects malformed Workbench endpoints', async () => {
  for (const endpoint of ['http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://localhost:3456']) {
    const child = launcher()
    const startup = waitForWindowsWorkbench(child)
    child.emit('spawn')
    child.stdout.write(`ArmorBreak 工作台：${endpoint}\r\n`)
    await assert.rejects(startup, /EXPERIENCE_START_BAD_ENDPOINT/)
  }
})

test('Windows probe separates CMD spawn failure, exit, and missing Node', async () => {
  const unspawned = launcher()
  const failed = waitForWindowsWorkbench(unspawned)
  unspawned.emit('error', Object.assign(new Error('local private launcher path'), { code: 'ENOENT' }))
  await assert.rejects(failed, /^Error: EXPERIENCE_CMD_SPAWN_FAILED phase=CMD_SPAWN_PENDING stdoutBytes=0 stderrBytes=0 code=ENOENT$/)

  const exited = launcher()
  const early = waitForWindowsWorkbench(exited)
  exited.emit('spawn')
  exited.stderr.write('local private launcher path')
  exited.emit('exit', 1, null)
  exited.emit('close', 1, null)
  await assert.rejects(early, /^Error: EXPERIENCE_START_EXITED phase=CMD_NODE_PREFLIGHT_PENDING stdoutBytes=0 stderrBytes=27 exitCode=1 signal=none$/)

  const preflight = launcher()
  const noNode = waitForWindowsWorkbench(preflight)
  preflight.emit('spawn')
  preflight.stdout.write('Node.js 22 or newer is required. Install the official Node.js LTS, then try again.\r\n')
  await assert.rejects(noNode, /EXPERIENCE_NODE_PREREQUISITE_FAILED phase=CMD_NODE_PREFLIGHT_PENDING/)

  const failedCli = launcher()
  const cliStarted = waitForWindowsWorkbench(failedCli)
  failedCli.emit('spawn')
  failedCli.stdout.write('DSH is not connected. No privileged approval or host installation is available.\r\n')
  failedCli.stderr.write('ERR_MODULE_NOT_FOUND: local private module path')
  failedCli.stdout.write('Startup failed. Check the message above. No administrator permission is required.\r\n')
  await assert.rejects(cliStarted, /^Error: EXPERIENCE_START_FAILED phase=WORKBENCH_URL_PENDING stdoutBytes=\d+ stderrBytes=\d+ code=ERR_MODULE_NOT_FOUND$/)
})

test('Windows probe identifies which startup evidence is missing at deadline', async () => {
  const cases = [
    ['Unrelated text http://127.0.0.1:12345\r\n', 'CMD_NODE_PREFLIGHT_PENDING'],
    ['DSH is not connected. No privileged approval or host installation is available.\r\n', 'WORKBENCH_URL_PENDING'],
    ['ArmorBreak 工作台：http://127.0.0.1:12345', 'WORKBENCH_URL_INCOMPLETE'],
  ]
  await Promise.all(cases.map(async ([output, phase]) => {
    const child = launcher()
    const startup = waitForWindowsWorkbench(child, 20)
    child.emit('spawn')
    child.stdout.write(output)
    await assert.rejects(startup, new RegExp(`EXPERIENCE_START_TIMEOUT phase=${phase}`))
  }))
})

test('Windows probe bounds diagnostic output while waiting for startup', async () => {
  const child = launcher()
  const startup = waitForWindowsWorkbench(child)
  child.emit('spawn')
  child.stderr.write(Buffer.alloc(65537, 'x'))
  await assert.rejects(startup, /^Error: EXPERIENCE_START_OUTPUT_LIMIT phase=CMD_NODE_PREFLIGHT_PENDING stdoutBytes=0 stderrBytes=65537$/)
})
