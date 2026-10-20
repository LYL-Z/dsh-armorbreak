/**
 * v1.2.0 isolation-provider manager tests. No real daemon is required: the exec
 * probe is injected so every state transition (absent / CLI only / daemon ready
 * / verified) is deterministic.
 */
import assert from 'node:assert/strict'
import test from 'node:test'

import { IsolationProviderManager, PROVIDER_STATES } from '../lib/core/isolation.js'

function fakeExec(table) {
  return async (command, args) => {
    const key = `${command} ${args.join(' ')}`
    const value = table[key]
    if (value === undefined) {
      const error = new Error(`${command} not found`)
      error.code = 'ENOENT'
      throw error
    }
    if (value instanceof Error) throw value
    return { stdout: String(value), stderr: '' }
  }
}

const ABSENT = fakeExec({})
const CLI_ONLY = fakeExec({
  'docker --version': 'Docker version 27.0.0',
  'podman --version': 'podman version 5.0.0',
})
const READY = fakeExec({
  'docker --version': 'Docker version 27.0.0',
  'docker info --format {{.ServerVersion}}': '27.0.0',
  'podman --version': 'podman version 5.0.0',
  'wsl --version': 'WSL version 2.0',
  'wsl --status': 'Default Version: 2',
})

test('provider manager never claims isolation from a CLI without a daemon', async () => {
  const absent = await new IsolationProviderManager({ exec: ABSENT }).diagnose()
  assert.equal(absent.providers.find((p) => p.id === 'docker').state, 'Unavailable')
  assert.equal(absent.l1.available, false)

  const cliOnly = await new IsolationProviderManager({ exec: CLI_ONLY }).diagnose()
  const docker = cliOnly.providers.find((p) => p.id === 'docker')
  assert.equal(docker.state, 'Installed')
  assert.match(docker.reason, /daemon|守护/)
  assert.equal(cliOnly.l1.verified, false)

  const ready = await new IsolationProviderManager({ exec: READY }).diagnose()
  assert.equal(ready.providers.find((p) => p.id === 'docker').state, 'DaemonReady')
  assert.equal(ready.l1.available, false, 'daemon-ready is not verified isolation')
  assert.equal(ready.providers.find((p) => p.id === 'wsl2').state, 'Installed', 'WSL2 is not treated as a sandbox')
  assert.match(ready.wsl2Note, /WSL2/)
  for (const provider of ready.providers) assert.ok(PROVIDER_STATES.includes(provider.state))
})

test('verify requires an injected self-test and then records IsolationVerified', async () => {
  const manager = new IsolationProviderManager({ exec: READY, verifyImpl: async () => ({ ok: false, reason: 'self-test image missing' }) })
  const failed = await manager.verify('docker')
  assert.equal(failed.verified, false)
  assert.match(failed.reason, /self-test/)

  const good = new IsolationProviderManager({ exec: READY, verifyImpl: async () => ({ ok: true, reason: 'harmless container ran' }) })
  const result = await good.verify('docker')
  assert.equal(result.verified, true)
  const diagnosis = await good.diagnose({ fresh: true })
  assert.equal(diagnosis.providers.find((p) => p.id === 'docker').state, 'IsolationVerified')
  assert.equal(diagnosis.l1.available, true)
  assert.equal(diagnosis.l1.verified, true)
})

test('default verify is explicit about not being a self-test; guide lists official links', async () => {
  const manager = new IsolationProviderManager({ exec: READY })
  const result = await manager.verify('docker')
  assert.equal(result.verified, false)
  assert.match(result.reason, /verify-l1|未配置/)
  const guides = manager.installationGuide()
  assert.ok(guides.some((guide) => guide.id === 'docker' && /docker.com/.test(guide.installUrl)))
  assert.ok(guides.some((guide) => guide.id === 'wsl2' && /wsl/.test(guide.installUrl)))
})
