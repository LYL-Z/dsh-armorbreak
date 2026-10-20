/**
 * Regression tests for two real defects found while testing the installed mode:
 *   1. `armorbreak_health` returned `state.tools = registry.list()`, which embeds
 *      capability `run`/`networkTarget` functions. The registry validates tool
 *      output as lossless JSON, so the call failed with "value is not lossless JSON".
 *   2. Without an explicit `workspace`, tools fell back to the host process cwd
 *      instead of the calling session's working directory.
 */
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

/** @param {Record<string, any>} services */
async function loadToolsWith(services = {}) {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-lossless-state-'))
  process.env.ARMORBREAK_HOME = stateRoot
  /** @type {Map<string, any>} */
  const defs = new Map()
  const ctx = {
    tools: { register: (definition) => (defs.set(definition.name, definition), () => {}) },
    get(name) {
      return services[name]
    },
    logger: { warn() {} },
  }
  const module = await import('../tools.js')
  module.apply(ctx)
  return { defs, stateRoot }
}

function mockExec(overrides = {}) {
  return { agent: { id: 'agent-test' }, callId: 'call_lossless_0001', signal: new AbortController().signal, ...overrides }
}

/**
 * Assert a value is lossless JSON: only null/string/finite number/boolean/
 * arrays/plain objects; no functions, symbols, bigint, undefined or cycles.
 * @param {unknown} value
 * @param {string} [path]
 * @param {Set<object>} [seen]
 */
function assertLossless(value, path = '$', seen = new Set()) {
  if (value === null) return
  const kind = typeof value
  if (kind === 'string' || kind === 'boolean') return
  if (kind === 'number') {
    assert.ok(Number.isFinite(value), `${path}: non-finite number`)
    return
  }
  assert.ok(kind === 'object', `${path}: non-lossless ${kind} value`)
  if (seen.has(value)) assert.fail(`${path}: circular reference`)
  seen.add(value)
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertLossless(item, `${path}[${index}]`, seen))
    return
  }
  const prototype = Object.getPrototypeOf(value)
  assert.ok(prototype === Object.prototype || prototype === null, `${path}: non-plain object ${prototype}`)
  for (const [key, inner] of Object.entries(value)) {
    assert.notEqual(inner, undefined, `${path}.${key}: undefined is not lossless JSON`)
    assertLossless(inner, `${path}.${key}`, seen)
  }
}

test('armorbreak_health output is lossless JSON (no embedded capability functions)', async () => {
  const { defs } = await loadToolsWith()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-lossless-ws-'))
  const value = await defs.get('armorbreak_health').execute({ workspace }, mockExec())
  assertLossless(value)
  assert.equal(Object.prototype.hasOwnProperty.call(value.data, 'tools'), false, 'state must not carry raw capability objects')
  // The capabilities projection is present and function-free.
  assert.ok(Array.isArray(value.data.capabilities))
  assert.ok(value.data.capabilities.length > 0)
  for (const capability of value.data.capabilities) {
    assert.equal(typeof capability.id, 'string')
    assert.equal(capability.run, undefined)
    assert.equal(capability.networkTarget, undefined)
  }
  // JSON round-trip is byte-stable (a lossless value survives it).
  assert.deepEqual(JSON.parse(JSON.stringify(value)), value)
})

test('every ArmorBreak tool returns lossless JSON data', async () => {
  const { defs } = await loadToolsWith()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-lossless-ws-'))
  const cases = [
    ['armorbreak_health', {}],
    ['armorbreak_capabilities', {}],
    ['armorbreak_capabilities', { probeDependencies: true }],
    ['armorbreak_scope', { action: 'list' }],
    ['armorbreak_environment', { action: 'providers' }],
    ['armorbreak_files', { action: 'list' }],
    ['armorbreak_task', { action: 'list' }],
    ['armorbreak_workflow', { action: 'list' }],
  ]
  for (const [name, args] of cases) {
    const value = await defs.get(name).execute({ ...args, workspace }, mockExec())
    assertLossless(value, name)
    assert.equal(typeof value.text, 'string')
  }
})

test('default workspace resolves to the session working directory', async () => {
  const sessionDir = await mkdtemp(join(tmpdir(), 'abm-session-'))
  const workingDirectory = {
    async ensure(agent) {
      assert.ok(agent, 'workingDirectory.ensure must receive the calling agent')
      return sessionDir
    },
  }
  const { defs } = await loadToolsWith({ workingDirectory })
  const health = await defs.get('armorbreak_health').execute({}, mockExec())
  assert.equal(health.data.workspace, sessionDir)
  const created = await defs.get('armorbreak_task').execute({ action: 'create', title: 'default workspace task' }, mockExec())
  assert.equal(created.data.workspace, sessionDir)
  assert.equal(created.data.state, 'CREATED')
  const listed = await defs.get('armorbreak_task').execute({ action: 'list' }, mockExec())
  assert.equal(listed.data.workspace, sessionDir)
  assert.ok(listed.data.tasks.some((task) => task.id === created.data.id))
})

test('explicit workspace still overrides the session working directory', async () => {
  const sessionDir = await mkdtemp(join(tmpdir(), 'abm-session-'))
  const explicitDir = await mkdtemp(join(tmpdir(), 'abm-explicit-'))
  const { defs } = await loadToolsWith({ workingDirectory: { async ensure() { return sessionDir } } })
  const created = await defs.get('armorbreak_task').execute({ action: 'create', title: 'explicit ws', workspace: explicitDir }, mockExec())
  assert.equal(created.data.workspace, explicitDir)
})
