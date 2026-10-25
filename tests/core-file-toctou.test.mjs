import assert from 'node:assert/strict'
import { link, mkdir, mkdtemp, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { readBounded } from '../lib/core/util.js'

test('runner rechecks scope and refuses a directory junction swap before L0 file read', async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'abm-runner-file-race-'))
  const workspace = join(base, 'workspace')
  const inside = join(workspace, 'inside')
  const retained = join(workspace, 'inside-retained')
  const outside = join(base, 'outside')
  const target = join(inside, 'sample.txt')
  await mkdir(inside, { recursive: true })
  await mkdir(outside, { recursive: true })
  await writeFile(target, 'SAFE_IN_WORKSPACE')
  await writeFile(join(outside, 'sample.txt'), 'OUTSIDE_SYNTHETIC_SECRET')

  const junctionProbe = join(base, 'junction-probe')
  try {
    await symlink(outside, junctionProbe, 'junction')
    await rm(junctionProbe, { recursive: true, force: true })
  } catch (error) {
    await rm(base, { recursive: true, force: true })
    if (['EPERM', 'EACCES', 'ENOSYS'].includes(error?.code)) {
      t.skip(`directory link creation unavailable on this platform: ${error.code}`)
      return
    }
    throw error
  }

  const runtime = new ArmorBreakRuntime({ stateRoot: join(base, 'state') })
  try {
    await runtime.init()
    let capabilityExecuted = false
    runtime.registry.registerManifest('file-race-fixture', {
      domain: 'file-race-fixture',
      capabilities: [{
        id: 'fixture.race.read',
        title: 'fixture race read',
        description: 'returns only the bytes read by the core harness',
        riskLevel: 'L0',
        targetKind: 'file',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run(input) {
          capabilityExecuted = true
          return { summary: input.text ?? '(binary)', data: { observed: input.text }, evidence: [] }
        },
      }],
    })
    const store = runtime.workspace(workspace).taskStore
    const task = await store.create({
      title: 'synthetic file path race',
      objective: 'verify L0 file scope is stable across open',
      targetPath: target,
      targetKind: 'file',
      steps: [{ id: 'read', title: 'read', capabilityId: 'fixture.race.read', options: {} }],
    })
    await runtime.runner.prepareTask(task)

    let swapped = false
    const originalCheck = runtime.scope.checkFile.bind(runtime.scope)
    runtime.scope.checkFile = async (request) => {
      const result = await originalCheck(request)
      if (result.allowed && !swapped && request.targetPath === target) {
        await rename(inside, retained)
        try {
          await symlink(outside, inside, 'junction')
          swapped = true
        } catch (error) {
          await rename(retained, inside)
          throw error
        }
      }
      return result
    }

    await assert.rejects(
      runtime.runner.runCapability({ task, capabilityId: 'fixture.race.read', targetPath: target, options: {}, stepId: 'read' }),
      (error) => ['OUT_OF_SCOPE', 'PATH_CHANGED'].includes(error?.code),
    )
    assert.equal(swapped, true)
    assert.equal(capabilityExecuted, false)
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('bounded core reader rejects a hard link to a file with an external name', async (t) => {
  const base = await mkdtemp(join(tmpdir(), 'abm-util-hardlink-'))
  const external = join(base, 'external.txt')
  const workspace = join(base, 'workspace')
  const target = join(workspace, 'linked.txt')
  await mkdir(workspace, { recursive: true })
  await writeFile(external, 'OUTSIDE_SYNTHETIC_SECRET')
  try {
    await link(external, target)
  } catch (error) {
    await rm(base, { recursive: true, force: true })
    if (['EPERM', 'EACCES', 'ENOSYS', 'EXDEV'].includes(error?.code)) {
      t.skip(`hard link creation unavailable on this filesystem: ${error.code}`)
      return
    }
    throw error
  }
  try {
    await assert.rejects(readBounded(target, 1024), /multiple hard links/)
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})
