import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import fsPromises from 'node:fs/promises'
import { link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import test from 'node:test'

import { createEngine } from '../packages/engine-node/index.js'
import { createMcpServer } from '../packages/mcp-server/index.js'

async function fixture() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-mcp-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-mcp-ws-'))
  const { server, engine } = await createMcpServer({
    stateRoot, workspaceId: workspace,
    principal: { id: 'mcp-local', kind: 'local-user', workspaces: [workspace] },
  })
  return { server, engine, workspace }
}

test('MCP initialize, tools/list and tools/call capabilities', async () => {
  const { server, engine } = await fixture()
  const init = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }))
  const initialized = JSON.parse(init)
  assert.equal(initialized.result.protocolVersion, '2025-06-18')
  assert.equal(initialized.result.serverInfo.name, 'armorbreak')
  const list = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })))
  assert.ok(list.result.tools.some((tool) => tool.name === 'armorbreak_health'))
  assert.ok(list.result.tools.some((tool) => tool.name === 'armorbreak_capabilities'))
  const call = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'armorbreak_capabilities', arguments: {} } })))
  assert.equal(call.result.isError, false)
  const payload = JSON.parse(call.result.content[0].text)
  assert.equal(payload.length, 48)
  await engine.close()
})

test('MCP fails closed before initialize, on unknown tools and parse errors', async () => {
  const { server, engine } = await fixture()
  const before = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })))
  assert.equal(before.error.code, -32002)
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize' }))
  const unknown = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'rm_rf', arguments: {} } })))
  assert.equal(unknown.error.code, -32602)
  const malformed = JSON.parse(await server.handleLine('{not json'))
  assert.equal(malformed.error.code, -32700)
  assert.equal(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })), null)
  await engine.close()
})


test('MCP armorbreak_analyze performs a real L0 task and report', async () => {
  const { server, engine, workspace } = await fixture()
  await writeFile(join(workspace, 'sample.txt'), 'armorbreak mcp l0 test\n')
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const response = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'forensics.hash', target: join(workspace, 'sample.txt') } } })))
  assert.equal(response.result.isError, false, response.result.content?.[0]?.text)
  const result = JSON.parse(response.result.content[0].text)
  assert.equal(result.state, 'COMPLETED')
  assert.equal(result.capability, 'forensics.hash')
  assert.match(result.targetSha256, /^[a-f0-9]{64}$/)
  assert.ok(result.evidenceIds.length >= 1)
  assert.ok(result.reportPath)
  const taskRaw = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'armorbreak_task_get', arguments: { taskId: result.taskId } } }))
  const task = JSON.parse(JSON.parse(taskRaw).result.content[0].text || '{}')
  assert.equal(task.id, result.taskId)
  const storedTask = await engine.runtime.workspace(workspace).taskStore.get(result.taskId)
  assert.equal(storedTask.principalId, server.principal.id)
  assert.equal(storedTask.sessionId, server.connectionId)
  const otherConnectionId = randomUUID()
  const otherConnection = {
    ...server.context('other-connection'),
    principal: { ...server.principal, sessionId: otherConnectionId },
    connectionId: otherConnectionId,
  }
  await assert.rejects(() => engine.getTask(otherConnection, result.taskId), (cause) => cause.code === 'POLICY_DENIED')
  const evidenceRaw = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'armorbreak_evidence', arguments: { taskId: result.taskId } } }))
  const evidence = JSON.parse(JSON.parse(evidenceRaw).result.content[0].text)
  assert.ok(evidence.evidence.length >= 1)
  const reportRaw = await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'armorbreak_report', arguments: { taskId: result.taskId } } }))
  const report = JSON.parse(JSON.parse(reportRaw).result.content[0].text)
  assert.match(report.markdown, /完整性|哈希|ArmorBreak/)
  const resources = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'resources/list' })))
  assert.ok(resources.result.resources.some((resource) => resource.uri.endsWith(result.taskId)))
  const reportResource = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'resources/read', params: { uri: `armorbreak://report/${result.taskId}` } })))
  assert.match(reportResource.result.contents[0].text, /ArmorBreak/)
  const prompts = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'prompts/list' })))
  assert.ok(prompts.result.prompts.some((prompt) => prompt.name === 'armorbreak-triage'))
  const prompt = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 10, method: 'prompts/get', params: { name: 'armorbreak-triage' } })))
  assert.equal(prompt.result.messages[0].role, 'user')
  const outside = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'armorbreak_analyze', arguments: { capability: 'forensics.hash', target: 'C:\\Windows\\win.ini' } } })))
  assert.equal(outside.result.isError, true)
  await engine.close()
})


test('MCP exposes the seven Agent Skills with digests and readable SKILL.md', async () => {
  const { server, engine } = await fixture()
  await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }))
  const listed = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'skills/list' })))
  assert.equal(listed.result.skills.length, 7)
  for (const skill of listed.result.skills) {
    assert.match(skill.uri, /SKILL\.md$/)
    assert.match(skill.resources[0].digest, /^sha256:[a-f0-9]{64}$/)
    const read = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'resources/read', params: { uri: skill.uri } })))
    assert.match(read.result.contents[0].text, /^---\n/)
  }
  const got = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'skills/get', params: { uri: listed.result.skills[0].uri } })))
  assert.equal(got.result.skill.uri, listed.result.skills[0].uri)
  await engine.close()
})

test('MCP isolates engine failures at the JSON-RPC boundary and stdio stays available', async () => {
  const root = await mkdtemp(join(tmpdir(), 'abm-mcp-dispatch-error-'))
  const workspace = join(root, 'workspace')
  const stateRoot = join(root, 'state')
  await mkdir(workspace, { recursive: true })
  const principal = { id: 'mcp-dispatch-test', kind: 'local-user', workspaces: [workspace] }
  const seedEngine = await createEngine({ stateRoot, principals: [principal] })
  let foreignTask
  try {
    foreignTask = await seedEngine.createTask({
      principal, connectionId: 'another-mcp-connection', workspaceId: workspace,
      requestId: 'seed-foreign-task', traceId: 'seed-foreign-task',
    }, { title: 'same-principal task from another MCP connection' })
  } finally {
    await seedEngine.close()
  }
  const script = fileURLToPath(new URL('../packages/mcp-server/index.js', import.meta.url))
  const child = spawn(process.execPath, [script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ARMORBREAK_STATE_ROOT: stateRoot,
      ARMORBREAK_WORKSPACE: workspace,
      ARMORBREAK_PRINCIPAL_ID: 'mcp-dispatch-test',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const stdout = []
  const stderr = []
  child.stdout.on('data', (chunk) => stdout.push(String(chunk)))
  child.stderr.on('data', (chunk) => stderr.push(String(chunk)))
  child.stdin.end([
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: `armorbreak://task/${foreignTask.id}` } }),
    JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/list' }),
  ].join('\n') + '\n')

  try {
    const exitCode = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { child.kill(); reject(new Error('MCP stdio child timed out')) }, 10_000)
      child.once('error', (cause) => { clearTimeout(timeout); reject(cause) })
      child.once('exit', (code) => { clearTimeout(timeout); resolve(code) })
    })
    const responses = stdout.join('').trim().split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line))
    const byId = new Map(responses.map((response) => [response.id, response]))
    assert.equal(exitCode, 0, stderr.join(''))
    assert.equal(byId.get(2)?.error?.code, -32603)
    assert.equal(byId.get(2)?.error?.message, 'internal error')
    assert.ok(byId.get(3)?.result?.tools.some((tool) => tool.name === 'armorbreak_health'))
    assert.doesNotMatch(stdout.join('') + stderr.join(''), /POLICY_DENIED|outside the authorized workspace/)
  } finally {
    if (child.exitCode === null) child.kill()
    await rm(root, { recursive: true, force: true })
  }
})

test('MCP skill reads reject junction escapes and hard links without listing their contents', async () => {
  const { server, engine } = await fixture()
  const skillsRoot = fileURLToPath(new URL('../skills/', import.meta.url))
  const testId = randomUUID()
  const junctionName = `mcp-junction-${testId}`
  const hardlinkName = `mcp-hardlink-${testId}`
  const junctionPath = join(skillsRoot, junctionName)
  const hardlinkDirectory = join(skillsRoot, hardlinkName)
  const outside = await mkdtemp(join(tmpdir(), 'abm-mcp-skill-outside-'))
  const externalSkill = join(outside, 'SKILL.md')

  try {
    await writeFile(externalSkill, '---\nname: outside-secret\ndescription: outside fixture\n---\nOUTSIDE_SKILL_SECRET')
    // A directory junction makes the lexical URI look in-root while resolving outside.
    await symlink(outside, junctionPath, 'junction')
    // A hard link has no symlink metadata; nlink and opened-file identity must catch it.
    await mkdir(hardlinkDirectory)
    await link(externalSkill, join(hardlinkDirectory, 'SKILL.md'))
    await server.dispatch({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })

    for (const [id, skillPath] of [[2, join(junctionPath, 'SKILL.md')], [3, join(hardlinkDirectory, 'SKILL.md')]]) {
      const result = await server.dispatch({ jsonrpc: '2.0', id, method: 'resources/read', params: { uri: pathToFileURL(skillPath).href } })
      assert.equal(result.error?.code, -32602)
      assert.doesNotMatch(JSON.stringify(result), /OUTSIDE_SKILL_SECRET/)
    }

    const listed = await server.dispatch({ jsonrpc: '2.0', id: 4, method: 'skills/list' })
    assert.equal(listed.result.skills.some((skill) => [junctionName, hardlinkName].includes(skill.frontmatter.name)), false)
    assert.doesNotMatch(JSON.stringify(listed), /OUTSIDE_SKILL_SECRET/)
  } finally {
    await rm(junctionPath, { recursive: true, force: true })
    await rm(hardlinkDirectory, { recursive: true, force: true })
    await rm(outside, { recursive: true, force: true })
    await engine.close()
  }
})

if (process.platform === 'linux') test('MCP skill read rejects a parent symlink swap at the open boundary', async () => {
  const { server, engine } = await fixture()
  const skillsRoot = fileURLToPath(new URL('../skills/', import.meta.url))
  const testId = randomUUID()
  const skillName = `mcp-open-race-${testId}`
  const skillDirectory = join(skillsRoot, skillName)
  const retainedDirectory = `${skillDirectory}-retained`
  const skillPath = join(skillDirectory, 'SKILL.md')
  const outside = await mkdtemp(join(tmpdir(), 'abm-mcp-open-race-outside-'))
  const externalSkill = join(outside, 'SKILL.md')
  const originalOpen = fsPromises.open
  let swapped = false

  try {
    await mkdir(skillDirectory)
    await writeFile(skillPath, '---\nname: internal-race-fixture\ndescription: internal fixture\n---\nINTERNAL_SKILL_BYTES')
    await writeFile(externalSkill, '---\nname: outside-race-fixture\ndescription: external fixture\n---\nOUTSIDE_SKILL_SECRET')
    await server.dispatch({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} })
    fsPromises.open = async (file, ...args) => {
      const openedPath = resolve(String(file))
      const targetPath = resolve(skillPath)
      if (!swapped && openedPath === targetPath) {
        swapped = true
        await rename(skillDirectory, retainedDirectory)
        await symlink(outside, skillDirectory, 'dir')
      }
      return originalOpen(file, ...args)
    }
    syncBuiltinESMExports()

    const result = await server.dispatch({
      jsonrpc: '2.0', id: 2, method: 'resources/read',
      params: { uri: pathToFileURL(skillPath).href },
    })
    assert.equal(swapped, true, 'the parent symlink must be installed after pre-open checks and before open')
    assert.equal(result.error?.code, -32602)
    assert.doesNotMatch(JSON.stringify(result), /OUTSIDE_SKILL_SECRET/)
    assert.match(await readFile(externalSkill, 'utf8'), /OUTSIDE_SKILL_SECRET/)
  } finally {
    fsPromises.open = originalOpen
    syncBuiltinESMExports()
    await rm(skillDirectory, { recursive: true, force: true })
    await rm(retainedDirectory, { recursive: true, force: true })
    await rm(outside, { recursive: true, force: true })
    await engine.close()
  }
})
