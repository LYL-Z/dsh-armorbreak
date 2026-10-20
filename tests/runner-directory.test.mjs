/**
 * Directory-target routing tests: the reported defect where WebCodeSecurityReview
 * declared a directory target but its sast capabilities fell back to `file`.
 * Also covers the planning-time target-kind check, the actionable file-vs-directory
 * error, and realpath containment for directory reads.
 */
import assert from 'node:assert/strict'
import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { ExecutionError, PolicyDeniedError } from '../lib/core/runner.js'
import { getWorkflow } from '../lib/core/workflows.js'

async function tempDir(prefix = 'abm-dir-') {
  return mkdtemp(join(tmpdir(), prefix))
}

async function makeRuntime() {
  const stateRoot = await tempDir('abm-dir-state-')
  const workspace = await tempDir('abm-dir-ws-')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  return { runtime, workspace }
}

/** Create a tiny vulnerable project used by the directory workflow test. */
async function makeProject(workspace) {
  const project = join(workspace, 'project')
  await mkdir(join(project, 'src'), { recursive: true })
  await writeFile(join(project, 'package.json'), JSON.stringify({ name: 'demo-project', version: '1.0.0', dependencies: { lodash: '4.17.20' } }, null, 2))
  await writeFile(join(project, 'src', 'app.js'), [
    '// tiny fixture for the directory workflow test',
    'export function run(userInput) {',
    '  const result = eval(userInput)',
    '  return result',
    '}',
    'export const awsKey = "AKIAIOSFODNN7EXAMPLE"',
    '',
  ].join('\n'))
  await writeFile(join(project, 'src', 'db.js'), [
    'export function query(db, userId) {',
    '  return db.query("SELECT * FROM users WHERE id = " + userId)',
    '}',
    '',
  ].join('\n'))
  return project
}

test('WebCodeSecurityReview runs on a real directory and produces multi-file findings', async () => {
  const { runtime, workspace } = await makeRuntime()
  const project = await makeProject(workspace)
  const workflow = getWorkflow('WebCodeSecurityReview')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'directory workflow test',
    targetPath: project,
    targetKind: 'directory',
    workflowId: workflow.id,
    steps: workflow.steps,
  })
  const updated = await runtime.runner.runWorkflow(task, { generateReport: true })
  assert.equal(updated.state, 'COMPLETED', `workflow failed: ${updated.stateHistory.at(-1)?.reason}`)
  assert.ok(updated.steps.every((step) => step.status === 'DONE'), `step statuses: ${JSON.stringify(updated.steps.map((step) => [step.id, step.status, step.error]))}`)
  assert.ok(updated.stats.evidence >= 4, `expected evidence from all four steps, got ${updated.stats.evidence}`)
  const { findings } = await store.evidenceStore(task.id).readFindings()
  assert.ok(findings.length >= 2, `expected findings from the directory scan, got ${findings.length}`)
  const targets = findings.map((finding) => finding.target).join('\n')
  assert.match(targets, /src[\\/]app\.js|src[\\/]db\.js/, 'findings must point at the scanned files, proving multi-file coverage')
  assert.ok(updated.report && updated.report.path.endsWith('.md'))
})

test('planning rejects a directory task whose capabilities only accept files', async () => {
  const { runtime, workspace } = await makeRuntime()
  const project = await makeProject(workspace)
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'mismatched kinds',
    targetPath: project,
    targetKind: 'directory',
    steps: [{ id: 'identify', title: 'binary only', capabilityId: 'binary.identify', options: {} }],
  })
  await assert.rejects(
    () => runtime.runner.prepareTask(task),
    (error) => error instanceof ExecutionError && error.code === 'TARGET_KIND_MISMATCH' && /directory-capable|accept a directory target/.test(error.message),
  )
  assert.equal(task.state, 'FAILED')
  assert.match(task.stateHistory.at(-1).reason, /sast\.scan/)
})

test('file capability on a directory target returns an actionable directory-capability hint', async () => {
  const { runtime, workspace } = await makeRuntime()
  const project = await makeProject(workspace)
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'file capability on directory',
    targetPath: project,
    targetKind: 'file',
    steps: [{ id: 'identify', title: 'binary only', capabilityId: 'binary.identify', options: {} }],
  })
  await assert.rejects(
    () =>
      runtime.runner.runCapability({
        task,
        capabilityId: 'binary.identify',
        targetPath: project,
        options: {},
        stepId: 'identify',
      }),
    (error) => error instanceof ExecutionError && error.code === 'TARGET_NOT_FILE' && /directory-capable capabilities/.test(error.message) && /sast\.scan/.test(error.message),
  )
  // The task remains in a recoverable state (steps failed but evidence preserved path is still open).
  assert.ok(['EXECUTING', 'COLLECTING_EVIDENCE', 'FAILED', 'PARTIAL_SUCCESS'].includes(task.state))
})

test('directory readFile rejects a junction that escapes the analyzed root', async (t) => {
  const { runtime, workspace } = await makeRuntime()
  const project = await makeProject(workspace)
  const outside = await tempDir('abm-dir-outside-')
  await writeFile(join(outside, 'secret.txt'), 'TOP-SECRET-OUTSIDE-ROOT')
  const linkPath = join(project, 'escape-link')
  try {
    await symlink(outside, linkPath, 'junction')
  } catch {
    t.skip('cannot create junction on this host')
    return
  }
  runtime.registry.registerManifest('fixturedir', {
    domain: 'fixturedir',
    capabilities: [
      {
        id: 'fixturedir.readfile',
        title: 'directory readFile containment probe',
        description: 'Reads one legitimate file and one junction-escaped file through the directory environment.',
        riskLevel: 'L0',
        targetKind: 'directory',
        params: { type: 'object', properties: {}, additionalProperties: false },
        async run(input) {
          const legit = await input.env.readFile(join(input.targetPath, 'src', 'app.js'), 4096)
          let escapeCode = null
          try {
            await input.env.readFile(join(linkPath, 'secret.txt'), 4096)
          } catch (error) {
            escapeCode = error?.code ?? String(error?.message ?? error)
          }
          return {
            summary: `legit=${legit.length} bytes, escapeCode=${escapeCode}`,
            data: { legitBytes: legit.length, escapeCode },
          }
        },
      },
    ],
  })
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'realpath containment',
    targetPath: project,
    targetKind: 'directory',
    steps: [{ id: 'probe', title: 'probe', capabilityId: 'fixturedir.readfile', options: {} }],
  })
  await runtime.runner.prepareTask(task)
  const result = await runtime.runner.runCapability({ task, capabilityId: 'fixturedir.readfile', targetPath: project, options: {}, stepId: 'probe' })
  assert.ok(result.data.legitBytes > 0, 'legitimate reads inside the root must still work')
  assert.equal(result.data.escapeCode, 'PATH_ESCAPE', 'a junction escaping the root must be rejected')
})

test('a directory task cannot smuggle a network capability past planning', async () => {
  const { runtime, workspace } = await makeRuntime()
  const project = await makeProject(workspace)
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'network step in directory task',
    targetPath: project,
    targetKind: 'directory',
    steps: [{ id: 'net', title: 'network', capabilityId: 'live.http_probe', options: { url: 'http://lab.example.test/' } }],
  })
  await assert.rejects(
    () => runtime.runner.prepareTask(task, { approvalTarget: 'lab.example.test' }),
    (error) => error instanceof ExecutionError && error.code === 'TARGET_KIND_MISMATCH' && /network/.test(error.message),
  )
  assert.equal(task.state, 'FAILED')
})
