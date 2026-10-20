/**
 * Tool-wiring integration tests: loads tools.js against a mock Cordis context,
 * captures every registered ToolDefinition, then executes the model-facing tools
 * end-to-end against the real core runtime (task store, policy, evidence, report).
 * This exercises the exact code path the harness registry calls, without an LLM.
 */
import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

/** @returns {Promise<{defs: Map<string, any>, ctx: any}>} */
async function loadTools() {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-tool-state-'))
  process.env.ARMORBREAK_HOME = stateRoot
  /** @type {Map<string, any>} */
  const defs = new Map()
  const ctx = {
    tools: {
      register(definition) {
        defs.set(definition.name, definition)
        return () => {}
      },
    },
    get() {
      return undefined
    },
    logger: { warn() {} },
  }
  const module = await import('../tools.js')
  module.apply(ctx)
  return { defs, ctx }
}

function mockExec(signal) {
  return { agent: undefined, callId: 'call_test_0001', signal: signal ?? new AbortController().signal }
}

test('tools.js registers nine model-facing tools with valid JSON schemas', async () => {
  const { defs } = await loadTools()
  const expected = [
    'armorbreak_health',
    'armorbreak_capabilities',
    'armorbreak_scope',
    'armorbreak_files',
    'armorbreak_task',
    'armorbreak_analyze',
    'armorbreak_workflow',
    'armorbreak_evidence',
    'armorbreak_report',
  ]
  assert.deepEqual([...defs.keys()].sort(), expected.sort())
  for (const [name, definition] of defs) {
    assert.equal(definition.name, name)
    assert.ok(definition.description.length > 80, `${name} description too short for model discovery`)
    assert.equal(definition.parameters.type, 'object', `${name} parameters must be an object schema`)
    assert.equal(definition.output.schema.type, 'object')
    assert.equal(typeof definition.output.render, 'function')
    assert.equal(typeof definition.execute, 'function')
    // Parameters declared in JSON Schema must not be empty for action-driven tools.
    if (name !== 'armorbreak_health') assert.ok(Object.keys(definition.parameters.properties ?? {}).length > 0, `${name} has no parameters`)
  }
})

test('armorbreak_health reports environment, isolation denial and capability count', async () => {
  const { defs } = await loadTools()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tool-ws-'))
  const value = await defs.get('armorbreak_health').execute({ workspace }, mockExec())
  assert.match(value.text, /环境健康|ArmorBreak/)
  assert.equal(value.data.version, '1.0.4')
  assert.ok(value.data.registry.capabilities > 0)
  assert.equal(typeof value.data.isolation.available, 'boolean')
  assert.ok(Array.isArray(value.data.capabilities))
})

test('armorbreak_capabilities lists real capabilities and describes one', async () => {
  const { defs } = await loadTools()
  const listed = await defs.get('armorbreak_capabilities').execute({}, mockExec())
  assert.ok(listed.data.capabilities.length > 0)
  const first = listed.data.capabilities[0]
  assert.ok(first.id.includes('.'))
  assert.ok(['L0', 'L1', 'L2', 'L3'].includes(first.riskLevel))
  const described = await defs.get('armorbreak_capabilities').execute({ capability: first.id }, mockExec())
  assert.match(described.text, new RegExp(first.id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  assert.equal(described.data.targetKind.length > 0, true)
})

test('armorbreak_task create/list/get works on the real task store', async () => {
  const { defs } = await loadTools()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tool-ws-'))
  const target = join(workspace, 'artifact.bin')
  await writeFile(target, 'artifact-bytes')
  const created = await defs.get('armorbreak_task').execute(
    { action: 'create', workspace, title: 'Tool wiring task', objective: 'verify tools', targetPath: target },
    mockExec(),
  )
  const taskId = created.data.id
  assert.match(taskId, /^task_/)
  assert.equal(created.data.state, 'CREATED')
  const listed = await defs.get('armorbreak_task').execute({ action: 'list', workspace }, mockExec())
  assert.ok(listed.data.tasks.some((task) => task.id === taskId))
  const fetched = await defs.get('armorbreak_task').execute({ action: 'get', workspace, taskId }, mockExec())
  assert.match(fetched.text, /Tool wiring task/)
  const noted = await defs.get('armorbreak_task').execute({ action: 'note', workspace, taskId, note: 'wiring verified' }, mockExec())
  assert.match(noted.text, /备注/)
})

test('armorbreak_analyze rejects unknown capabilities with an actionable message', async () => {
  const { defs } = await loadTools()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tool-ws-'))
  await assert.rejects(
    () => defs.get('armorbreak_analyze').execute({ capability: 'does.not_exist', workspace }, mockExec()),
    /unknown capability/,
  )
})

test('armorbreak_analyze runs a real L0 capability and produces a report', async (t) => {
  const { defs } = await loadTools()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tool-ws-'))
  const health = await defs.get('armorbreak_health').execute({ workspace }, mockExec())
  // Prefer a format-agnostic L0 file capability so any small fixture is valid input.
  const preferred = ['binary.identify', 'forensics.filetype', 'ctf.classify', 'ctf.flag_scan']
  const capability = health.data.capabilities.find((item) => item.riskLevel === 'L0' && item.targetKind === 'file' && preferred.includes(item.id))
  if (!capability) {
    t.skip('no format-agnostic L0 file capability registered yet')
    return
  }
  const sample = join(workspace, 'sample.bin')
  await writeFile(sample, Buffer.from('4142434445464748495041434b4554', 'hex'))
  const analyzed = await defs.get('armorbreak_analyze').execute({ capability: capability.id, target: sample, workspace }, mockExec())
  assert.match(analyzed.text, /任务/)
  assert.ok(analyzed.data.task.id.startsWith('task_'))
  assert.ok(analyzed.data.evidenceIds.length >= 1)
  const taskId = analyzed.data.task.id
  const report = await defs.get('armorbreak_report').execute({ taskId, workspace, format: 'markdown' }, mockExec())
  assert.match(report.text, /报告已生成/)
  assert.ok(report.data.path.endsWith('.md'))
  const evidence = await defs.get('armorbreak_evidence').execute({ action: 'chain', workspace, taskId }, mockExec())
  assert.match(evidence.text, /证据链/)
  assert.equal(evidence.data.evidence.valid, true)
})

test('armorbreak_scope separates request from platform-approved activation, then revokes', async () => {
  const { defs, ctx } = await loadTools()
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tool-ws-'))
  const scopePath = await mkdtemp(join(tmpdir(), 'abm-scope-'))
  const requested = await defs.get('armorbreak_scope').execute(
    { action: 'request', workspace, purpose: 'tool wiring test', operator: 'tester', paths: [scopePath], ttlHours: 1 },
    mockExec(),
  )
  assert.match(requested.data.id, /^authreq_/)
  assert.equal(requested.data.status, 'pending')
  assert.match(requested.text, /未生效|not active|不授予/i)
  const listedPending = await defs.get('armorbreak_scope').execute({ action: 'list', workspace }, mockExec())
  assert.equal(listedPending.data.authorizations.length, 0, 'a request must not create an active authorization')

  await assert.rejects(
    () => defs.get('armorbreak_scope').execute({ action: 'activate', workspace, requestId: requested.data.id }, mockExec()),
    /审批|approval|fail/i,
    'activation without the platform approval service must fail closed',
  )

  // Inject a mock platform approval service and retry activation.
  ctx.get = () => ({ request: async () => 'allowed-once' })
  const activated = await defs.get('armorbreak_scope').execute(
    { action: 'activate', workspace, requestId: requested.data.id },
    { agent: {}, callId: 'call_test_activate', signal: new AbortController().signal },
  )
  assert.match(activated.data.id, /^authz_/)
  assert.equal(activated.data.approvalSource, 'platform-approval')
  assert.match(activated.text, /平台审批/)
  const listed = await defs.get('armorbreak_scope').execute({ action: 'list', workspace }, mockExec())
  assert.ok(listed.data.authorizations.some((item) => item.id === activated.data.id))
  const revoked = await defs.get('armorbreak_scope').execute({ action: 'revoke', workspace, authorizationId: activated.data.id }, mockExec())
  assert.match(revoked.text, /已撤销/)
  await assert.rejects(
    () => defs.get('armorbreak_scope').execute({ action: 'authorize', workspace }, mockExec()),
    /已移除|request/,
    'the legacy self-service authorize action must not exist',
  )
})

test('armorbreak_workflow lists and rejects unknown workflow ids', async () => {
  const { defs } = await loadTools()
  const listed = await defs.get('armorbreak_workflow').execute({ action: 'list' }, mockExec())
  assert.ok(listed.data.workflows.length >= 8)
  const ids = listed.data.workflows.map((workflow) => workflow.id)
  for (const required of ['BinaryStaticAnalysis', 'AndroidAPKReview', 'WebCodeSecurityReview', 'PCAPInvestigation', 'DependencyAudit', 'CTFArtifactAnalysis', 'ForensicFileReview', 'SecurityReportGeneration']) {
    assert.ok(ids.includes(required), `missing workflow ${required}`)
  }
  const workspace = await mkdtemp(join(tmpdir(), 'abm-tool-ws-'))
  await assert.rejects(
    () => defs.get('armorbreak_workflow').execute({ action: 'start', workflow: 'NoSuchWorkflow', target: workspace, workspace }, mockExec()),
    /unknown workflow/,
  )
})
