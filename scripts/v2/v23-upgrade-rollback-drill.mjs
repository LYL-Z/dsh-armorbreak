#!/usr/bin/env node
/** Isolated package-selector drill using synthetic V2.2-compatible task data. */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { execFileSync } from 'node:child_process'
import { ApprovalAuthority } from '../../lib/control/approvalAuthority.js'
import { TransactionalInstaller } from '../../lib/install/installer.js'
import { TaskStore } from '../../packages/core/src/tasks.js'
import { inspectTask, snapshotTask } from '../../packages/migration/oldData.js'

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
const sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const evidencePath = 'docs/v2.3/evidence/p0-h/upgrade-rollback-drill.json'
const scratch = await mkdtemp(join(tmpdir(), 'armorbreak-v23-isolated-drill-'))
let scratchRemoved = false

try {
  const workspace = join(scratch, 'copied-v2.2-test-workspace')
  const taskId = 'task_v22_history_001'
  const taskDir = join(workspace, '.armorbreak', 'tasks', taskId)
  const reportPath = join(taskDir, 'report.md')
  const configPath = join(workspace, '.armorbreak', 'config.json')
  const originalReport = Buffer.from('# Synthetic V2.2 historical report\nStatus: COMPLETED\n')
  const originalConfig = Buffer.from('{"profile":"synthetic-test","permissions":["workspace.read"],"schemaVersion":"armorbreak.profile/v1"}\n')
  const task = {
    schemaVersion: 'armorbreak/v2', id: taskId, title: 'Synthetic V2.2 history fixture',
    state: 'COMPLETED', workspace, targetPath: join(workspace, 'fixtures', 'sample.bin'),
    targetKind: 'file', steps: [], stats: { evidence: 1, findings: 0, stepsDone: 1, stepsFailed: 0 },
    report: { path: reportPath, sha256: digest(originalReport) },
  }
  await mkdir(taskDir, { recursive: true })
  await mkdir(join(workspace, '.armorbreak'), { recursive: true })
  await writeFile(reportPath, originalReport)
  await writeFile(join(taskDir, 'evidence.jsonl'), '{"schemaVersion":"armorbreak.evidence/v1","id":"ev_v22_001","event":"fixture.completed"}\n')
  await writeFile(join(taskDir, 'task.json'), `${JSON.stringify(task, null, 2)}\n`)
  await writeFile(configPath, originalConfig)

  const before = {
    task: { files: snapshotTask(taskDir).files },
    configSha256: digest(await readFile(configPath)),
    reportSha256: digest(await readFile(reportPath)),
  }
  const historicalInspection = inspectTask(taskDir)
  assert.equal(historicalInspection.id, taskId)
  assert.equal(historicalInspection.reportSha256, before.reportSha256)

  const authority = new ApprovalAuthority({ stateRoot: join(scratch, 'approval-state') })
  const installer = new TransactionalInstaller({ root: join(scratch, 'isolated-install-root'), approvalAuthority: authority })
  const install = async (version, bytes) => {
    const artifactPath = join(scratch, `${version}.candidate.bin`)
    await writeFile(artifactPath, bytes)
    let plan = await installer.plan({
      artifactPath,
      components: [{ name: 'armorbreak-fixture', version, license: 'MIT', commit: sourceCommit.slice(0, 12), digest: `sha256:${digest(bytes)}`, scripts: {} }],
      repo: 'local/isolated-fixture', commit: sourceCommit, version, license: 'MIT', permissions: ['workspace.read'],
    })
    assert.equal(plan.status, 'PLANNED')
    await installer.persist(plan)
    const staged = await installer.stage(plan)
    const verified = await installer.verify(staged)
    const token = authority.issue({ id: `install:${plan.planId}`, riskLevel: 'L2', taskId: plan.planId, target: plan.planHash, operator: 'isolated-drill' }).token
    return { artifactPath, plan: await installer.approve(verified, { approvalToken: token, operator: 'isolated-drill' }) }
  }

  const v22 = await install('2.2.0-fixture', Buffer.from('synthetic-v2.2-package-marker\n'))
  const v22Active = await installer.activate(v22.plan)
  const previousPointer = await readFile(join(installer.root, 'active.json'))
  const v23 = await install('2.3.0-candidate', Buffer.from(`synthetic-v2.3-candidate:${sourceCommit}\n`))

  // Inject a post-verification staged-artifact change. Activation must refuse it
  // and keep the V2.2 active pointer unchanged. Then restore the expected bytes.
  const stagedArtifact = join(installer.staging, v23.plan.planId, 'artifact.bin')
  await writeFile(stagedArtifact, 'injected-corruption\n')
  await assert.rejects(() => installer.activate(v23.plan), /staged artifact changed before activation/)
  assert.deepEqual(await readFile(join(installer.root, 'active.json')), previousPointer)
  await copyFile(v23.artifactPath, stagedArtifact)
  const v23Active = await installer.activate(v23.plan)

  // Candidate reads the copied historical task and report while data remain in
  // the separate workspace root. A traversal id is refused at the store API.
  const candidateStore = new TaskStore({ workspaceRoot: workspace })
  const readTask = await candidateStore.get(taskId)
  assert.equal(readTask.schemaVersion, 'armorbreak/v2')
  assert.equal(readTask.report.sha256, before.reportSha256)
  assert.equal((await readFile(readTask.report.path)).toString(), originalReport.toString())
  assert.throws(() => candidateStore.taskDir('../outside'), /invalid task id/)

  const rollback = await installer.rollback(v23Active)
  const restoredPointer = await readFile(join(installer.root, 'active.json'))
  assert.deepEqual(restoredPointer, previousPointer)
  assert.equal(JSON.parse(restoredPointer).planId, v22Active.planId)
  const after = {
    task: { files: snapshotTask(taskDir).files },
    configSha256: digest(await readFile(configPath)),
    reportSha256: digest(await readFile(reportPath)),
  }
  assert.deepEqual(after, before)
  assert.equal(rollback.status, 'ROLLED_BACK')

  const summary = {
    schemaVersion: 'armorbreak.v2.3-upgrade-rollback-drill/v1',
    sourceCommit,
    executedAt: new Date().toISOString(),
    status: 'PASS_ISOLATED_FILESYSTEM_DRILL',
    dataOrigin: 'synthetic V2.2-compatible task/report/config fixture; no user data or formal install used',
    tempRootWasOutsideRepository: !resolve(scratch).toLowerCase().startsWith(`${resolve(process.cwd()).toLowerCase()}\\`),
    packageMechanism: 'TransactionalInstaller staged/verified/approved/activated a synthetic candidate artifact; no package code was executed',
    checks: {
      v22PackageActivated: v22Active.status === 'ACTIVE',
      v23StagedArtifactFailureWasInjected: true,
      injectedFailurePreservedV22ActivePointer: true,
      v23CandidateActivatedAfterIntegrityRestoration: v23Active.status === 'ACTIVE',
      historicalTaskAndReportReadByCurrentCandidateCore: true,
      pathTraversalDenied: true,
      v23RollbackRestoredV22ActivePointer: JSON.parse(restoredPointer).planId === v22Active.planId,
      oldTaskEvidenceReportAndConfigSha256Unchanged: JSON.stringify(after) === JSON.stringify(before),
      before,
      after,
      rollbackCleanup: rollback.cleanup,
      limitation: 'This exercises real local installer state transitions and Core reads on synthetic data; it is not an owner package installation or real user-profile upgrade, and OS ACL/service-principal isolation was not independently measured.',
    },
  }
  if (!summary.tempRootWasOutsideRepository) throw new Error('isolated drill workspace resolved inside the repository')
  await rm(scratch, { recursive: true, force: true })
  scratchRemoved = true
  summary.tempRootRemoved = scratchRemoved
  await writeFile(evidencePath, `${JSON.stringify(summary, null, 2)}\n`)
  console.log(JSON.stringify({ evidence: evidencePath, status: summary.status, sourceCommit, tempRootRemoved: scratchRemoved }, null, 2))
} finally {
  if (!scratchRemoved) await rm(scratch, { recursive: true, force: true }).catch(() => {})
}
