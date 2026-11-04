#!/usr/bin/env node
/** Exercise the actual release archive outside the source/development node_modules. */
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { verifyV23PortableManifest } from './verify-v23-portable-manifest.mjs'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const artifact = resolve(process.env.V23_PORTABLE_ARTIFACT ?? join(root, 'dist', 'armorbreak-portable-2.3.0.tar.gz'))
const output = resolve(process.env.V23_PORTABLE_EVIDENCE ?? join(root, 'dist', 'v23-portable-cleanroom.json'))
const npmCommand = process.platform === 'win32' ? process.execPath : 'npm'
const npmArgsPrefix = process.platform === 'win32' ? [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')] : []
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
const sourceCommit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const { artifactBytes, artifactSha256, manifest, manifestPath, manifestSha256 } = verifyV23PortableManifest(artifact, sourceCommit)
const scratch = mkdtempSync(join(tmpdir(), 'armorbreak-v23-portable-'))
const appRoot = join(scratch, 'app')
const workspace = join(scratch, 'workspace')
const stateRoot = join(scratch, 'state')
const summarize = (result) => ({
  exitCode: result.status,
  stdoutSha256: digest(Buffer.from(result.stdout ?? '')),
  stderrSha256: digest(Buffer.from(result.stderr ?? '')),
})
const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { cwd: appRoot, encoding: 'utf8', timeout: 180_000, windowsHide: true, ...options })
  if (result.error || result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed: ${result.error?.message ?? result.stderr?.slice(0, 800) ?? result.status}`)
  return { ...result, record: summarize(result) }
}
let engine
let evidence
try {
  mkdirSync(appRoot, { recursive: true })
  mkdirSync(workspace, { recursive: true })
  execFileSync('tar', ['-xzf', '-'], { cwd: appRoot, input: artifactBytes, stdio: ['pipe', 'pipe', 'pipe'] })
  const npmVersion = execFileSync(npmCommand, [...npmArgsPrefix, '--version'], { encoding: 'utf8' }).trim()
  const install = run(npmCommand, [...npmArgsPrefix, 'install', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--registry', 'https://registry.npmjs.org'])
  const packageJson = JSON.parse(readFileSync(join(appRoot, 'node_modules', 'typescript', 'package.json'), 'utf8'))
  if (packageJson.version !== '5.9.3' || packageJson.license !== 'Apache-2.0') throw new Error('isolated runtime did not install the pinned TypeScript 5.9.3 Apache-2.0 package')

  const capabilities = run(process.execPath, ['packages/cli/index.js', 'capabilities', '--json'], {
    env: { ...process.env, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace },
  })
  const capabilityList = JSON.parse(capabilities.stdout)
  if (capabilityList.length !== 53) throw new Error(`expected 53 capabilities, found ${capabilityList.length}`)
  await writeFileSync(join(workspace, 'sample.js'), 'export function run(value) { return value.trim() }\n')
  await writeFileSync(join(workspace, 'sample.ts'), 'export interface User { id: string }\nexport function getId(user: User): string { return user.id }\n')

  const principal = { id: 'portable-cleanroom', kind: 'local-user', workspaces: [workspace] }
  const { createMcpServer } = await import(pathToFileURL(join(appRoot, 'packages/mcp-server/index.js')))
  const created = await createMcpServer({ stateRoot, workspaceId: workspace, principal })
  engine = created.engine
  const server = created.server
  const call = async (id, name, args) => {
    const response = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } })))
    if (response.error || response.result?.isError) throw new Error(response.error?.message ?? response.result.content?.[0]?.text ?? `${name} failed`)
    return JSON.parse(response.result.content[0].text)
  }
  const initialize = JSON.parse(await server.handleLine(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } })))
  if (initialize.result?.protocolVersion !== '2025-06-18') throw new Error('portable MCP initialize failed')
  const direct = await call(2, 'armorbreak_analyze', { capability: 'source.symbols', target: workspace })
  const directTask = await call(3, 'armorbreak_task_get', { taskId: direct.taskId })
  const directReport = await call(4, 'armorbreak_report', { taskId: direct.taskId })
  if (direct.state !== 'COMPLETED' || !directTask.id || !directReport.markdown) throw new Error('direct JS/TS source.symbols task/report read failed')
  const directSummary = directTask.steps?.[0]?.summary ?? ''
  if (!/2\/2/.test(directSummary)) throw new Error(`clean-room JS/TS analysis did not report both source files: ${directSummary}`)
  const workflow = await call(5, 'armorbreak_workflow', { action: 'start', workflow: 'CrossLanguageSourceReview', target: workspace })
  const workflowTask = await call(6, 'armorbreak_task_get', { taskId: workflow.taskId })
  const workflowReport = await call(7, 'armorbreak_report', { taskId: workflow.taskId })
  if (workflow.state !== 'COMPLETED' || workflow.stats?.stepsDone !== 1 || workflowTask.steps?.[0]?.status !== 'DONE' || !workflowReport.markdown) throw new Error('portable L0 workflow task/report read or completion counter failed')
  await engine.close()
  engine = null
  evidence = {
    schemaVersion: 'armorbreak.v2.3-portable-cleanroom/v1',
    status: 'PASS_ACTUAL_CLEANROOM_ARCHIVE_EXECUTION',
    sourceCommit,
    environment: { platform: process.platform, arch: process.arch, node: process.version, npm: npmVersion, developmentWorktreeNodeModulesUsed: false },
    artifact: {
      path: artifact,
      bytes: artifactBytes.length,
      sha256: artifactSha256,
      manifestPath,
      manifestSha256,
      manifestCommit: manifest.commit,
      sbomSha256: manifest.sbomSha256,
    },
    runtimeDependency: { package: 'typescript', version: packageJson.version, license: packageJson.license, install: ['npm', 'install', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--registry', 'https://registry.npmjs.org'], result: install.record },
    checks: {
      capabilities: { count: capabilityList.length, result: capabilities.record },
      sourceSymbolsJavaScriptAndTypeScript: { taskId: direct.taskId, state: direct.state, summary: directSummary, reportSha256: digest(Buffer.from(directReport.markdown)), taskAndReportRead: true },
      l0Workflow: { workflow: 'CrossLanguageSourceReview', taskId: workflow.taskId, state: workflow.state, stepStatus: workflowTask.steps[0].status, stats: workflow.stats, reportSha256: digest(Buffer.from(workflowReport.markdown)), taskAndReportRead: true },
    },
  }
  mkdirSync(dirname(output), { recursive: true })
  writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' })
  console.log(JSON.stringify({ status: evidence.status, sourceCommit: evidence.sourceCommit, artifactSha256, evidencePath: output, checked: ['capabilities', 'JavaScript and TypeScript source.symbols', 'CrossLanguageSourceReview L0 workflow', 'task and report reads'] }, null, 2))
} finally {
  if (engine) await engine.close().catch(() => {})
  rmSync(scratch, { recursive: true, force: true })
}
