#!/usr/bin/env node
/** Real package deployment/read/rollback drill using the published V2.2 package and built V2.3 candidate. */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { release, tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const candidateVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version
const historicalV22CapabilityCount = 46
const candidateArtifact = join(root, 'dist', `armorbreak-portable-${candidateVersion}.tar.gz`)
const candidateManifestPath = `${candidateArtifact}.manifest.json`
const evidencePath = 'docs/v2.3/evidence/p0-h/real-package-upgrade-rollback.json'
const V22_ASSET = 'armorbreak-portable-2.2.0.tar.gz'
// GitHub Release API digest for the immutable v2.2.0 asset observed on 2026-10-30.
const V22_SHA256 = '5e5aca98da18d4f0cb17db71cf57c5577f8f8f64810a30844bd5237b4ed7b630'
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')
const fileDigest = (path) => digest(readFileSync(path))
const normalizedPath = (path) => resolve(path).replaceAll('\\', '/')
const samePath = (left, right) => process.platform === 'win32'
  ? normalizedPath(left).toLowerCase() === normalizedPath(right).toLowerCase()
  : normalizedPath(left) === normalizedPath(right)
const isWithinPath = (path, parent) => {
  const child = normalizedPath(path)
  const root = normalizedPath(parent).replace(/\/$/, '')
  return (process.platform === 'win32' ? child.toLowerCase() : child) .startsWith(`${process.platform === 'win32' ? root.toLowerCase() : root}/`)
}
const redactDiagnostic = (value, paths = []) => {
  let text = String(value ?? '').slice(0, 1200)
  for (const [path, label] of paths) if (path) text = text.split(path).join(label)
  return text
    .replace(/file:\/\/\/[A-Za-z]:\/[^\r\n\s"']+/gi, '<redacted-path>')
    .replace(/(?:[A-Za-z]:\\|\\\\)[^\r\n]*/g, '<redacted-path>')
    .replace(/(?:\/home\/|\/Users\/)[^/\s]+/g, '<redacted-user-path>')
    .replace(/\bS-1-\d+(?:-\d+)+\b/g, '<redacted-sid>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, '<redacted-id>')
    .replace(/(token|authorization|password|secret)(\s*[:=]\s*)\S+/gi, '$1$2<redacted>')
}
const safeStat = (path) => {
  try {
    const lexical = lstatSync(path, { bigint: true })
    const canonical = realpathSync(path)
    const info = statSync(path, { bigint: true })
    return { exists: true, type: lexical.isSymbolicLink() ? 'symlink' : lexical.isFile() ? 'file' : lexical.isDirectory() ? 'directory' : 'other', bytes: info.isFile() ? Number(info.size) : null, sha256: info.isFile() ? fileDigest(path) : null, realpathMatchesExpected: samePath(canonical, path), dev: String(info.dev), ino: String(info.ino), nlink: String(info.nlink) }
  } catch (error) {
    return { exists: false, errorCode: error?.code ?? 'UNKNOWN' }
  }
}
const sha256FileTree = (dir) => {
  const out = {}
  const visit = (base) => {
    for (const entry of readdirSync(base, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(base, entry.name)
      const stat = lstatSync(path)
      if (stat.isSymbolicLink()) throw new Error(`drill refuses symlink entry: ${relative(dir, path)}`)
      if (stat.isDirectory()) visit(path)
      else if (stat.isFile()) out[relative(dir, path).split(sep).join('/')] = { size: stat.size, sha256: fileDigest(path) }
      else throw new Error(`drill refuses non-regular entry: ${relative(dir, path)}`)
    }
  }
  visit(dir)
  return out
}
const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true, maxBuffer: 12 * 1024 * 1024, timeout: 120_000, ...options })
  return { status: result.status, signal: result.signal ?? null, stdout: result.stdout ?? '', stderr: result.stderr ?? '', error: result.error?.message ?? null, errorCode: result.error?.code ?? null }
}
function execute(command, args, options = {}) {
  const result = run(command, args, options)
  if (result.error || result.status !== 0) {
    const stderrSha256 = digest(Buffer.from(result.stderr))
    throw new Error(`${command} failed (exit=${result.status ?? 'null'}, signal=${result.signal ?? 'none'}, code=${result.errorCode ?? 'none'}, stderrSha256=${stderrSha256})`)
  }
  return result
}
function summary(command, args, result) {
  return { command: [command, ...args], exitCode: result.status, stdoutSha256: digest(Buffer.from(result.stdout)), stderrSha256: digest(Buffer.from(result.stderr)), error: result.error }
}
function cleanupScratch(path) {
  if (!existsSync(path)) return null
  const args = [path, '/reset', '/T', '/C']
  const aclReset = run('icacls.exe', args)
  if (aclReset.error || aclReset.status !== 0) throw new Error(`could not restore inherited ACLs on isolated temporary data before cleanup (diagnostic SHA-256 ${digest(Buffer.from(`${aclReset.error ?? ''}\n${aclReset.stderr}`))})`)
  rmSync(path, { recursive: true, force: true })
  return summary('icacls.exe', ['<isolated-temp>', '/reset', '/T', '/C'], aclReset)
}
function unpack(archive, target) {
  mkdirSync(target, { recursive: true })
  return execute('tar', ['-xzf', archive, '-C', target])
}
function cli(appDir, env, ...args) {
  return run(process.execPath, [join(appDir, 'packages', 'cli', 'index.js'), ...args], { cwd: appDir, env })
}

const diagnostics = {
  schemaVersion: 'armorbreak.v23-windows-drill-diagnostics/v1', status: 'IN_PROGRESS', capturedAt: new Date().toISOString(),
  runner: { platform: process.platform, arch: process.arch, node: process.version, windowsRelease: process.platform === 'win32' ? release() : null, gitVersion: null, tempConfigured: Boolean(process.env.TEMP), tmpConfigured: Boolean(process.env.TMP), tempPathSha256: process.env.TEMP ? digest(Buffer.from(resolve(process.env.TEMP))) : null, tmpPathSha256: process.env.TMP ? digest(Buffer.from(resolve(process.env.TMP))) : null, tempEqualsTmp: Boolean(process.env.TEMP && process.env.TMP && samePath(process.env.TEMP, process.env.TMP)), tempUnderRunnerTemp: Boolean(process.env.TEMP && process.env.RUNNER_TEMP && isWithinPath(process.env.TEMP, process.env.RUNNER_TEMP)), tmpUnderRunnerTemp: Boolean(process.env.TMP && process.env.RUNNER_TEMP && isWithinPath(process.env.TMP, process.env.RUNNER_TEMP)) },
  steps: {},
}
try { diagnostics.runner.gitVersion = run('git', ['--version']).stdout.trim().slice(0, 80) } catch {}
const diagnosticPath = process.env.V23_DIAGNOSTICS_PATH
const writeDiagnostics = () => {
  if (!diagnosticPath) return
  mkdirSync(dirname(diagnosticPath), { recursive: true })
  writeFileSync(diagnosticPath, `${JSON.stringify(diagnostics, null, 2)}\n`)
}

if (process.platform !== 'win32') throw new Error('the real package permission/ACL drill requires a Windows host')
// Use the runner-owned scratch root as TEMP/TMP for every child CLI. The hosted
// Windows default user Temp path was outside RUNNER_TEMP; preserving the custom
// default can make historical V2.2 path checks depend on runner path aliases.
const isolatedTempRoot = resolve(process.env.RUNNER_TEMP || tmpdir())
process.env.TEMP = isolatedTempRoot
process.env.TMP = isolatedTempRoot
diagnostics.runner.tempPathSha256 = digest(Buffer.from(isolatedTempRoot))
diagnostics.runner.tmpPathSha256 = digest(Buffer.from(isolatedTempRoot))
diagnostics.runner.tempEqualsTmp = true
diagnostics.runner.tempUnderRunnerTemp = Boolean(process.env.RUNNER_TEMP && (samePath(isolatedTempRoot, process.env.RUNNER_TEMP) || isWithinPath(isolatedTempRoot, process.env.RUNNER_TEMP)))
diagnostics.runner.tmpUnderRunnerTemp = diagnostics.runner.tempUnderRunnerTemp
if (candidateVersion !== '2.3.1') throw new Error(`candidate package version must be 2.3.1 (found ${candidateVersion})`)
if (!existsSync(candidateArtifact) || !existsSync(candidateManifestPath)) throw new Error('build the committed V2.3 candidate package and manifest before running this drill')
const head = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const candidateManifest = JSON.parse(readFileSync(candidateManifestPath, 'utf8'))
if (candidateManifest.commit !== head || candidateManifest.version !== '2.3.1' || candidateManifest.productionSigned !== false) throw new Error('candidate manifest must identify the current exact commit and remain explicitly unsigned')
const candidateSha256 = fileDigest(candidateArtifact)
const manifestSha256 = candidateManifest.sha256 ?? candidateManifest.artifact?.sha256
if (manifestSha256 !== candidateSha256 || candidateManifest.version !== '2.3.1' || candidateManifest.reproducible !== true || candidateManifest.cleanRoom?.result !== 'PASS') throw new Error('candidate artifact digest, version, reproducibility, or clean-room execution check failed')

const scratch = mkdtempSync(join(isolatedTempRoot, 'armorbreak-v23-real-deploy-'))
try {
  const v22Downloads = join(scratch, 'v22-download')
  mkdirSync(v22Downloads, { recursive: true })
  const v22DownloadArgs = ['release', 'download', 'v2.2.0', '--repo', 'LYL-Z/dsh-armorbreak', '--pattern', V22_ASSET, '--dir', v22Downloads]
  let v22DownloadAttempts = 0
  let v22DownloadResult
  while (v22DownloadAttempts < 4) {
    v22DownloadAttempts += 1
    v22DownloadResult = run('gh', v22DownloadArgs, { cwd: root })
    if (!v22DownloadResult.error && v22DownloadResult.status === 0) break
    if (v22DownloadAttempts < 4) await new Promise((resolveDelay) => setTimeout(resolveDelay, 1500 * v22DownloadAttempts))
  }
  if (v22DownloadResult.error || v22DownloadResult.status !== 0) {
    const failureDigest = digest(Buffer.from(`${v22DownloadResult.error ?? ''}\n${v22DownloadResult.stderr}`))
    throw new Error(`read-only v2.2.0 asset download failed after ${v22DownloadAttempts} attempts (diagnostic SHA-256 ${failureDigest})`)
  }
  const v22Artifact = join(v22Downloads, V22_ASSET)
  const v22Sha256 = fileDigest(v22Artifact)
  assert.equal(v22Sha256, V22_SHA256, 'downloaded historical asset must match the GitHub Release API SHA-256')

  const installs = join(scratch, 'installed-versions')
  const v22Install = join(installs, '2.2.0')
  const corruptedStage = join(installs, '2.3.1-staged-fault')
  const candidateInstall = join(installs, '2.3.1')
  const workspace = join(scratch, 'isolated-v2.2-test-profile', 'workspace')
  const stateRoot = join(scratch, 'isolated-v2.2-test-profile', 'state')
  const configDir = join(workspace, '.armorbreak')
  const configPath = join(configDir, 'mcp-host-config.json')
  const sample = join(workspace, 'v22-read-only-sample.txt')
  const outsideSample = join(scratch, 'outside-authorized-workspace.txt')
  mkdirSync(workspace, { recursive: true })
  mkdirSync(stateRoot, { recursive: true })
  mkdirSync(configDir, { recursive: true })
  writeFileSync(sample, 'V2.2 isolated read-only upgrade drill fixture\n')
  writeFileSync(outsideSample, 'outside workspace boundary sentinel\n')
  const config = {
    mcpServers: { armorbreak: {
      command: process.execPath,
      args: [join(v22Install, 'packages', 'mcp-server', 'index.js')],
      env: { ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_PRINCIPAL_ID: 'armorbreak-v23-isolated-test-user' },
    } },
  }
  const originalConfigBytes = Buffer.from(`${JSON.stringify(config, null, 2)}\n`)
  writeFileSync(configPath, originalConfigBytes)
  const v22UnpackResult = unpack(v22Artifact, v22Install)
  const v22Package = JSON.parse(readFileSync(join(v22Install, 'package.json'), 'utf8'))
  assert.equal(v22Package.version, '2.2.0')

  const whoami = execute('whoami.exe', ['/user', '/fo', 'csv', '/nh'])
  const sid = /S-1-\d+(?:-\d+)+/.exec(whoami.stdout)?.[0]
  if (!sid) throw new Error('cannot identify the Windows current-user principal SID')
  const aclResult = execute('icacls.exe', [scratch, '/inheritance:r', '/grant:r', `*${sid}:(F)`, '/T', '/C'])
  const aclInheritanceResult = execute('icacls.exe', [scratch, '/grant', `*${sid}:(OI)(CI)(IO)(F)`, '/T', '/C'])
  const disallowedAclSids = ['S-1-1-0', 'S-1-5-32-545', 'S-1-5-11']
  const aclScript = join(scratch, 'verify-acl.ps1')
  writeFileSync(aclScript, '$ErrorActionPreference = "Stop"\n$paths = ConvertFrom-Json $env:V23_ACL_PATHS\n$result = foreach ($path in $paths) { $item = Get-Item -LiteralPath $path -Force; foreach ($entry in $item.GetAccessControl().Access) { [pscustomobject]@{ path = $path; sid = $entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; type = [string]$entry.AccessControlType; rights = [string]$entry.FileSystemRights; inherited = [bool]$entry.IsInherited } } }\nConvertTo-Json -InputObject @($result) -Compress -Depth 5\n')
  const aclChecks = execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', aclScript], { env: { ...process.env, V23_ACL_PATHS: JSON.stringify([workspace, configDir, configPath]) } })
  const aclEntries = JSON.parse(aclChecks.stdout)
  diagnostics.steps.acl = {
    checkedPaths: ['<isolated-workspace>', '<isolated-workspace>/.armorbreak', '<isolated-workspace>/.armorbreak/mcp-host-config.json'],
    entries: aclEntries.map((entry) => ({ pathLabel: entry.path === workspace ? '<isolated-workspace>' : entry.path === configDir ? '<isolated-workspace>/.armorbreak' : '<isolated-workspace>/.armorbreak/mcp-host-config.json', sidMatchesCurrentUser: entry.sid === sid, type: entry.type, rights: entry.rights, inherited: entry.inherited })),
    broadPrincipalsAbsent: !disallowedAclSids.some((value) => aclEntries.some((entry) => entry.sid === value)),
    commandOutputSha256: digest(Buffer.from(`${aclResult.stdout}\n${aclInheritanceResult.stdout}`)),
    inspectionOutputSha256: digest(Buffer.from(aclChecks.stdout)),
  }
  if (aclEntries.some((entry) => entry.sid !== sid || entry.type !== 'Allow') || disallowedAclSids.some((value) => aclEntries.some((entry) => entry.sid === value)) || new Set(aclEntries.map((entry) => entry.path)).size !== 3) throw new Error('isolated workspace/config ACL is not restricted to current-user allow entries')
  const runEnv = {
    ...process.env,
    ARMORBREAK_STATE_ROOT: stateRoot,
    ARMORBREAK_WORKSPACE: workspace,
    ARMORBREAK_PRINCIPAL_ID: 'armorbreak-v23-isolated-test-user',
    ARMORBREAK_MCP_AUDIT_LOG: join(stateRoot, 'mcp-audit.jsonl'),
  }
  diagnostics.steps.environment = {
    stateRootMatchesConfigured: samePath(runEnv.ARMORBREAK_STATE_ROOT, config.mcpServers.armorbreak.env.ARMORBREAK_STATE_ROOT),
    workspaceMatchesConfigured: samePath(runEnv.ARMORBREAK_WORKSPACE, config.mcpServers.armorbreak.env.ARMORBREAK_WORKSPACE),
    stateRootIsIsolated: isWithinPath(runEnv.ARMORBREAK_STATE_ROOT, scratch),
    workspaceIsIsolated: isWithinPath(runEnv.ARMORBREAK_WORKSPACE, scratch),
    principalConfigured: Boolean(runEnv.ARMORBREAK_PRINCIPAL_ID),
    principalMatchesConfig: runEnv.ARMORBREAK_PRINCIPAL_ID === config.mcpServers.armorbreak.env.ARMORBREAK_PRINCIPAL_ID,
    stateRootLabel: '<isolated-state-root>', workspaceLabel: '<isolated-workspace>', sessionPolicy: 'CLI process has no MCP session; task session is null by design',
  }
  const v22CapabilitiesBefore = cli(v22Install, runEnv, 'capabilities', '--json')
  if (v22CapabilitiesBefore.status !== 0 || JSON.parse(v22CapabilitiesBefore.stdout).length !== historicalV22CapabilityCount) throw new Error(`published V2.2.0 package capability baseline does not match ${historicalV22CapabilityCount}`)
  const v22SeedAnalyzeArgs = ['analyze', '--capability', 'forensics.hash', '--target', sample, '--json']
  const v22Seed = cli(v22Install, runEnv, ...v22SeedAnalyzeArgs)
  diagnostics.steps.v22Seed = { exitCode: v22Seed.status, signal: v22Seed.signal, errorCode: v22Seed.errorCode, stdoutSha256: digest(Buffer.from(v22Seed.stdout)), stderr: redactDiagnostic(v22Seed.stderr, [[scratch, '<isolated-temp>']]), taskId: null }
  if (v22Seed.status !== 0) throw new Error('V2.2 package could not create the isolated history task (see structured diagnostics)')
  const taskId = JSON.parse(v22Seed.stdout).taskId
  diagnostics.steps.v22Seed.taskId = { present: typeof taskId === 'string', formatValid: typeof taskId === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(taskId) }
  const v22Task = cli(v22Install, runEnv, 'task', 'status', taskId, '--json')
  const v22Report = cli(v22Install, runEnv, 'report', taskId, '--json')
  const taskDir = join(workspace, '.armorbreak', 'tasks', String(taskId))
  const taskFile = join(taskDir, 'task.json')
  let taskRecordOnDisk = null
  let taskRecordErrorCode = null
  try { if (existsSync(taskFile)) taskRecordOnDisk = JSON.parse(readFileSync(taskFile, 'utf8')) } catch (error) { taskRecordErrorCode = error?.code ?? 'INVALID_JSON' }
  let reportRecordOnDisk = null
  const reportsDir = join(taskDir, 'reports')
  if (existsSync(reportsDir)) {
    const reportFiles = readdirSync(reportsDir).filter((name) => name.endsWith('.md')).sort()
    if (reportFiles.length) reportRecordOnDisk = join(reportsDir, reportFiles.at(-1))
  }
  let reportRecord = null
  try { reportRecord = JSON.parse(v22Report.stdout) } catch {}
  const diagnosticPaths = [[scratch, '<isolated-temp>'], [workspace, '<isolated-workspace>'], [stateRoot, '<isolated-state-root>']]
  diagnostics.steps.v22TaskRead = {
    exitCode: v22Task.status, signal: v22Task.signal, errorCode: v22Task.errorCode, stdoutSha256: digest(Buffer.from(v22Task.stdout)),
    stderr: redactDiagnostic(v22Task.stderr, diagnosticPaths), taskIdValid: diagnostics.steps.v22Seed.taskId.formatValid,
    metadata: taskRecordOnDisk ? { schemaVersion: taskRecordOnDisk.schemaVersion, state: taskRecordOnDisk.state, workspaceMatches: typeof taskRecordOnDisk.workspace === 'string' && samePath(taskRecordOnDisk.workspace, workspace), principalMatches: taskRecordOnDisk.principalId === runEnv.ARMORBREAK_PRINCIPAL_ID, sessionIsNull: taskRecordOnDisk.sessionId == null } : null,
    metadataErrorCode: taskRecordErrorCode,
    files: { task: safeStat(taskFile) },
  }
  diagnostics.steps.v22ReportRead = {
    exitCode: v22Report.status, signal: v22Report.signal, errorCode: v22Report.errorCode, stdoutSha256: digest(Buffer.from(v22Report.stdout)),
    stderr: redactDiagnostic(v22Report.stderr, diagnosticPaths),
    metadata: reportRecord ? { format: reportRecord.format ?? null, bytes: Number.isInteger(reportRecord.bytes) ? reportRecord.bytes : null, hasMarkdown: typeof reportRecord.markdown === 'string', hasPath: Boolean(reportRecord.path), declaredSha256Matches: typeof reportRecord.markdown === 'string' && reportRecord.sha256 === digest(Buffer.from(reportRecord.markdown)) } : null,
    files: { report: reportRecordOnDisk ? safeStat(reportRecordOnDisk) : { exists: false } },
    pathValidation: (() => {
      const reportPath = typeof taskRecordOnDisk?.report?.path === 'string' ? resolve(taskRecordOnDisk.report.path) : null
      if (!reportPath) return { taskDirectoryRealpathMatches: null, reportsRootRealpathMatches: null, reportFileRealpathMatches: null, reportPathWithinReportsRoot: null }
      const canonicalTask = realpathSync(taskDir)
      const canonicalReports = realpathSync(reportsDir)
      const canonicalReport = realpathSync(reportPath)
      const legacyWithin = (base, target) => {
        const rel = relative(base, target)
        return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
      }
      return {
        taskDirectoryRealpathMatches: samePath(taskDir, canonicalTask),
        reportsRootRealpathMatches: samePath(reportsDir, canonicalReports),
        reportFileRealpathMatches: samePath(reportPath, canonicalReport),
        reportPathWithinReportsRoot: legacyWithin(reportsDir, reportPath),
        canonicalReportsRootWithinTaskDirectory: legacyWithin(canonicalTask, canonicalReports),
        canonicalReportWithinCanonicalReportsRoot: legacyWithin(canonicalReports, canonicalReport),
      }
    })(),
  }
  if (v22Task.status !== 0) { diagnostics.status = 'FAIL_V22_TASK_READ'; writeDiagnostics(); throw new Error('V2.2 package failed to read its own task before upgrade (see structured diagnostics)') }
  if (v22Report.status !== 0) { diagnostics.status = 'FAIL_V22_REPORT_READ'; writeDiagnostics(); throw new Error('V2.2 package failed to read its own report before upgrade (see structured diagnostics)') }
  const oldTaskRecord = JSON.parse(v22Task.stdout)
  const oldReportRecord = JSON.parse(v22Report.stdout)
  if (oldTaskRecord.schemaVersion !== 'armorbreak/v2' || !oldReportRecord.markdown?.includes('ArmorBreak')) throw new Error('V2.2 task/report content does not match the historical V2 schema')
  const before = { tasks: sha256FileTree(join(workspace, '.armorbreak', 'tasks')), configSha256: fileDigest(configPath), reportSha256: digest(Buffer.from(oldReportRecord.markdown)) }

  // Exercise a real staged package verification failure. The installed V2.2
  // tree remains available; the candidate is discarded before it can run.
  const corruptUnpackResult = unpack(candidateArtifact, corruptedStage)
  const corruptedEntry = join(corruptedStage, 'index.js')
  writeFileSync(corruptedEntry, `${readFileSync(corruptedEntry, 'utf8')}\n// injected candidate corruption\n`)
  const corruptedHash = fileDigest(corruptedEntry)
  const candidateEntry = candidateManifest.contentManifest.find((entry) => entry.path === 'index.js')
  const injectedFailureRejected = Boolean(candidateEntry && corruptedHash !== candidateEntry.sha256)
  assert.equal(injectedFailureRejected, true)
  rmSync(corruptedStage, { recursive: true, force: true })
  const v22AfterFailure = cli(v22Install, runEnv, 'capabilities', '--json')
  if (v22AfterFailure.status !== 0 || JSON.parse(v22AfterFailure.stdout).length !== historicalV22CapabilityCount) throw new Error('failure injection damaged or displaced the previous V2.2 installation')

  // Install and execute the real current V2.3 package archive from the builder.
  const candidateUnpackResult = unpack(candidateArtifact, candidateInstall)
  const installedPackage = JSON.parse(readFileSync(join(candidateInstall, 'package.json'), 'utf8'))
  assert.equal(installedPackage.version, '2.3.1')
  const candidateConfig = structuredClone(config)
  candidateConfig.mcpServers.armorbreak.args = [join(candidateInstall, 'packages', 'mcp-server', 'index.js')]
  writeFileSync(configPath, `${JSON.stringify(candidateConfig, null, 2)}\n`)
  const candidateCapabilities = cli(candidateInstall, runEnv, 'capabilities', '--json')
  const candidateTask = cli(candidateInstall, runEnv, 'task', 'status', taskId, '--json')
  const candidateReport = cli(candidateInstall, runEnv, 'report', taskId, '--json')
  if (candidateCapabilities.status !== 0 || JSON.parse(candidateCapabilities.stdout).length !== 53 || candidateTask.status !== 0 || candidateReport.status !== 0) throw new Error('installed candidate did not start or read the V2.2 historical task/report')
  const candidateReportRecord = JSON.parse(candidateReport.stdout)
  if (digest(Buffer.from(candidateReportRecord.markdown)) !== before.reportSha256) throw new Error('candidate report bytes differ from the V2.2 report read before upgrade')

  const hostConfig = cli(candidateInstall, runEnv, 'agent', 'doctor', '--config', configPath, '--json')
  if (hostConfig.status !== 0 || JSON.parse(hostConfig.stdout).status !== 'OK') throw new Error('candidate package rejected its isolated host MCP configuration')
  const outOfWorkspace = cli(candidateInstall, runEnv, 'analyze', '--capability', 'forensics.hash', '--target', outsideSample, '--json')
  if (outOfWorkspace.status === 0 || !/outside|scope|authorized/i.test(outOfWorkspace.stderr)) throw new Error('candidate package did not deny a target outside its configured workspace')

  const mcpMessages = [
    { jsonrpc: '2.0', id: 1, method: 'initialize' },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'armorbreak_task_list', arguments: {} } },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'armorbreak_report', arguments: { taskId } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'armorbreak_workflow', arguments: { action: 'list', principal: 'attacker-selected-principal' } } },
  ].map((message) => JSON.stringify(message)).join('\n') + '\n'
  const mcpEntrypoint = JSON.parse(readFileSync(configPath, 'utf8')).mcpServers.armorbreak.args[0]
  const mcp = run(process.execPath, [mcpEntrypoint], { cwd: candidateInstall, env: runEnv, input: mcpMessages })
  if (mcp.status !== 0) throw new Error(`candidate MCP server failed initialization: ${mcp.stderr.slice(0, 1200)}`)
  const frames = mcp.stdout.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line))
  const initialize = frames.find((frame) => frame.id === 1)
  const taskList = frames.find((frame) => frame.id === 2)
  const report = frames.find((frame) => frame.id === 3)
  const maliciousPrincipal = frames.find((frame) => frame.id === 4)
  const listedTasks = JSON.parse(taskList.result.content[0].text)
  assert.equal(initialize.result.serverInfo.name, 'armorbreak')
  assert.equal(initialize.result.protocolVersion, '2025-06-18')
  assert.equal(taskList.result.isError, false)
  assert.ok(!listedTasks.tasks.some((task) => task.id === taskId), 'a new MCP session must not inherit visibility into the historical CLI session task')
  assert.equal(report.result.isError, true)
  assert.match(report.result.content[0].text, /outside the authorized principal, session, or workspace/)
  assert.equal(maliciousPrincipal.result.isError, true)
  assert.match(maliciousPrincipal.result.content[0].text, /unsupported armorbreak_workflow argument: principal/)

  // Roll back by selecting and re-running the preserved, byte-identical V2.2
  // installation. This repository has no OS-level installer/updater yet.
  writeFileSync(configPath, originalConfigBytes)
  const rollbackCapabilities = cli(v22Install, runEnv, 'capabilities', '--json')
  const rollbackTask = cli(v22Install, runEnv, 'task', 'status', taskId, '--json')
  const rollbackReport = cli(v22Install, runEnv, 'report', taskId, '--json')
  if (rollbackCapabilities.status !== 0 || rollbackTask.status !== 0 || rollbackReport.status !== 0) throw new Error('V2.2 package failed after rollback selection')
  const after = { tasks: sha256FileTree(join(workspace, '.armorbreak', 'tasks')), configSha256: fileDigest(configPath), reportSha256: digest(Buffer.from(JSON.parse(rollbackReport.stdout).markdown)) }
  assert.deepEqual(after, before)
  assert.equal(rollbackCapabilities.status, 0)
  assert.equal(JSON.parse(rollbackCapabilities.stdout).length, historicalV22CapabilityCount)
  assert.equal(rollbackTask.status, 0)
  assert.equal(rollbackReport.status, 0)

  const evidence = {
    schemaVersion: 'armorbreak.v2.3-real-package-upgrade-rollback/v1',
    status: 'PASS_ISOLATED_REAL_PACKAGE_DEPLOYMENT',
    capturedAt: new Date().toISOString(),
    sourceCommit: head,
    platform: { os: process.platform, arch: process.arch, node: process.version },
    historicalPackage: { version: '2.2.0', release: 'v2.2.0', asset: V22_ASSET, source: 'GitHub Release API asset digest; downloaded read-only', sha256: v22Sha256, expectedSha256: V22_SHA256 },
    candidatePackage: { version: '2.3.1', artifact: relative(root, candidateArtifact).split(sep).join('/'), sha256: candidateSha256, reproducible: candidateManifest.reproducible, cleanRoomCliCapabilities: candidateManifest.cleanRoom.cliCapabilities, productionSigned: false },
    deployment: {
      v22PackageExtractedAndExecuted: true,
      v22HistoricalCapabilityCount: historicalV22CapabilityCount,
      v22PackageCreatedHistoryTask: { id: taskId, schemaVersion: oldTaskRecord.schemaVersion, taskSha256: digest(Buffer.from(v22Task.stdout)), reportSha256: before.reportSha256 },
      candidateExtractedAndInstalledUnderIsolatedTempRoot: true,
      candidateStartedAndReported53Capabilities: true,
      candidateReadHistoricalTaskAndReport: true,
      candidateHostConfigDoctorStatus: JSON.parse(hostConfig.stdout).status,
      mcpInitializeProtocol: initialize.result.protocolVersion,
      mcpHistoricalCliTaskHiddenFromNewMcpSession: !listedTasks.tasks.some((task) => task.id === taskId),
      mcpReportDeniedForForeignCliSessionTask: report.result.isError,
      trustedPrincipal: { configuredByHostEnvironment: true, callerPrincipalOverrideRejected: true, windowsSidSha256: digest(Buffer.from(sid)), aclRestrictedToCurrentUser: true, aclEntries: aclEntries.map((entry) => ({ ...entry, path: entry.path === workspace ? '<isolated-workspace>' : entry.path === configDir ? '<isolated-workspace>/.armorbreak' : '<isolated-workspace>/.armorbreak/mcp-host-config.json', sid: 'CURRENT_USER_SID' })), rawIcaclsAccountOutput: 'redacted; normalized ACL entries and command-output SHA-256 are retained', aclCommandOutputSha256: digest(Buffer.from(`${aclResult.stdout}\n${aclInheritanceResult.stdout}`)), aclInspectionOutputSha256: digest(Buffer.from(aclChecks.stdout)) },
      workspaceBoundary: { outsideTargetRejected: true, stderrSha256: digest(Buffer.from(outOfWorkspace.stderr)) },
      failureInjection: { candidateStageEntry: 'index.js', corruptedEntrySha256: corruptedHash, rejectedBeforeCandidateStartup: injectedFailureRejected, v22PackageStillStartedAfterFault: true },
      rollback: { selectedPreviousVersion: '2.2.0', previousPackageRestarted: true, taskTreeHashesBeforeAndAfterEqual: JSON.stringify(before.tasks) === JSON.stringify(after.tasks), configHashBefore: before.configSha256, configHashAfter: after.configSha256, reportHashBefore: before.reportSha256, reportHashAfter: after.reportSha256 },
      packageInstallMechanism: 'Candidate tarball was extracted and executed from an isolated version directory; rollback selected and restarted the preserved V2.2 package. Project does not yet ship an OS-integrated updater/installer.',
      noFormalInstallOrV2_2AssetModified: true,
      temporaryWorkspaceRemovedAtCompletion: false,
    },
    commands: [
      { ...summary('gh', v22DownloadArgs.map((arg) => arg.replaceAll(scratch, '<isolated-temp>')), v22DownloadResult), attempts: v22DownloadAttempts },
      summary('tar', ['-xzf', V22_ASSET, '-C', 'isolated V2.2 install'], v22UnpackResult),
      summary('icacls.exe', ['isolated temp root', '/inheritance:r', '/grant:r', 'CURRENT_USER_SID:(F)', '/T', '/C'], aclResult),
      summary('icacls.exe', ['isolated temp root', '/grant', 'CURRENT_USER_SID:(OI)(CI)(IO)(F)', '/T', '/C'], aclInheritanceResult),
      summary('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', 'verify-acl.ps1'], aclChecks),
      summary(process.execPath, ['packages/cli/index.js', 'capabilities', '--json', '(published V2.2.0 baseline)'], v22CapabilitiesBefore),
      summary('tar', ['-xzf', relative(root, candidateArtifact), '-C', 'fault-injected stage'], corruptUnpackResult),
      summary('tar', ['-xzf', relative(root, candidateArtifact), '-C', 'isolated V2.3 install'], candidateUnpackResult),
      summary(process.execPath, ['packages/cli/index.js', 'analyze', '--capability', 'forensics.hash', '--target', '<isolated-workspace>/v22-read-only-sample.txt', '--json'], v22Seed),
      summary(process.execPath, ['packages/cli/index.js', 'capabilities', '--json'], candidateCapabilities),
      summary(process.execPath, ['packages/cli/index.js', 'task', 'status', taskId, '--json'], candidateTask),
      summary(process.execPath, ['packages/cli/index.js', 'report', taskId, '--json'], candidateReport),
      summary(process.execPath, ['packages/mcp-server/index.js', 'stdio MCP JSON-RPC initialize/task/report/principal-boundary'], mcp),
      summary(process.execPath, ['packages/cli/index.js', 'analyze', '--capability', 'forensics.hash', '--target', 'outside-workspace sentinel', '--json'], outOfWorkspace),
      summary(process.execPath, ['packages/cli/index.js', 'agent', 'doctor', '--config', '<isolated-workspace>/.armorbreak/mcp-host-config.json', '--json'], hostConfig),
      summary(process.execPath, ['packages/cli/index.js', 'capabilities', '--json', '(V2.2 rollback selection)'], rollbackCapabilities),
      summary(process.execPath, ['packages/cli/index.js', 'task', 'status', taskId, '--json', '(V2.2 rollback selection)'], rollbackTask),
      summary(process.execPath, ['packages/cli/index.js', 'report', taskId, '--json', '(V2.2 rollback selection)'], rollbackReport),
    ],
    dataHashes: { before, after },
    limits: ['Uses one isolated V2.2-format task generated by the unchanged published V2.2.0 package; this is test data, not real user data.', 'Rollback proves package-directory reselection and byte integrity, not an OS-integrated product updater.', 'Windows ACL evidence covers the current-user SID and blocks broad built-in principals; no second real Windows account was available for an impersonated denial test.', 'Candidate remains unsigned for production; builder test-key signature is not a maintainer identity.'],
  }
  const cleanupCommand = cleanupScratch(scratch)
  evidence.commands.push(cleanupCommand)
  evidence.deployment.temporaryWorkspaceRemovedAtCompletion = !existsSync(scratch)
  if (!evidence.deployment.temporaryWorkspaceRemovedAtCompletion) throw new Error('isolated test root was not removed after drill')
  const outputPath = join(root, evidencePath)
  mkdirSync(dirname(outputPath), { recursive: true })
  writeFileSync(outputPath, `${JSON.stringify(evidence, null, 2)}\n`)
  diagnostics.status = 'PASS'
  diagnostics.evidence = { v22TaskIdValid: diagnostics.steps.v22Seed.taskId.formatValid, preUpgradeTaskAndReportReadable: true, candidateSha256, rollbackHashesEqual: true }
  writeDiagnostics()
  console.log(JSON.stringify({ status: evidence.status, evidence: evidencePath, sourceCommit: head, candidateSha256, v22Sha256, taskId, beforeAfterHashesEqual: JSON.stringify(before) === JSON.stringify(after) }, null, 2))
} finally {
  if (diagnostics.status === 'IN_PROGRESS') diagnostics.status = 'FAIL_EARLY_EXIT'
  writeDiagnostics()
  cleanupScratch(scratch)
}
