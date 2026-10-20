/**
 * External tool adapter layer (Stage B, first batch).
 *
 * Implements the v2 adapter shape in a lightweight way:
 *   detect/execute is `execFile` with argv arrays (never a shell);
 *   normalize maps tool JSON into the same findings/evidence model as the
 *   built-in analyzers, keeping severity / confidence / verification separate.
 *
 * Semgrep and Trivy are REQUIRED to be installed by the operator. Missing tools
 * produce actionable guidance instead of a silent downgrade. The `env.execExternal`
 * hook exists only for tests; the runner never sets it.
 * @module dsh-armorbreak/lib/analyzers/external/adapters
 */
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'

export const EXTERNAL_TOOL_GUIDANCE = Object.freeze({
  semgrep: 'Install Semgrep (https://semgrep.dev/docs/getting-started/) and pass a local rule path via options.config. No rule download is performed by ArmorBreak.',
  trivy: 'Install Trivy (https://trivy.dev/latest/getting-started/installation/) and prepare a local vulnerability DB (trivy fs --download-db-only once). ArmorBreak will not auto-download a DB.',
})

/** Minimal env for child processes: never forward the host's full environment. */
function childEnv() {
  /** @type {Record<string, string>} */
  const env = {}
  for (const key of ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'PATHEXT', 'ComSpec', 'COMSPEC']) {
    if (typeof process.env[key] === 'string') env[key] = process.env[key]
  }
  return env
}

/** @param {Buffer|string} value */
function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

/**
 * Execute an external tool with a bounded argv call.
 * @param {any} env capability env (may contain the test seam `execExternal`)
 * @param {string} command
 * @param {string[]} args
 * @param {{timeoutMs?: number, maxOutputBytes?: number}} [limits]
 */
export async function executeExternal(env, command, args, limits = {}) {
  const timeoutMs = Math.max(1000, Math.min(Number(limits.timeoutMs ?? 60_000), 600_000))
  const maxOutputBytes = Math.max(1024 * 1024, Math.min(Number(limits.maxOutputBytes ?? 8 * 1024 * 1024), 32 * 1024 * 1024))
  if (typeof env?.execExternal === 'function') {
    const result = await env.execExternal(command, args, { timeoutMs })
    return { stdout: String(result?.stdout ?? ''), stderr: String(result?.stderr ?? ''), exitCode: Number(result?.exitCode ?? 0) }
  }
  return await new Promise((resolve, reject) => {
    execFile(command, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: maxOutputBytes, env: childEnv() }, (error, stdout, stderr) => {
      if (error) {
        if (/** @type {any} */ (error).code === 'ENOENT') {
          reject(new Error(`${command} is not installed or not on PATH. ${EXTERNAL_TOOL_GUIDANCE[command] ?? ''}`.trim()))
          return
        }
        const exitCode = typeof /** @type {any} */ (error).code === 'number' ? /** @type {any} */ (error).code : null
        reject(new Error(`${command} failed (exit=${exitCode}): ${String(stderr ?? '').slice(0, 800) || String(/** @type {any} */ (error).message ?? error).slice(0, 800)}`))
        return
      }
      resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), exitCode: 0 })
    })
  })
}

/** @param {string} value */
function asText(value) {
  return typeof value === 'string' ? value : ''
}

/** @param {string} severity */
function mapSeverity(severity) {
  const value = String(severity ?? '').trim().toLowerCase()
  if (value === 'error' || value === 'critical') return 'critical'
  if (value === 'warning' || value === 'high') return 'high'
  if (value === 'medium') return 'medium'
  if (value === 'low') return 'low'
  return 'info'
}

/** @param {string} raw */
function parseJson(raw, tool) {
  try {
    return JSON.parse(raw)
  } catch {
    throw new Error(`${tool} output is not valid JSON; refusing to normalize an unparsable report`)
  }
}

/**
 * Normalize a Semgrep `--json` report.
 * @param {string} raw
 * @param {{maxFindings?: number}} [options]
 */
export function parseSemgrepReport(raw, options = {}) {
  const report = parseJson(raw, 'semgrep')
  if (!report || typeof report !== 'object' || !Array.isArray(report.results)) {
    throw new Error('semgrep output JSON is not a Semgrep report (missing results array)')
  }
  const results = report.results
  const maxFindings = Math.max(1, Math.min(Number(options.maxFindings ?? 200), 1000))
  /** @type {any[]} */
  const findings = []
  /** @type {any[]} */
  const evidence = []
  for (const [index, item] of results.slice(0, maxFindings).entries()) {
    const extra = item?.extra ?? {}
    const path = asText(item?.path) || '(unknown)'
    const startLine = Number(item?.start?.line ?? 0) || null
    const endLine = Number(item?.end?.line ?? 0) || null
    const checkId = asText(item?.check_id) || 'semgrep.unknown'
    const message = asText(extra.message).split(/\r?\n/)[0].slice(0, 300)
    const lineText = asText(extra.lines).split(/\r?\n/)[0].slice(0, 300)
    const cweValues = Array.isArray(extra?.metadata?.cwe) ? extra.metadata.cwe : []
    const cwe = cweValues.length > 0 ? String(cweValues[0]).slice(0, 40) : null
    findings.push({
      title: `[semgrep] ${message || checkId}`.slice(0, 200),
      severity: mapSeverity(extra.severity),
      description: message || `Semgrep rule ${checkId} matched`,
      verification: 'hypothesis',
      confidence: 'medium',
      method: 'semgrep rule match (static pattern; no data-flow validation)',
      cwe,
      cvss: null,
      remediation: 'Review the rule match against the actual data flow; do not report as a confirmed vulnerability without independent evidence.',
      target: startLine ? `${path}:${startLine}` : path,
      sourceTool: 'semgrep',
      sourceRule: checkId,
      location: { file: path, startLine, endLine },
      evidence: [{ title: `semgrep ${checkId}`, excerpt: `${path}:${startLine ?? '?'} ${lineText}`.slice(0, 800) }],
    })
    evidence.push({
      title: `semgrep result ${index + 1} (${checkId})`,
      kind: 'external-tool',
      excerpt: `${path}:${startLine ?? '?'}-${endLine ?? '?'} severity=${extra.severity ?? '?'} message=${message}`.slice(0, 900),
      meta: { tool: 'semgrep', rule: checkId, file: path, startLine },
    })
  }
  return {
    findings,
    evidence,
    data: {
      tool: 'semgrep',
      toolVersion: asText(report?.version) || null,
      resultCount: results.length,
      reportedFindings: findings.length,
      truncated: results.length > maxFindings,
      errors: Array.isArray(report?.errors) ? report.errors.length : 0,
      scannedPaths: Array.isArray(report?.paths?.scanned) ? report.paths.scanned.length : null,
    },
  }
}

/**
 * Normalize a Trivy `fs --format json` report (vulnerabilities, secrets, misconfigurations).
 * @param {string} raw
 * @param {{maxFindings?: number}} [options]
 */
export function parseTrivyReport(raw, options = {}) {
  const report = parseJson(raw, 'trivy')
  if (!report || typeof report !== 'object' || !Array.isArray(report.Results)) {
    throw new Error('trivy output JSON is not a Trivy report (missing Results array)')
  }
  const results = report.Results
  const maxFindings = Math.max(1, Math.min(Number(options.maxFindings ?? 200), 1000))
  /** @type {any[]} */
  const findings = []
  /** @type {any[]} */
  const evidence = []
  const kinds = new Set()
  const push = (finding, excerpt) => {
    if (findings.length >= maxFindings) return
    findings.push(finding)
    evidence.push({ title: finding.title.slice(0, 120), kind: 'external-tool', excerpt: String(excerpt).slice(0, 900), meta: { tool: 'trivy', rule: finding.sourceRule, file: finding.location?.file } })
  }
  for (const result of results) {
    const target = asText(result?.Target) || '(unknown)'
    const kind = asText(result?.Class) || asText(result?.Type) || 'unknown'
    kinds.add(kind)
    for (const item of Array.isArray(result?.Vulnerabilities) ? result.Vulnerabilities : []) {
      const score = Number(item?.CVSS?.nvd?.V3Score ?? item?.CVSS?.redhat?.V3Score ?? NaN)
      push({
        title: `[trivy] ${asText(item?.VulnerabilityID) || 'CVE'} in ${asText(item?.PkgName) || 'package'}`.slice(0, 200),
        severity: mapSeverity(item?.Severity),
        description: asText(item?.Title) || asText(item?.Description) || 'Dependency vulnerability reported by Trivy',
        verification: 'hypothesis',
        confidence: 'medium',
        method: 'trivy vulnerability DB match (version range; no exploit validation)',
        cwe: Array.isArray(item?.CweIDs) && item.CweIDs.length > 0 ? String(item.CweIDs[0]).slice(0, 40) : null,
        cvss: Number.isFinite(score) ? score : null,
        remediation: item?.FixedVersion ? `Upgrade ${asText(item.PkgName)} to ${asText(item.FixedVersion)}` : 'No fixed version published; mitigate or replace the dependency.',
        target: `${target} (${asText(item?.PkgName)})`,
        sourceTool: 'trivy',
        sourceRule: asText(item?.VulnerabilityID) || null,
        location: { file: target, package: asText(item?.PkgName), installedVersion: asText(item?.InstalledVersion), fixedVersion: asText(item?.FixedVersion) || null, kind: 'dependency' },
        evidence: [{ title: 'trivy vulnerability', excerpt: `${item?.VulnerabilityID} ${item?.PkgName} ${item?.InstalledVersion}`.slice(0, 500) }],
      }, `${target} ${item?.VulnerabilityID ?? ''} ${item?.PkgName ?? ''} ${item?.InstalledVersion ?? ''} -> ${item?.FixedVersion ?? 'no-fix'}`)
    }
    for (const item of Array.isArray(result?.Secrets) ? result.Secrets : []) {
      push({
        title: `[trivy] secret ${asText(item?.RuleID) || 'match'} in ${target}`.slice(0, 200),
        severity: mapSeverity(item?.Severity),
        description: asText(item?.Title) || 'Trivy detected a secret-like value; verify whether it is a real credential.',
        verification: 'hypothesis',
        confidence: 'low',
        method: 'trivy secret pattern match (may be a test fixture or example)',
        cwe: null,
        cvss: null,
        remediation: 'Confirm the value is a live credential; rotate it if so. Ignore documented test/example values.',
        target,
        sourceTool: 'trivy',
        sourceRule: asText(item?.RuleID) || null,
        location: { file: target, startLine: Number(item?.StartLine ?? 0) || null, kind: 'secret' },
        evidence: [{ title: 'trivy secret', excerpt: `${item?.RuleID ?? ''} ${item?.Title ?? ''} line=${item?.StartLine ?? '?'}`.slice(0, 500) }],
      }, `${target} ${item?.RuleID ?? ''} line=${item?.StartLine ?? '?'} (value redacted)`)
    }
    for (const item of Array.isArray(result?.Misconfigurations) ? result.Misconfigurations : []) {
      push({
        title: `[trivy] ${asText(item?.ID) || 'misconfiguration'} ${asText(item?.Title) || ''}`.slice(0, 200),
        severity: mapSeverity(item?.Severity),
        description: asText(item?.Message) || asText(item?.Title) || 'Trivy misconfiguration check failed',
        verification: 'hypothesis',
        confidence: 'medium',
        method: 'trivy IaC/config check',
        cwe: null,
        cvss: null,
        remediation: asText(item?.Resolution) || 'Review the configuration and apply the documented fix.',
        target,
        sourceTool: 'trivy',
        sourceRule: asText(item?.ID) || null,
        location: { file: target, startLine: Number(item?.CauseMetadata?.StartLine ?? 0) || null, kind: 'configuration' },
        evidence: [{ title: 'trivy misconfiguration', excerpt: `${item?.ID ?? ''} ${item?.Title ?? ''}`.slice(0, 500) }],
      }, `${target} ${item?.ID ?? ''} ${item?.Title ?? ''}`)
    }
  }
  return {
    findings,
    evidence,
    data: {
      tool: 'trivy',
      toolVersion: asText(report?.SchemaVersion) ? `schema-${report.SchemaVersion}` : null,
      resultCount: results.length,
      reportedFindings: findings.length,
      truncated: findings.length >= maxFindings,
      kinds,
    },
  }
}

/**
 * Semgrep capability: run the installed CLI against a directory with a local rule set.
 */
export const semgrepCapability = {
  id: 'sast.semgrep',
  title: 'Semgrep 外部规则扫描（JSON 归一化，L0）',
  description:
    '调用本机已安装的 Semgrep 对目录做规则扫描，并将 --json 输出归一化为统一 findings/evidence。必须提供本地规则路径 options.config；不会联网拉规则。规则命中一律 hypothesis，需人工复核后才可升级。Semgrep 未安装时返回安装指引，不使用内置规则冒充外部结果。',
  riskLevel: 'L0',
  targetKind: 'directory',
  externalTools: ['semgrep'],
  params: {
    type: 'object',
    properties: {
      config: { type: 'string', description: 'Local Semgrep rule file or directory (required; no auto-fetch).' },
      maxFindings: { type: 'integer', minimum: 1, maximum: 1000, description: 'Maximum normalized findings. Default 200.' },
      timeoutMs: { type: 'number', description: 'Execution timeout in ms (default 120000, max 600000).' },
    },
    required: ['config'],
    additionalProperties: false,
  },
  async run(input) {
    const options = input.options ?? {}
    const target = String(input.targetPath ?? '')
    if (!target) throw new Error('sast.semgrep needs a directory target')
    const config = String(options.config ?? '').trim()
    if (!config) throw new Error('sast.semgrep needs options.config: a local Semgrep rule path (no network rule fetch)')
    const timeoutMs = Math.max(10_000, Math.min(Number(options.timeoutMs ?? 120_000), 600_000))
    const { stdout, stderr } = await executeExternal(input.env, 'semgrep', ['scan', '--json', '--quiet', '--config', config, target], { timeoutMs })
    const parsed = parseSemgrepReport(stdout, { maxFindings: options.maxFindings })
    return {
      summary: `Semgrep（${parsed.data.toolVersion ?? 'unknown version'}）扫描 ${target}：${parsed.data.resultCount} 条结果，归一化 ${parsed.findings.length} 条 findings（全部 hypothesis）`,
      data: { ...parsed.data, target, stderr: stderr.slice(0, 500), ruleConfig: config },
      findings: parsed.findings,
      evidence: [
        ...parsed.evidence,
        { title: 'semgrep invocation', kind: 'external-tool', excerpt: `command=semgrep scan --json --config ${config} ${target} sha256(stdout)=${sha256(stdout)}` },
      ],
      meta: { capability: 'sast.semgrep', externalTool: 'semgrep', targetKind: 'directory', verificationDefault: 'hypothesis' },
    }
  },
}

/**
 * Trivy capability: run `trivy fs --format json` and normalize vulnerabilities,
 * secrets and misconfigurations. Uses the local vulnerability DB only.
 */
export const trivyCapability = {
  id: 'sast.trivy',
  title: 'Trivy 文件系统/依赖扫描（JSON 归一化，L0）',
  description:
    '调用本机已安装的 Trivy 对目录执行 fs 扫描，并将 JSON 报告归一化为统一 findings/evidence（漏洞/密钥/配置）。默认使用本地漏洞库并禁止自动下载；CVSS 与严重度取自工具输出，但所有发现默认 hypothesis，版本命中不等于可利用。Trivy 未安装或本地库缺失时返回明确指引。',
  riskLevel: 'L0',
  targetKind: 'directory',
  externalTools: ['trivy'],
  params: {
    type: 'object',
    properties: {
      scanners: { type: 'string', description: 'Comma-separated scanners (default "vuln,secret").' },
      severity: { type: 'string', description: 'Comma-separated severities (default "HIGH,CRITICAL").' },
      downloadDb: { type: 'boolean', description: 'When true, allow trivy to download a DB (requires network). Default false.' },
      maxFindings: { type: 'integer', minimum: 1, maximum: 1000, description: 'Maximum normalized findings. Default 200.' },
      timeoutMs: { type: 'number', description: 'Execution timeout in ms (default 180000, max 600000).' },
    },
    additionalProperties: false,
  },
  async run(input) {
    const options = input.options ?? {}
    const target = String(input.targetPath ?? '')
    if (!target) throw new Error('sast.trivy needs a directory target')
    const scanners = String(options.scanners ?? 'vuln,secret')
    const severity = String(options.severity ?? 'HIGH,CRITICAL')
    const timeoutMs = Math.max(10_000, Math.min(Number(options.timeoutMs ?? 180_000), 600_000))
    const args = ['fs', '--format', 'json', '--quiet', '--scanners', scanners, '--severity', severity]
    if (options.downloadDb !== true) args.push('--skip-db-update')
    args.push(target)
    const { stdout, stderr } = await executeExternal(input.env, 'trivy', args, { timeoutMs })
    const parsed = parseTrivyReport(stdout, { maxFindings: options.maxFindings })
    return {
      summary: `Trivy 扫描 ${target}：${parsed.data.resultCount} 个结果集，归一化 ${parsed.findings.length} 条 findings（scanners=${scanners}, severity=${severity}，全部 hypothesis）`,
      data: { ...parsed.data, target, stderr: stderr.slice(0, 500), scanners, severity, dbDownloadAllowed: options.downloadDb === true },
      findings: parsed.findings,
      evidence: [
        ...parsed.evidence,
        { title: 'trivy invocation', kind: 'external-tool', excerpt: `command=trivy ${args.join(' ')} sha256(stdout)=${sha256(stdout)}` },
      ],
      meta: { capability: 'sast.trivy', externalTool: 'trivy', targetKind: 'directory', verificationDefault: 'hypothesis', offlineDb: options.downloadDb !== true },
    }
  },
}
