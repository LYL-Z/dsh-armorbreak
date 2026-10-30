/**
 * Report engine: Markdown / HTML / JSON / SARIF / PDF (via a detected
 * LibreOffice) rendering from a task's durable evidence, findings, and audit.
 * @module dsh-armorbreak/lib/core/reports
 */
import { execFile } from 'node:child_process'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { readSafeRepoFile } from '../../../lib/release/safeEvidenceFile.js'
import { escapeHtml, nowIso, sanitizeText, sha256 } from './util.js'
import { SEVERITY_SCORE } from './evidence.js'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/** @param {string} value */
function slug(value) {
  return String(value ?? 'report')
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'report'
}

/** @param {string} level */
function sarifLevel(level) {
  if (level === 'critical' || level === 'high') return 'error'
  if (level === 'medium') return 'warning'
  return 'note'
}

/** @param {string|null} cwe */
function cweUrl(cwe) {
  if (!cwe) return null
  const id = cwe.replace(/^CWE-?/i, '')
  return `https://cwe.mitre.org/data/definitions/${id}.html`
}

/**
 * Collect every input a report renderer needs.
 * @param {import('./runtime.js').ArmorBreakRuntime} runtime
 * @param {any} task
 */
async function collect(runtime, task) {
  const ctx = runtime.workspace(task.workspace)
  const store = ctx.taskStore
  const evidenceStore = store.evidenceStore(task.id)
  const [evidence, findingsState, audit, chain, environment, policy] = await Promise.all([
    evidenceStore.readEvidence(10000),
    evidenceStore.readFindings(),
    ctx.audit.read({ taskId: task.id, limit: 500 }),
    evidenceStore.verifyChain(),
    runtime.health.environment(),
    ctx.scope.snapshot(),
  ])
  const findings = [...findingsState.findings].sort((a, b) => {
    const bySeverity = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    return bySeverity !== 0 ? bySeverity : String(a.id).localeCompare(String(b.id))
  })
  return { task, evidence, findings, audit, chain, environment, policy }
}

/** @param {Array<{severity: string}>} findings */
function severityCounts(findings) {
  /** @type {Record<string, number>} */
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1
  return counts
}

/** @param {number} count */
function plural(count, one, many) {
  return `${count} ${count === 1 ? one : many}`
}

/**
 * @param {Awaited<ReturnType<typeof collect>>} data
 */
function renderMarkdown(data) {
  const { task, evidence, findings, audit, chain, environment, policy } = data
  const counts = severityCounts(findings)
  const lines = []
  lines.push(`# ArmorBreak 安全研究报告 — ${task.title}`)
  lines.push('')
  lines.push(`- 报告 ID：\`${task.id}\``)
  lines.push(`- 生成时间：${nowIso()}`)
  lines.push(`- 任务状态：**${task.state}**${task.workflowId ? `（工作流 ${task.workflowId}）` : ''}`)
  lines.push(`- 工作区：\`${task.workspace}\``)
  lines.push(`- 目标：\`${task.targetPath ?? '(none)'}\``)
  lines.push(`- 操作者：${task.operator}`)
  lines.push(`- 证据链：${chain.valid ? '校验通过' : `**损坏**（第 ${chain.brokenAt} 条：${chain.reason}）`}，${plural(chain.records, '条记录', '条记录')}`)
  lines.push('')
  lines.push('## 1. 摘要')
  lines.push('')
  lines.push(`共 ${plural(findings.length, '条发现', '条发现')}：${['critical', 'high', 'medium', 'low', 'info'].map((level) => `${level} ${counts[level] ?? 0}`).join(' · ')}。留档证据 ${evidence.length} 条。`)
  lines.push('')
  if (findings.length > 0) {
    lines.push('| # | 严重程度 | 标题 | 验证状态 | CWE | 位置 |')
    lines.push('|---|---|---|---|---|---|')
    findings.forEach((finding, index) => {
      lines.push(`| ${index + 1} | ${finding.severity} | ${mdCell(finding.title)} | ${finding.verification} | ${finding.cwe ?? '-'} | ${mdCell(finding.target ?? '-')} |`)
    })
    lines.push('')
  }
  lines.push('## 2. 授权与范围')
  lines.push('')
  if ((policy.authorizations ?? []).length === 0) {
    lines.push('- 本任务未使用跨工作区授权；分析限制在任务工作区内。')
  } else {
    for (const authorization of policy.authorizations) {
      lines.push(`- \`${authorization.id}\` 用途：${authorization.purpose}；操作者：${authorization.operator}；路径：${(authorization.paths ?? []).join(', ') || '-'}；网络目标：${(authorization.networkTargets ?? []).map((target) => target.host).join(', ') || '-'}；上限：${authorization.riskCeiling}；${authorization.active ? '有效' : '已过期/已撤销'}`)
    }
  }
  if ((task.approvals ?? []).length > 0) {
    lines.push(`- 平台审批记录：${task.approvals.map((id) => `\`${id}\``).join(', ')}`)
  }
  lines.push('')
  lines.push('## 3. 任务与工作流')
  lines.push('')
  lines.push(`- 风险上限：${task.riskMax}`)
  lines.push(`- 状态轨迹：${(task.stateHistory ?? []).map((entry) => `${entry.state}(${entry.at})`).join(' → ')}`)
  lines.push('')
  if ((task.steps ?? []).length > 0) {
    lines.push('| 步骤 | 能力 | 状态 | 耗时 | 摘要 |')
    lines.push('|---|---|---|---|---|')
    for (const step of task.steps) {
      lines.push(`| ${step.id} | ${step.capabilityId} | ${step.status} | ${step.durationMs ? `${step.durationMs} ms` : '-'} | ${mdCell(step.error ?? step.summary ?? '')} |`)
    }
    lines.push('')
  }
  lines.push('## 4. 发现')
  lines.push('')
  if (findings.length === 0) {
    lines.push('没有记录到带证据的发现。这不等于目标安全：未覆盖的检测能力与未验证的假设见第 7 节。')
  }
  findings.forEach((finding, index) => {
    lines.push(`### 4.${index + 1} ${finding.title}`)
    lines.push('')
    lines.push(`- 编号：\`${finding.id}\``)
    lines.push(`- 严重程度：**${finding.severity}**（评分依据：${finding.cvss !== null ? `CVSS ${finding.cvss}` : `严重程度映射 ${SEVERITY_SCORE[finding.severity] ?? 'n/a'}`}）`)
    lines.push(`- 证据成熟度：**${finding.verification}**（observed=来源直接报告的事实；corroborated=不同来源族关联；hypothesis=来源推断；unverified=来源状态未知）`)
    lines.push(`- 漏洞验证：**${finding.vulnerabilityStatus ?? 'not_tested'}**（证据关联不等于独立复现）`)
    lines.push(`- CWE：${finding.cwe ? `${finding.cwe} — ${cweUrl(finding.cwe)}` : '未映射'}`)
    lines.push(`- 检测方法：${finding.method}`)
    lines.push(`- 定位：\`${finding.target ?? '-'}\``)
    lines.push('')
    lines.push(`**说明**：${finding.description || '（无）'}`)
    lines.push('')
    lines.push(`**影响**：${finding.impact || `基于 ${finding.severity} 级别的影响评估`}`)
    lines.push('')
    lines.push(`**修复/复核建议**：${finding.remediation || '（待补充）'}`)
    lines.push('')
    lines.push(`**证据**：${(finding.evidenceIds ?? []).map((id) => `\`${id}\``).join(', ') || '（无）'}`)
    lines.push('')
  })
  lines.push('## 5. 证据附录')
  lines.push('')
  if (evidence.length === 0) {
    lines.push('（无证据记录）')
  } else {
    lines.push('| # | 证据 ID | 类型 | 来源能力 | 目标 SHA-256 | 摘要 |')
    lines.push('|---|---|---|---|---|---|')
    evidence.forEach((item, index) => {
      lines.push(`| ${index + 1} | \`${item.id}\` | ${item.kind} | ${item.capabilityId ?? '-'} | ${item.targetSha256 ? `\`${item.targetSha256}\`` : '-'} | ${mdCell(item.excerpt ?? '')} |`)
    })
  }
  lines.push('')
  lines.push('## 6. 审计记录（脱敏）')
  lines.push('')
  lines.push('| 序号 | 时间 | 动作 | 详情 |')
  lines.push('|---|---|---|---|')
  for (const record of audit.slice(-60)) {
    lines.push(`| ${record.seq} | ${record.at} | ${record.action ?? '-'} | ${mdCell(JSON.stringify(record).slice(0, 400))} |`)
  }
  lines.push('')
  lines.push('## 7. 复现条件、限制与不确定性')
  lines.push('')
  lines.push(`- 运行环境：${environment.platform}/${environment.arch}，Node ${environment.node}，DSH ${environment.dshVersion}，Profile ${environment.profile ?? 'n/a'}。`)
  lines.push(`- 隔离提供者：${environment.isolation?.available ? environment.isolation.provider : '不可用（L1 动态分析保持拒绝）'}。`)
  lines.push('- 本报告仅基于离线静态分析能力；没有执行样本，也没有对未授权目标发起任何主动流量。')
  lines.push('- 启发式结论（verification=hypothesis/unverified）需要人工复核后再作为漏洞处置。')
  for (const note of task.notes ?? []) lines.push(`- ${note.note}`)
  lines.push('')
  lines.push('---')
  lines.push('')
  lines.push('由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成。证据哈希链与审计日志可复核；不包含伪造的工具输出。')
  return `${lines.join('\n')}\n`
}

/** @param {unknown} value */
export function escapeMarkdownTableCell(value) {
  return String(value ?? '')
    .replace(/\r\n?|\n/g, ' ')
    .slice(0, 400)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
}

const mdCell = escapeMarkdownTableCell

/**
 * @param {Awaited<ReturnType<typeof collect>>} data
 */
function renderHtml(data) {
  const { task, evidence, findings, audit } = data
  const counts = severityCounts(findings)
  const findingCards = findings
    .map((finding) => {
      return `<section class="finding sev-${escapeHtml(finding.severity)}">
  <h3>${escapeHtml(finding.title)} <span class="sev">${escapeHtml(finding.severity)}</span></h3>
  <p class="meta">${escapeHtml(finding.id)} · 验证 ${escapeHtml(finding.verification)} · ${escapeHtml(finding.cwe ?? 'CWE 未映射')} · 方法 ${escapeHtml(finding.method)}</p>
  <p>${escapeHtml(finding.description)}</p>
  ${finding.remediation ? `<p class="fix"><strong>修复建议：</strong>${escapeHtml(finding.remediation)}</p>` : ''}
  <p class="meta">定位：<code>${escapeHtml(finding.target ?? '-')}</code> · 证据：${(finding.evidenceIds ?? []).map((id) => `<code>${escapeHtml(id)}</code>`).join(' ')}</p>
</section>`
    })
    .join('\n')
  const evidenceRows = evidence
    .map((item) => `<tr><td><code>${escapeHtml(item.id)}</code></td><td>${escapeHtml(item.kind)}</td><td>${escapeHtml(item.capabilityId ?? '-')}</td><td><code>${escapeHtml(item.targetSha256 ?? '-')}</code></td><td>${escapeHtml((item.excerpt ?? '').slice(0, 300))}</td></tr>`)
    .join('\n')
  const stepRows = (task.steps ?? [])
    .map((step) => `<tr><td>${escapeHtml(step.id)}</td><td>${escapeHtml(step.capabilityId)}</td><td>${escapeHtml(step.status)}</td><td>${step.durationMs ? `${step.durationMs} ms` : '-'}</td><td>${escapeHtml((step.error ?? step.summary ?? '').slice(0, 200))}</td></tr>`)
    .join('\n')
  const auditRows = audit
    .slice(-40)
    .map((record) => `<tr><td>${record.seq}</td><td>${escapeHtml(record.at)}</td><td>${escapeHtml(record.action ?? '-')}</td><td><code>${escapeHtml(JSON.stringify(record).slice(0, 300))}</code></td></tr>`)
    .join('\n')
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ArmorBreak 报告 — ${escapeHtml(task.title)}</title>
<style>
:root{--bg:#f7f7f5;--fg:#1f2328;--muted:#5b636e;--card:#fff;--border:#e3e5e8;--accent:#7c3aed;--code:#f0f1f3}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e6e6e6;--muted:#9aa2ad;--card:#1e2126;--border:#2d3138;--accent:#a78bfa;--code:#24272d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.65 -apple-system,"Segoe UI",system-ui,"Microsoft YaHei",sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 24px 80px}h1{font-size:26px;margin:0 0 6px}h2{margin-top:38px;padding-bottom:8px;border-bottom:1px solid var(--border);font-size:19px}
.meta{color:var(--muted);font-size:13px}code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:12.5px;word-break:break-all}
.summary{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.pill{background:var(--card);border:1px solid var(--border);border-radius:999px;padding:4px 12px;font-size:13px}
.finding{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--muted);border-radius:10px;padding:16px 18px;margin:14px 0}
.sev-critical{border-left-color:#dc2626}.sev-high{border-left-color:#ea580c}.sev-medium{border-left-color:#d97706}.sev-low{border-left-color:#2563eb}.sev-info{border-left-color:#6b7280}
.sev{font-size:12px;text-transform:uppercase;border:1px solid var(--border);border-radius:6px;padding:1px 7px;margin-left:8px;vertical-align:middle}
table{border-collapse:collapse;width:100%;font-size:13px;background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}th{background:var(--code);font-weight:600}
footer{margin-top:48px;color:var(--muted);font-size:12px}
</style></head><body><main>
<h1>ArmorBreak 安全研究报告</h1>
<p class="meta">${escapeHtml(task.title)} · 任务 <code>${escapeHtml(task.id)}</code> · ${escapeHtml(nowIso())} · 状态 <strong>${escapeHtml(task.state)}</strong></p>
<div class="summary">${['critical', 'high', 'medium', 'low', 'info'].map((level) => `<span class="pill">${level}: ${counts[level] ?? 0}</span>`).join('')}<span class="pill">证据: ${evidence.length}</span><span class="pill">证据链: ${data.chain.valid ? '通过' : '损坏'}</span></div>
<h2>1. 摘要</h2><p>共 ${findings.length} 条发现，${evidence.length} 条证据。工作区 <code>${escapeHtml(task.workspace)}</code>，目标 <code>${escapeHtml(task.targetPath ?? '-')}</code>。</p>
<h2>2. 任务与工作流</h2><p class="meta">风险上限 ${escapeHtml(task.riskMax)} · 工作流 ${escapeHtml(task.workflowId ?? 'adhoc')}</p>
<table><thead><tr><th>步骤</th><th>能力</th><th>状态</th><th>耗时</th><th>摘要/错误</th></tr></thead><tbody>${stepRows || '<tr><td colspan="5">无步骤</td></tr>'}</tbody></table>
<h2>3. 发现</h2>${findingCards || '<p>没有记录到带证据的发现。这不等于目标安全。</p>'}
<h2>4. 证据</h2><table><thead><tr><th>ID</th><th>类型</th><th>能力</th><th>目标 SHA-256</th><th>摘要</th></tr></thead><tbody>${evidenceRows || '<tr><td colspan="5">无</td></tr>'}</tbody></table>
<h2>5. 审计（脱敏）</h2><table><thead><tr><th>#</th><th>时间</th><th>动作</th><th>记录</th></tr></thead><tbody>${auditRows || '<tr><td colspan="4">无</td></tr>'}</tbody></table>
<h2>6. 复现条件与限制</h2><ul>
<li>环境：${escapeHtml(data.environment.platform)}/${escapeHtml(data.environment.arch)} · Node ${escapeHtml(data.environment.node)} · DSH ${escapeHtml(data.environment.dshVersion)}</li>
<li>隔离提供者：${escapeHtml(data.environment.isolation?.available ? String(data.environment.isolation.provider) : '不可用')}</li>
<li>仅离线静态分析；未执行样本；未对未授权目标发起主动流量。</li>
<li>启发式结论需人工复核；verification=hypothesis/unverified 不得直接当作已确认漏洞。</li>
</ul>
<footer>由 DeepSeek Harness「破甲模式 (ArmorBreak)」生成 · 证据哈希链可复核</footer>
</main></body></html>
`
}

/**
 * @param {Awaited<ReturnType<typeof collect>>} data
 */
function renderJson(data) {
  return JSON.stringify(
    {
      schema: 'armorbreak/report/v1',
      generatedAt: nowIso(),
      generator: { name: 'dsh-armorbreak', version: '1.0.0' },
      environment: data.environment,
      policy: data.policy,
      task: data.task,
      findings: data.findings,
      evidence: data.evidence,
      audit: data.audit,
      evidenceChain: data.chain,
    },
    null,
    2,
  )
}

/**
 * @param {Awaited<ReturnType<typeof collect>>} data
 */
function renderSarif(data) {
  const { task, findings, environment } = data
  const rules = []
  const results = []
  const ruleIds = new Set()
  for (const finding of findings) {
    const ruleId = finding.cwe ?? `armorbreak/${finding.fingerprint.slice(0, 12)}`
    if (!ruleIds.has(ruleId)) {
      ruleIds.add(ruleId)
      rules.push({
        id: ruleId,
        name: finding.title.replace(/[^A-Za-z0-9]+/g, '_').slice(0, 80) || 'ArmorBreakFinding',
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description || finding.title },
        helpUri: cweUrl(finding.cwe) ?? undefined,
        properties: { tags: finding.cwe ? ['security', `external/cwe/${finding.cwe.toLowerCase()}`] : ['security'] },
      })
    }
    const evidenceById = new Map(data.evidence.map((item) => [item.id, item]))
    const relatedLocations = []
    for (const evidenceId of finding.evidenceIds ?? []) {
      const item = evidenceById.get(evidenceId)
      const location = item?.meta?.location
      if (!location || typeof location.uri !== 'string' || !location.uri) continue
      const primaryUri = parseReportTarget(finding.target)?.uri
      if (location.uri === primaryUri && location.startLine === parseReportTarget(finding.target)?.line) continue
      relatedLocations.push({
        id: relatedLocations.length + 1,
        message: { text: `${item.title}: ${item.excerpt}`.slice(0, 2000) },
        physicalLocation: {
          artifactLocation: { uri: location.uri },
          ...(Number.isSafeInteger(location.startLine) && location.startLine > 0 ? { region: { startLine: location.startLine, ...(Number.isSafeInteger(location.startColumn) && location.startColumn > 0 ? { startColumn: location.startColumn } : {}) } } : {}),
        },
      })
    }
    const parsedTarget = parseReportTarget(finding.target)
    results.push({
      ruleId,
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title} — ${finding.description || 'no description'} (verification: ${finding.verification})` },
      locations: parsedTarget
        ? [{ physicalLocation: { artifactLocation: { uri: parsedTarget.uri }, ...(parsedTarget.line ? { region: { startLine: parsedTarget.line, ...(parsedTarget.column ? { startColumn: parsedTarget.column } : {}) } } : {}) } }]
        : [],
      ...(relatedLocations.length ? { relatedLocations } : {}),
      properties: {
        severity: finding.severity,
        verification: finding.verification,
        evidenceStatus: finding.verification,
        vulnerabilityStatus: finding.vulnerabilityStatus ?? 'not_tested',
        method: finding.method,
        evidenceIds: finding.evidenceIds,
        remediation: finding.remediation,
        taskId: task.id,
      },
    })
  }
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'ArmorBreak',
              informationUri: 'https://github.com/deepseek-ai/deepseek-harness',
              rules,
            },
          },
          automationDetails: { id: `armorbreak/${task.id}` },
          originalUriBaseIds: { WORKSPACE: { uri: `file:///${String(task.workspace).replace(/\\/g, '/').replace(/^\//, '')}` } },
          invocations: [{ executionSuccessful: true, endTimeUtc: nowIso(), properties: { environment } }],
          results,
        },
      ],
    },
    null,
    2,
  )
}

/** Parse `path:line[:column]` while preserving Windows drive-letter colons. */
function parseReportTarget(target) {
  if (typeof target !== 'string' || !target.trim()) return null
  const match = /^(.*?):(\d+)(?::(\d+))?$/.exec(target)
  if (!match) return { uri: target.replace(/\\/g, '/'), line: null, column: null }
  return {
    uri: match[1].replace(/\\/g, '/'),
    line: Number(match[2]) || null,
    column: match[3] ? Number(match[3]) || null : null,
  }
}

/**
 * Generate one report file for a task.
 * @param {import('./runtime.js').ArmorBreakRuntime} runtime
 * @param {any} task
 * @param {{format?: 'markdown'|'html'|'json'|'sarif'|'pdf'}} [opts]
 */
export async function generateTaskReport(runtime, task, opts = {}) {
  const format = opts.format ?? 'markdown'
  const data = await collect(runtime, task)
  const dir = join(runtime.workspace(task.workspace).taskStore.taskDir(task.id), 'reports')
  await mkdir(dir, { recursive: true })
  const stamp = nowIso().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19)
  const base = `${slug(task.workflowId ?? task.title)}_${stamp}`
  if (format === 'markdown' || format === 'md') {
    const content = renderMarkdown(data)
    const file = join(dir, `${base}.md`)
    await writeFile(file, content, 'utf8')
    return { format: 'markdown', path: file, sha256: sha256(content), generatedAt: nowIso(), bytes: Buffer.byteLength(content) }
  }
  if (format === 'html') {
    const content = renderHtml(data)
    const file = join(dir, `${base}.html`)
    await writeFile(file, content, 'utf8')
    return { format: 'html', path: file, sha256: sha256(content), generatedAt: nowIso(), bytes: Buffer.byteLength(content) }
  }
  if (format === 'json') {
    const content = renderJson(data)
    const file = join(dir, `${base}.json`)
    await writeFile(file, content, 'utf8')
    return { format: 'json', path: file, sha256: sha256(content), generatedAt: nowIso(), bytes: Buffer.byteLength(content) }
  }
  if (format === 'sarif') {
    const content = renderSarif(data)
    const file = join(dir, `${base}.sarif.json`)
    await writeFile(file, content, 'utf8')
    return { format: 'sarif', path: file, sha256: sha256(content), generatedAt: nowIso(), bytes: Buffer.byteLength(content) }
  }
  if (format === 'pdf') {
    const htmlContent = renderHtml(data)
    const htmlFile = join(dir, `${base}.html`)
    await writeFile(htmlFile, htmlContent, 'utf8')
    const libreoffice = await runtime.health.probe('soffice', { version: true })
    if (!libreoffice.found) {
      throw new Error('PDF export unavailable: LibreOffice (soffice) is not installed. Install it, or export Markdown/HTML/JSON/SARIF instead (format=markdown|html|json|sarif).')
    }
    await new Promise((resolvePromise, reject) => {
      execFile(
        libreoffice.path,
        ['--headless', '--convert-to', 'pdf', '--outdir', dir, htmlFile],
        { timeout: 120_000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
        (error, stdout, stderr) => {
          if (error) {
            reject(new Error(`LibreOffice PDF conversion failed: ${error.message} ${String(stderr ?? '').slice(0, 400)}`))
          } else {
            resolvePromise(stdout)
          }
        },
      )
    })
    const pdfFile = join(dir, `${base}.pdf`)
    const pdf = readSafeRepoFile(dir, `${base}.pdf`, { maxBytes: Number.MAX_SAFE_INTEGER - 1 })
    if (!pdf.length) throw new Error('LibreOffice reported success but produced no PDF; use format=html instead')
    return { format: 'pdf', path: pdfFile, sha256: sha256(pdf), generatedAt: nowIso(), bytes: pdf.length }
  }
  throw new Error(`unsupported report format "${format}"; use markdown|html|json|sarif|pdf`)
}

export default { generateTaskReport }
