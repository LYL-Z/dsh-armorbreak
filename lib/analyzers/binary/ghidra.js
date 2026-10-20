/**
 * Ghidra headless adapter (v1.2.0).
 *
 * Runs `analyzeHeadless` with the bundled ExportSummary.java script, which emits
 * a bounded function/caller JSON. The adapter never decompiles source and never
 * writes program bytes; only names/addresses/counts are normalized. Findings
 * based on function names are hypothesis-level.
 * @module dsh-armorbreak/lib/analyzers/binary/ghidra
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { executeTool, parseJsonOutput, resolveGhidra, EXTERNAL_TOOL_GUIDANCE } from '../../core/externalTools.js'

const SCRIPT_DIR = fileURLToPath(new URL('../../../scripts/ghidra/', import.meta.url)).replace(/[\\/]+$/, '')

const SUSPICIOUS_NAMES = [
  { name: 'process-injection', pattern: /(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext)/i },
  { name: 'credential-access', pattern: /(?:CryptUnprotectData|LsaOpenPolicy|OpenProcessToken|CredRead|DuplicateTokenEx)/i },
  { name: 'persistence', pattern: /(?:RegSetValueEx|CreateService|StartService|ChangeServiceConfig)/i },
  { name: 'anti-debug', pattern: /(?:IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebugger)/i },
  { name: 'network', pattern: /(?:InternetOpen|WinHttpOpen|WSAStartup|URLDownloadToFile)/i },
]

/** @param {string} raw @param {{maxFunctions?:number,maxFindings?:number}} [options] */
export function parseGhidraSummary(raw, options = {}) {
  const report = parseJsonOutput(raw, 'ghidra')
  if (!report || typeof report !== 'object' || !Array.isArray(report.functions)) {
    throw new Error('ghidra output JSON is not an ArmorBreak ExportSummary (missing functions array)')
  }
  const maxFunctions = Math.max(1, Math.min(Number(options.maxFunctions ?? 500), 5000))
  const functions = report.functions.slice(0, maxFunctions).map((fn) => ({
    name: String(fn.name ?? '').slice(0, 200),
    entry: String(fn.entry ?? '').slice(0, 40),
    size: Number(fn.size ?? 0) || 0,
    external: Boolean(fn.external),
    thunk: Boolean(fn.thunk),
    callingConvention: String(fn.callingConvention ?? '').slice(0, 60),
    callers: Number(fn.callers ?? 0) || 0,
  }))
  const matched = {}
  for (const fn of functions) {
    for (const category of SUSPICIOUS_NAMES) {
      if (!category.pattern.test(fn.name)) continue
      matched[category.name] ??= []
      if (matched[category.name].length < 20) matched[category.name].push(fn.name)
    }
  }
  const findings = []
  if (Object.keys(matched).length > 0) {
    findings.push({
      title: `Ghidra 函数命名命中 ${Object.keys(matched).length} 类敏感 API`,
      severity: 'low',
      description: `命中类别：${Object.keys(matched).join('、')}。函数名来自导入/符号，可能被加壳或动态解析隐藏；必须结合调用图与参数复核，不能仅凭名称定性。`,
      verification: 'hypothesis',
      method: 'Ghidra analyzeHeadless 函数表 + 敏感名称正则（静态，不执行）',
      cwe: null,
      cvss: null,
      remediation: '在授权环境中复核调用点、参数与数据流；不要仅凭函数名定性。',
      target: null,
      evidence: [{ title: '敏感函数名称', kind: 'ghidra-function-names', excerpt: JSON.stringify(matched).slice(0, 2000), meta: {} }],
    })
  }
  findings.push({
    title: `Ghidra 枚举 ${report.functionCount ?? functions.length} 个函数（导出 ${functions.length}）`,
    severity: 'info',
    description: '函数数量与调用者计数来自 Ghidra 自动分析；结果受加载器、符号与反编译质量影响。',
    verification: 'observed',
    method: 'Ghidra analyzeHeadless ExportSummary.java',
    cwe: null,
    cvss: null,
    remediation: '无需处理；用于函数级导航和后续人工复核。',
    target: null,
    evidence: [{ title: '函数统计', kind: 'ghidra-summary', excerpt: JSON.stringify({ functionCount: report.functionCount, emitted: functions.length, language: report.language, imageBase: report.imageBase }), meta: {} }],
  })
  const data = {
    program: String(report.program ?? '').slice(0, 200),
    language: String(report.language ?? '').slice(0, 100),
    imageBase: String(report.imageBase ?? '').slice(0, 40),
    functionCount: Number(report.functionCount ?? functions.length) || functions.length,
    emitted: functions.length,
    truncated: Number(report.functionCount ?? 0) > functions.length,
    functions,
    suspiciousNames: matched,
    verificationDefault: 'hypothesis',
    tool: 'ghidra',
  }
  return {
    summary: `Ghidra：${data.program || basename(String(options.path ?? 'sample'))}，函数 ${data.functionCount} 个（导出 ${data.emitted}），敏感名称 ${Object.keys(matched).length} 类。调用图与函数体未回传。`,
    findings: findings.slice(0, Math.max(1, Math.min(Number(options.maxFindings ?? 200), 1000))),
    evidence: [{ title: 'Ghidra 函数摘要', kind: 'ghidra-summary', excerpt: JSON.stringify({ functionCount: data.functionCount, emitted: data.emitted, names: Object.keys(matched) }), meta: {} }],
    data,
  }
}

export const ghidraCapability = {
  id: 'binary.ghidra',
  title: 'Ghidra 深度函数分析（外部工具）',
  description: '调用 Ghidra analyzeHeadless + 捆绑 ExportSummary.java，枚举函数、入口、调用者计数并匹配敏感函数名；输出有界，不回传反编译源码，不执行样本。缺失 Ghidra/JDK 21 时 fail-closed。结论中结构为 observed、敏感性名为 hypothesis。',
  riskLevel: 'L0',
  targetKind: 'file',
  params: {
    type: 'object',
    properties: {
      maxFunctions: { type: 'integer', minimum: 1, maximum: 5000, description: '返回的函数上限，默认 500。' },
      timeoutMs: { type: 'number', minimum: 5000, maximum: 600000, description: 'Ghidra headless 超时，默认 300000。' },
    },
    additionalProperties: false,
  },
  async run(input) {
    if (input.env?.signal?.aborted) throw new Error('已中止：Ghidra 分析取消')
    const targetPath = input.targetPath ?? null
    if (!targetPath) throw new Error('binary.ghidra needs an executable file target')
    if (!existsSync(targetPath)) throw new Error(`input file not found: ${targetPath}`)
    const isSeam = typeof input.env?.execExternal === 'function'
    const projectDir = mkdtempSync(join(tmpdir(), 'abm-ghidra-proj-'))
    const outFile = join(mkdtempSync(join(tmpdir(), 'abm-ghidra-out-')), 'summary.json')
    try {
      let tool
      let args
      if (isSeam) {
        tool = { command: 'ghidra', prefixArgs: [] }
        args = ['-import', targetPath, '-postScript', 'ExportSummary.java', outFile]
      } else {
        const ghidra = resolveGhidra(process.env)
        tool = process.platform === 'win32'
          ? { command: 'cmd.exe', prefixArgs: ['/d', '/s', '/c', ghidra.launcher] }
          : { command: ghidra.launcher, prefixArgs: [] }
        args = [
          projectDir, `abm_${Date.now()}`,
          '-import', targetPath,
          '-scriptPath', SCRIPT_DIR,
          '-analysisTimeoutPerFile', '180',
          '-deleteProject',
          '-postScript', 'ExportSummary.java', outFile,
        ]
        tool = { ...tool, envOverrides: { JAVA_HOME: ghidra.javaHome } }
      }
      try {
        await executeTool(input.env, tool, args, {
          timeoutMs: Math.max(5000, Math.min(Number(input.options?.timeoutMs ?? 300_000), 600_000)),
          maxOutputBytes: 32 * 1024 * 1024,
          envOverrides: tool.envOverrides ?? {},
        })
      } catch (error) {
        throw new Error(`binary.ghidra failed: ${String(error?.message ?? error)} ${EXTERNAL_TOOL_GUIDANCE.ghidra}`.trim())
      }
      if (!existsSync(outFile)) throw new Error('Ghidra completed but ExportSummary output was not written; check the script log/analysis timeout')
      if (input.env?.signal?.aborted) throw new Error('已中止：Ghidra 分析取消')
      const parsed = parseGhidraSummary(readFileSync(outFile, 'utf8'), { ...input.options, path: targetPath })
      return {
        ...parsed,
        meta: {
          domain: 'binary', capability: 'binary.ghidra', tool: 'ghidra', target: targetPath,
          inputBytes: statSync(targetPath).size, emitted: parsed.data.emitted, functionCount: parsed.data.functionCount,
        },
      }
    } finally {
      for (const dir of [projectDir, dirnameSafe(outFile)]) {
        try {
          rmSync(dir, { recursive: true, force: true })
        } catch {
          /* best effort */
        }
      }
    }
  },
}

function dirnameSafe(file) {
  const index = file.lastIndexOf('\\') >= 0 ? file.lastIndexOf('\\') : file.lastIndexOf('/')
  return index > 0 ? file.slice(0, index) : file
}
