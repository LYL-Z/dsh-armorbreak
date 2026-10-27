/**
 * Ghidra headless adapter (v1.2.0).
 *
 * Runs `analyzeHeadless` with the bundled ExportSummary.java script, which emits
 * bounded native Program IR. When Core supplies the authorized input buffer,
 * analysis uses an exact temporary copy and rejects truncated input; the source
 * file is never modified. The adapter does not decompile source or execute the
 * sample. Findings based on function names are hypothesis-level.
 * @module dsh-armorbreak/lib/analyzers/binary/ghidra
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
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

/** @param {string} raw @param {{maxFunctions?:number,maxBasicBlocks?:number,maxCallEdges?:number,maxSymbols?:number,maxSegments?:number,maxFindings?:number}} [options] */
export function parseGhidraSummary(raw, options = {}) {
  const report = parseJsonOutput(raw, 'ghidra')
  if (!report || typeof report !== 'object' || !Array.isArray(report.functions)) {
    throw new Error('ghidra output JSON is not an ArmorBreak ExportSummary (missing functions array)')
  }
  const maxFunctions = Math.max(1, Math.min(Number(options.maxFunctions ?? 500), 5000))
  const maxBasicBlocks = Math.max(1, Math.min(Number(options.maxBasicBlocks ?? 1000), 5000))
  const maxCallEdges = Math.max(1, Math.min(Number(options.maxCallEdges ?? 2000), 10000))
  const maxSymbols = Math.max(1, Math.min(Number(options.maxSymbols ?? 1000), 5000))
  const maxSegments = Math.max(1, Math.min(Number(options.maxSegments ?? 256), 512))
  const asCount = (value, fallback = 0) => Number.isSafeInteger(Number(value)) && Number(value) >= 0 ? Number(value) : fallback
  const functions = report.functions.slice(0, maxFunctions).map((fn) => ({
    name: String(fn.name ?? '').slice(0, 200),
    entry: String(fn.entry ?? '').slice(0, 40),
    relativeAddress: fn.relativeAddress == null ? null : String(fn.relativeAddress).slice(0, 40),
    fileOffset: fn.fileOffset == null ? null : String(fn.fileOffset).slice(0, 40),
    end: fn.end == null ? null : String(fn.end).slice(0, 40),
    size: asCount(fn.size),
    external: Boolean(fn.external),
    thunk: Boolean(fn.thunk),
    callingConvention: String(fn.callingConvention ?? '').slice(0, 60),
    callers: asCount(fn.callers),
    byteHashSha256: typeof fn.byteHashSha256 === 'string' && /^[a-f0-9]{64}$/i.test(fn.byteHashSha256) ? fn.byteHashSha256.toLowerCase() : null,
    byteHashBytes: asCount(fn.byteHashBytes),
    byteHashStatus: ['COMPLETE', 'PARTIAL_BUDGET', 'UNAVAILABLE'].includes(fn.byteHashStatus) ? fn.byteHashStatus : 'UNAVAILABLE',
  }))
  const callEdges = (Array.isArray(report.callEdges) ? report.callEdges : []).slice(0, maxCallEdges).map((edge) => ({
    caller: String(edge.caller ?? '').slice(0, 200),
    callerEntry: String(edge.callerEntry ?? '').slice(0, 40),
    callSite: String(edge.callSite ?? '').slice(0, 40),
    callSiteFileOffset: edge.callSiteFileOffset == null ? null : String(edge.callSiteFileOffset).slice(0, 40),
    callee: String(edge.callee ?? '').slice(0, 200),
    calleeEntry: String(edge.calleeEntry ?? '').slice(0, 40),
    calleeFileOffset: edge.calleeFileOffset == null ? null : String(edge.calleeFileOffset).slice(0, 40),
    referenceType: String(edge.referenceType ?? 'CALL').slice(0, 40),
  }))
  const basicBlocks = (Array.isArray(report.basicBlocks) ? report.basicBlocks : []).slice(0, maxBasicBlocks).map((block) => ({
    functionEntry: String(block.functionEntry ?? '').slice(0, 40),
    start: String(block.start ?? '').slice(0, 40),
    end: String(block.end ?? '').slice(0, 40),
    fileOffset: block.fileOffset == null ? null : String(block.fileOffset).slice(0, 40),
    size: asCount(block.size),
    flowType: String(block.flowType ?? 'UNKNOWN').slice(0, 40),
  }))
  const segments = (Array.isArray(report.segments) ? report.segments : []).slice(0, maxSegments).map((segment) => ({
    name: String(segment.name ?? '').slice(0, 120),
    start: String(segment.start ?? '').slice(0, 40),
    end: String(segment.end ?? '').slice(0, 40),
    fileOffset: segment.fileOffset == null ? null : String(segment.fileOffset).slice(0, 40),
    size: asCount(segment.size),
    initialized: Boolean(segment.initialized),
    read: Boolean(segment.read),
    write: Boolean(segment.write),
    execute: Boolean(segment.execute),
    overlay: Boolean(segment.overlay),
  }))
  const symbols = (Array.isArray(report.symbols) ? report.symbols : []).slice(0, maxSymbols).map((symbol) => ({
    name: String(symbol.name ?? '').slice(0, 200),
    address: String(symbol.address ?? '').slice(0, 40),
    fileOffset: symbol.fileOffset == null ? null : String(symbol.fileOffset).slice(0, 40),
    type: String(symbol.type ?? 'UNKNOWN').slice(0, 60),
    source: String(symbol.source ?? 'UNKNOWN').slice(0, 60),
    external: Boolean(symbol.external),
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
  const internalFunctionCount = asCount(report.internalFunctionCount, functions.length)
  const externalFunctionCount = asCount(report.externalFunctionCount)
  findings.push({
    title: `Ghidra 枚举 ${internalFunctionCount} 个内部函数、${externalFunctionCount} 个外部函数（输出 ${functions.length}）`,
    severity: 'info',
    description: '函数与调用者计数来自 Ghidra 自动分析；调用边/基本块只覆盖输出函数范围并受显式上限约束。结果受加载器、符号与自动分析质量影响，不是反编译源码。',
    verification: 'observed',
    method: 'Ghidra analyzeHeadless ExportSummary.java',
    cwe: null,
    cvss: null,
    remediation: '无需处理；用于函数级导航和后续人工复核。',
    target: null,
    evidence: [{ title: '函数统计', kind: 'ghidra-summary', excerpt: JSON.stringify({ functionCount: asCount(report.functionCount, functions.length), internalFunctionCount, externalFunctionCount, emitted: functions.length, language: report.language, imageBase: report.imageBase }), meta: {} }],
  })
  const data = {
    program: String(report.program ?? '').slice(0, 200),
    executableFormat: String(report.executableFormat ?? '').slice(0, 100),
    processor: String(report.processor ?? '').slice(0, 100),
    language: String(report.language ?? '').slice(0, 100),
    endianness: report.endianness === 'big' ? 'big' : report.endianness === 'little' ? 'little' : 'unknown',
    imageBase: String(report.imageBase ?? '').slice(0, 40),
    toolVersion: String(report.toolVersion ?? options.toolVersion ?? 'UNAVAILABLE').slice(0, 60),
    functionCount: asCount(report.functionCount, functions.length),
    internalFunctionCount: asCount(report.internalFunctionCount, functions.length),
    externalFunctionCount: asCount(report.externalFunctionCount),
    emitted: functions.length,
    truncated: Boolean(report.functionsTruncated)
      || (Array.isArray(report.functions) && report.functions.length > functions.length)
      || asCount(report.internalFunctionCount, functions.length) > functions.length
      || Boolean(report.callEdgesTruncated)
      || (Array.isArray(report.callEdges) && report.callEdges.length > callEdges.length)
      || Boolean(report.basicBlocksTruncated)
      || (Array.isArray(report.basicBlocks) && report.basicBlocks.length > basicBlocks.length)
      || Boolean(report.segmentsTruncated)
      || (Array.isArray(report.segments) && report.segments.length > segments.length)
      || Boolean(report.symbolsTruncated)
      || (Array.isArray(report.symbols) && report.symbols.length > symbols.length),
    functionScopeTruncated: Boolean(report.functionsTruncated)
      || (Array.isArray(report.functions) && report.functions.length > functions.length),
    functions,
    callEdgeCount: asCount(report.callEdgeCount, callEdges.length),
    callEdgesTruncated: Boolean(report.callEdgesTruncated) || (Array.isArray(report.callEdges) && report.callEdges.length > callEdges.length),
    callEdgeCountComplete: report.callEdgeCountComplete === true
      && !Boolean(report.callEdgesTruncated)
      && (!Array.isArray(report.callEdges) || report.callEdges.length <= callEdges.length),
    callEdges,
    basicBlockCount: asCount(report.basicBlockCount, basicBlocks.length),
    basicBlocksTruncated: Boolean(report.basicBlocksTruncated) || (Array.isArray(report.basicBlocks) && report.basicBlocks.length > basicBlocks.length),
    basicBlockCountComplete: report.basicBlockCountComplete === true
      && !Boolean(report.basicBlocksTruncated)
      && (!Array.isArray(report.basicBlocks) || report.basicBlocks.length <= basicBlocks.length),
    basicBlocks,
    segments,
    symbols,
    symbolCount: asCount(report.symbolCount, symbols.length),
    segmentsTruncated: Boolean(report.segmentsTruncated) || (Array.isArray(report.segments) && report.segments.length > segments.length),
    symbolsTruncated: Boolean(report.symbolsTruncated) || (Array.isArray(report.symbols) && report.symbols.length > symbols.length),
    suspiciousNames: matched,
    verificationDefault: 'hypothesis',
    tool: 'ghidra',
  }
  return {
    summary: `Ghidra ${data.toolVersion}：${data.program || basename(String(options.path ?? 'sample'))}，函数 ${data.functionCount} 个（输出 ${data.emitted}），基本块 ${data.basicBlockCount} 个、调用边 ${data.callEdgeCount} 条；敏感名称 ${Object.keys(matched).length} 类。`,
    findings: findings.slice(0, Math.max(1, Math.min(Number(options.maxFindings ?? 200), 1000))),
    evidence: [{ title: 'Ghidra 函数与调用摘要', kind: 'ghidra-summary', excerpt: JSON.stringify({ toolVersion: data.toolVersion, functionCount: data.functionCount, internalFunctionCount: data.internalFunctionCount, externalFunctionCount: data.externalFunctionCount, emitted: data.emitted, callEdgeCount: data.callEdgeCount, basicBlockCount: data.basicBlockCount, names: Object.keys(matched) }), meta: {} }],
    data,
  }
}

export const ghidraCapability = {
  id: 'binary.ghidra',
  title: 'Ghidra 深度函数分析（外部工具）',
  description: '调用锁定 Ghidra 12.1.4 与 JDK 21 的 analyzeHeadless + 捆绑 ExportSummary.java，对 Core 授权缓冲区的精确临时副本输出有界函数/基本块/调用边、文件偏移、函数字节哈希、节段及符号；不修改源文件、不回传反编译源码、不执行样本。结论中结构为 observed、敏感性名为 hypothesis。',
  riskLevel: 'L0',
  targetKind: 'file',
  params: {
    type: 'object',
    properties: {
      maxFunctions: { type: 'integer', minimum: 1, maximum: 5000, description: '返回的函数上限，默认 100。' },
      maxBasicBlocks: { type: 'integer', minimum: 1, maximum: 5000, description: '返回的基本块上限，默认 1000。' },
      maxCallEdges: { type: 'integer', minimum: 1, maximum: 10000, description: '返回的调用边上限，默认 2000。' },
      maxSymbols: { type: 'integer', minimum: 1, maximum: 5000, description: '返回的符号上限，默认 1000。' },
      timeoutMs: { type: 'number', minimum: 5000, maximum: 600000, description: 'Ghidra headless 超时，默认 300000。' },
    },
    additionalProperties: false,
  },
  async run(input) {
    if (input.env?.signal?.aborted) throw new Error('已中止：Ghidra 分析取消')
    const targetPath = input.targetPath ?? null
    if (!targetPath) throw new Error('binary.ghidra needs an executable file target')
    if (!existsSync(targetPath)) throw new Error(`input file not found: ${targetPath}`)
    const inputBuffer = Buffer.isBuffer(input.buffer) ? input.buffer : null
    if (inputBuffer && (input.env?.targetTruncated === true
      || (Number.isFinite(Number(input.env?.targetSize)) && Number(input.env.targetSize) !== inputBuffer.length))) {
      throw new Error('binary.ghidra refuses truncated or size-mismatched Core input; increase the authorized input limit and retry')
    }
    const isSeam = typeof input.env?.execExternal === 'function'
    const ghidra = isSeam ? null : resolveGhidra(process.env)
    let sampleDir = null
    let projectDir = null
    let outputDir = null
    try {
      let analysisPath = targetPath
      if (inputBuffer) {
        sampleDir = mkdtempSync(join(tmpdir(), 'abm-ghidra-sample-'))
        analysisPath = join(sampleDir, basename(targetPath) || 'sample.bin')
        writeFileSync(analysisPath, inputBuffer)
      }
      projectDir = mkdtempSync(join(tmpdir(), 'abm-ghidra-proj-'))
      outputDir = mkdtempSync(join(tmpdir(), 'abm-ghidra-out-'))
      const outFile = join(outputDir, 'summary.json')
      let tool
      let args
      if (isSeam) {
        tool = { command: 'ghidra', prefixArgs: [] }
        args = ['-import', analysisPath, '-postScript', 'ExportSummary.java', outFile,
          String(input.options?.maxFunctions ?? 100), String(input.options?.maxBasicBlocks ?? 1000),
          String(input.options?.maxCallEdges ?? 2000), String(input.options?.maxSymbols ?? 1000)]
      } else {
        tool = process.platform === 'win32'
          ? { command: 'cmd.exe', prefixArgs: ['/d', '/s', '/c', ghidra.launcher] }
          : { command: ghidra.launcher, prefixArgs: [] }
        args = [
          projectDir, `abm_${Date.now()}`,
          '-import', analysisPath,
          '-scriptPath', SCRIPT_DIR,
          '-analysisTimeoutPerFile', '180',
          '-deleteProject',
          '-postScript', 'ExportSummary.java', outFile,
          String(input.options?.maxFunctions ?? 100), String(input.options?.maxBasicBlocks ?? 1000),
          String(input.options?.maxCallEdges ?? 2000), String(input.options?.maxSymbols ?? 1000),
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
      const toolVersion = isSeam ? 'TEST_SEAM' : ghidra.version
      const parsed = parseGhidraSummary(readFileSync(outFile, 'utf8'), { ...input.options, path: targetPath, toolVersion })
      return {
        ...parsed,
        meta: {
          domain: 'binary', capability: 'binary.ghidra', tool: 'ghidra', target: targetPath,
          toolVersion, inputBytes: inputBuffer?.length ?? statSync(targetPath).size, emitted: parsed.data.emitted,
          functionCount: parsed.data.functionCount, callEdgeCount: parsed.data.callEdgeCount,
          basicBlockCount: parsed.data.basicBlockCount,
        },
      }
    } finally {
      for (const dir of [sampleDir, projectDir, outputDir]) {
        if (!dir) continue
        try {
          rmSync(dir, { recursive: true, force: true })
        } catch {
          /* best effort */
        }
      }
    }
  },
}
