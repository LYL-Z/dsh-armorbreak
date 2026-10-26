/** ArmorBreak artifact intake capabilities. Offline, read-only and bounded. */
import { basename, relative } from 'node:path'
import { checkAbort, enforceDataSize, makeEvidence, makeMeta, sanitizeText } from '../binary/util.js'
import { boundedOptions, fitArtifactGraphToResultBudget, identifyArtifact, inventoryFiles } from './intake.js'

const emptyParams = { type: 'object', properties: {}, additionalProperties: false }

function limitsFor(input) {
  const limits = input.limits ?? {}
  return {
    maxInputBytes: Number(limits.maxInputBytes ?? limits.maxBytes ?? 32 * 1024 * 1024),
    maxFileReadBytes: Number(limits.maxFileReadBytes ?? 4 * 1024 * 1024),
    maxItems: Number(limits.maxItems ?? 300),
    maxFindings: Number(limits.maxFindings ?? 100),
    maxResultBytes: Number(limits.maxResultBytes ?? 256 * 1024),
  }
}

function finish(capability, format, input, data, summary, warnings = [], extraEvidence = []) {
  const notes = [...warnings]
  const finalData = enforceDataSize(data, notes)
  return {
    summary: sanitizeText(summary, 4000),
    findings: [],
    evidence: [
      makeEvidence('通用产物分析摘要', 'artifact-intake', summary, { detector: data.detector ?? null, status: data.analysis?.status ?? data.status ?? null }),
      ...extraEvidence,
    ].slice(0, 8),
    data: finalData,
    meta: {
      ...makeMeta(capability, format, {
        analyzedBytes: data.summary?.bytesRead ?? data.bytes ?? 0,
        source: input.evidenceSource ?? (input.buffer ? 'buffer' : 'workspace-read'),
        truncated: input.env?.targetTruncated === true,
      }, notes),
      artifactSchema: data.schemaVersion ?? null,
    },
  }
}

const capabilities = [
  {
    id: 'artifact.identify',
    title: '通用产物识别',
    description: '基于魔数、基本容器结构、有限文本与文件名提示识别常见原生文件、归档、文档、图像、源码和字节码；记录 SHA-256、结构摘要、候选置信度及截断边界。只读，不执行样本，也不把扩展名识别当作语义支持。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: { fileName: { type: 'string', maxLength: 512, description: '仅用于候选提示；内容特征优先。' } },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'artifact.identify'
      checkAbort(input.env, capId)
      let buffer = Buffer.isBuffer(input.buffer) ? input.buffer : null
      let source = 'buffer'
      if (!buffer && typeof input.text === 'string') {
        buffer = Buffer.from(input.text, 'utf8')
        source = 'text-reencoded'
      }
      if (!buffer) throw new Error('artifact.identify requires file bytes supplied by Core or text input')
      const fileName = String(input.options?.fileName ?? (input.targetPath ? basename(input.targetPath) : ''))
      const detected = identifyArtifact(buffer, fileName)
      const warnings = []
      if (input.env?.targetTruncated === true) warnings.push('Core truncated the input; SHA-256 and structural facts cover only bytes read.')
      checkAbort(input.env, capId)
      const data = {
        schemaVersion: 'armorbreak.artifact-identification/v1',
        detector: detected.detector,
        ...detected,
        inputCompleteness: input.env?.targetTruncated === true ? 'truncated' : 'as_supplied',
        hashScope: input.env?.targetTruncated === true ? 'observed_bytes_only' : 'supplied_bytes',
        analysis: { level: 'S1', status: detected.status === 'UNKNOWN' ? 'UNSUPPORTED' : 'COMPLETE', warnings, limitsApplied: input.env?.targetTruncated === true ? ['core.maxInputBytes'] : [] },
      }
      const summary = `${detected.format}（confidence=${detected.confidence}），${detected.bytes} 字节，SHA-256 ${detected.sha256}；可打印片段 ${detected.structuralFacts.printableFragmentCount} 个。${detected.status === 'UNKNOWN' ? '未匹配已实现格式，保留为未知输入。' : ''}`
      return finish(capId, detected.format, { ...input, buffer, evidenceSource: source }, data, summary, warnings)
    },
  },
  {
    id: 'artifact.inventory',
    title: '递归产物清单与归档索引',
    description: '通过 Core 提供的有界目录读取构建文件与嵌套归档关系图；ZIP/TAR/GZIP 成员仅在内存中解析，检查路径穿越、ADS、符号链接/特殊文件、名称碰撞、压缩比、递归深度和字节预算。无法安全解析时保留原因并返回 PARTIAL，不写出或执行成员。',
    riskLevel: 'L0',
    targetKind: 'directory',
    params: {
      type: 'object',
      properties: {
        maxFiles: { type: 'integer', minimum: 1, maximum: 5000 },
        maxScanBytes: { type: 'integer', minimum: 1024, maximum: 33554432 },
        maxEntries: { type: 'integer', minimum: 1, maximum: 10000 },
        maxDepth: { type: 'integer', minimum: 0, maximum: 10 },
        maxEntryBytes: { type: 'integer', minimum: 1, maximum: 8388608 },
        maxExpandedBytes: { type: 'integer', minimum: 1024, maximum: 67108864 },
        maxExpansionRatio: { type: 'integer', minimum: 1, maximum: 1000 },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'artifact.inventory'
      checkAbort(input.env, capId)
      if (!input.targetPath || typeof input.env?.listFiles !== 'function' || typeof input.env?.readFile !== 'function') {
        throw new Error('artifact.inventory requires a directory target and Core-bounded env.listFiles/env.readFile')
      }
      const limits = limitsFor(input)
      const bounded = boundedOptions(input.options ?? {}, limits)
      const listed = await input.env.listFiles(input.targetPath, { maxFiles: bounded.maxFiles, maxDepth: bounded.maxDepth })
      const sorted = [...new Set((Array.isArray(listed) ? listed : []).filter((path) => typeof path === 'string'))].sort((a, b) => a.localeCompare(b))
      const files = []
      let totalRead = 0
      let truncatedFiles = 0
      let unreadableFiles = 0
      for (const absPath of sorted.slice(0, bounded.maxFiles)) {
        checkAbort(input.env, capId)
        const remaining = bounded.maxScanBytes - totalRead
        if (remaining <= 0) break
        const readCap = Math.min(bounded.maxFileBytes, remaining)
        const wasTruncated = input.env.targetTruncated === true
        let bytes
        try {
          bytes = await input.env.readFile(absPath, readCap)
        } catch (error) {
          unreadableFiles += 1
          files.push({ path: safeRelativePath(input.targetPath, absPath), bytes: null, inputCompleteness: 'unreadable', sha256Scope: 'none', physicalBytes: null })
          continue
        }
        if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes ?? [])
        totalRead += bytes.length
        const newlyTruncated = !wasTruncated && input.env.targetTruncated === true
        const atLimit = bytes.length === readCap
        const inputCompleteness = newlyTruncated ? 'truncated' : atLimit ? 'unknown_at_read_limit' : 'complete'
        if (inputCompleteness !== 'complete') truncatedFiles += 1
        files.push({
          path: safeRelativePath(input.targetPath, absPath),
          bytes,
          inputCompleteness,
          sha256Scope: inputCompleteness === 'complete' ? 'complete_input' : 'observed_bytes_only',
          physicalBytes: inputCompleteness === 'complete' ? bytes.length : null,
        })
      }
      const graph = inventoryFiles(files, { bounded })
      const warnings = [...graph.analysis.warnings]
      if (unreadableFiles > 0) warnings.push(`${unreadableFiles} listed file(s) could not be read through the Core path boundary.`)
      if (sorted.length > bounded.maxFiles) graph.analysis.limitsApplied.push('maxFiles')
      if (totalRead >= bounded.maxScanBytes && sorted.length > files.length) graph.analysis.limitsApplied.push('maxScanBytes')
      if (truncatedFiles > 0) warnings.push(`${truncatedFiles} file(s) were truncated or landed exactly on a read limit; their hashes cover observed bytes only.`)
      if (sorted.length === 0) warnings.push('Core returned no regular files; hidden paths and symbolic links are excluded by the current directory listing contract.')
      graph.analysis.warnings = [...new Set(warnings)].slice(0, 100)
      graph.analysis.limitsApplied = [...new Set(graph.analysis.limitsApplied)]
      if (graph.analysis.warnings.length || graph.analysis.limitsApplied.length || truncatedFiles) graph.analysis.status = 'PARTIAL'
      const data = fitArtifactGraphToResultBudget({
        ...graph,
        summary: { ...graph.summary, filesListed: sorted.length, filesRead: files.length - unreadableFiles, unreadableFiles, truncatedOrCappedFiles: truncatedFiles },
        analysis: graph.analysis,
      }, limits.maxResultBytes)
      if (data.analysis.limitsApplied.includes('maxResultBytes')) warnings.push('The artifact graph was reduced to Core maxResultBytes; returned node and edge counts reflect the truncated graph.')
      const summary = `索引 ${files.length}/${sorted.length} 个文件，生成 ${data.nodes.length} 个节点、${data.edges.length} 条关系；观测 ${totalRead} 字节，归档展开 ${data.summary.expandedBytes} 字节。状态 ${data.analysis.status}。`
      const evidence = [makeEvidence('索引统计', 'artifact-graph-summary', JSON.stringify(data.summary))]
      checkAbort(input.env, capId)
      return finish(capId, 'artifact-graph', { ...input, buffer: null, evidenceSource: 'workspace-read' }, data, summary, warnings, evidence)
    },
  },
]

function safeRelativePath(root, fullPath) {
  const path = relative(root, fullPath).replace(/\\/g, '/')
  if (!path || path === '.') return '.'
  if (path === '..' || path.startsWith('../') || /^[A-Za-z]:/.test(path) || path.startsWith('/')) return '[path-rejected]'
  return sanitizeText(path, 500)
}

export default { domain: 'artifact', capabilities }
