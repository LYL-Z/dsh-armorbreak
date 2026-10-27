/** Bounded native executable Program IR assembled from ArmorBreak parsers and Ghidra. */
import {
  checkAbort,
  enforceDataSize,
  makeEvidence,
  makeMeta,
  normalizeLimits,
  requireBytes,
  sanitizeText,
  truncationInfo,
} from './util.js'
import { detectContainer, identify } from './identify.js'
import { parsePe } from './pe.js'
import { parseElf } from './elf.js'
import { parseMachO } from './macho.js'
import { analyzeStructure } from './structure.js'
import { ghidraCapability } from './ghidra.js'

const CAPABILITY_ID = 'binary.program_ir'
const NATIVE_FORMATS = new Set(['pe', 'elf', 'macho'])

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, Math.floor(parsed))) : fallback
}

function formatDetails(buffer, format, facts, limits, structure) {
  const sections = Array.isArray(facts.sections) ? facts.sections.slice(0, limits.maxItems) : []
  if (format === 'pe') {
    const parsed = parsePe(buffer, { maxSections: Math.min(96, limits.maxItems) })
    if (!parsed.ok || parsed.partial) return {
      architecture: facts.arch ?? parsed.coff?.machineName ?? null,
      bitness: facts.bits ?? null,
      endianness: 'little',
      type: facts.type ?? null,
      entryPoint: facts.entryPoint ?? null,
      entryPointVa: facts.entryPointVa ?? null,
      imageBase: null,
      sections,
      segments: [],
      imports: facts.imports ?? null,
      exports: facts.exports ?? null,
      relocations: { status: 'UNAVAILABLE', entriesParsed: 0 },
      debugInfo: { status: 'UNAVAILABLE', reason: parsed.reason ?? parsed.warnings?.[0] ?? 'PE 可选头不完整。' },
      resources: { status: 'UNAVAILABLE' },
      parseWarnings: (parsed.warnings ?? []).slice(0, 20),
      sourceSymbolSummary: structure.data,
    }
    const relocationDirectory = parsed.ok ? parsed.directories.find((entry) => entry.name === 'basereloc') : null
    return {
      architecture: facts.arch ?? null,
      bitness: facts.bits ?? null,
      endianness: facts.endianness ?? 'little',
      type: facts.type ?? null,
      entryPoint: facts.entryPoint ?? facts.entryPointHex ?? null,
      entryPointVa: facts.entryPointVa ?? null,
      imageBase: facts.imageBase ?? null,
      sections,
      segments: [],
      imports: facts.imports ?? null,
      exports: facts.exports ?? null,
      relocations: {
        status: parsed.ok && relocationDirectory?.rva && relocationDirectory?.size ? 'DIRECTORY_PRESENT_NOT_DECODED' : 'NOT_DECODED',
        directory: relocationDirectory ? { rva: relocationDirectory.rva, size: relocationDirectory.size } : null,
        entriesParsed: 0,
      },
      debugInfo: parsed.ok ? {
        status: parsed.debug.present ? 'PRESENT' : 'ABSENT',
        records: parsed.debug.entries.slice(0, 16).map((entry) => ({
          type: entry.typeName,
          codeView: entry.codeview ? {
            guid: entry.codeview.guid ?? null,
            age: entry.codeview.age ?? null,
            pdbFilename: typeof entry.codeview.pdbPath === 'string' ? entry.codeview.pdbPath.split(/[\\/]/).pop() : null,
          } : null,
        })),
      } : { status: 'UNAVAILABLE', reason: parsed.reason },
      resources: parsed.ok ? { status: parsed.resources.present ? 'PRESENT' : 'ABSENT', count: parsed.resources.count, types: parsed.resources.types, manifestPresent: parsed.resources.manifestPresent, versionInfoPresent: parsed.resources.versionInfo !== null } : { status: 'UNAVAILABLE' },
      parseWarnings: parsed.ok ? parsed.warnings.slice(0, 20) : [parsed.reason],
      sourceSymbolSummary: structure.data,
    }
  }
  if (format === 'elf') {
    const parsed = parseElf(buffer, { maxSections: Math.min(512, limits.maxItems), maxSymbols: Math.min(300, limits.maxStrings) })
    const relocationSections = parsed.ok ? parsed.sections.filter((section) => section.type === 4 || section.type === 9).slice(0, 100).map((section) => ({
      name: section.name,
      type: section.typeName,
      offset: section.offset,
      size: section.size,
      entrySize: section.entsize,
    })) : []
    return {
      architecture: facts.arch ?? facts.machine ?? null,
      bitness: facts.bits ?? null,
      endianness: facts.endianness ?? null,
      type: facts.type ?? null,
      entryPoint: facts.entryPoint ?? null,
      entryPointVa: facts.entryPoint ?? null,
      imageBase: null,
      sections,
      segments: parsed.ok ? parsed.programHeaders.slice(0, Math.min(256, limits.maxItems)).map((segment) => ({
        type: segment.typeName,
        offset: segment.offset,
        virtualAddress: segment.vaddr,
        fileSize: segment.filesz,
        memorySize: segment.memsz,
        flags: segment.flags,
        alignment: segment.align,
      })) : [],
      imports: facts.imports ?? null,
      exports: facts.exports ?? null,
      relocations: { status: relocationSections.length ? 'SECTION_HEADERS_ONLY' : 'NOT_DECODED', entriesParsed: 0, sections: relocationSections },
      debugInfo: parsed.ok ? {
        status: parsed.sections.some((section) => /^\.(?:z?debug|stab)/i.test(section.name)) ? 'DEBUG_SECTIONS_PRESENT' : 'NO_DEBUG_SECTIONS_DETECTED',
        sections: parsed.sections.filter((section) => /^\.(?:z?debug|stab)/i.test(section.name)).slice(0, 64).map((section) => section.name),
        buildId: parsed.buildId,
      } : { status: 'UNAVAILABLE', reason: parsed.reason },
      resources: { status: 'NOT_APPLICABLE' },
      parseWarnings: parsed.ok ? parsed.warnings.slice(0, 20) : [parsed.reason],
      sourceSymbolSummary: structure.data,
    }
  }
  const parsed = detectContainer(buffer).parsed ?? parseMachO(buffer, { maxSymbols: Math.min(300, limits.maxStrings) })
  const slices = Array.isArray(parsed?.slices) ? parsed.slices.filter((slice) => slice.ok).slice(0, 8) : []
  const sliceDetails = slices.map((slice) => {
    const image = slice.image ?? slice
    return {
      architecture: image.header.arch,
      bitness: image.header.bits,
      endianness: image.header.endianness,
      fileType: image.header.fileTypeName,
      entryPoint: image.entryPoint,
      uuid: image.uuid,
      segments: image.segments.slice(0, Math.min(256, limits.maxItems)),
      sections: image.sections.slice(0, limits.maxItems).map((section) => ({
        name: `${section.segment}.${section.name}`,
        address: section.addr,
        offset: section.offset,
        size: section.size,
        flags: section.flagNames,
      })),
      imports: image.imports,
      exports: image.exports,
      codeSignature: image.codesign,
      encryption: image.encryption,
      functionStarts: image.functionStarts,
    }
  })
  return {
    architecture: facts.arch ?? null,
    bitness: facts.bits ?? null,
    endianness: facts.endianness ?? null,
    type: facts.type ?? null,
    entryPoint: facts.entryPoint ?? null,
    entryPointVa: facts.entryPointVa ?? null,
    imageBase: sliceDetails[0]?.segments?.find((segment) => segment.name === '__TEXT')?.vmaddr ?? null,
    sections: sliceDetails.flatMap((slice) => slice.sections).slice(0, limits.maxItems),
    segments: sliceDetails.flatMap((slice) => slice.segments).slice(0, Math.min(256, limits.maxItems)),
    imports: facts.imports ?? null,
    exports: facts.exports ?? null,
    slices: sliceDetails,
    relocations: { status: 'NOT_DECODED', entriesParsed: 0 },
    debugInfo: {
      status: sliceDetails.some((slice) => slice.sections.some((section) => /(?:^|\.)__(?:debug|DWARF)/i.test(section.name))) ? 'DEBUG_SECTIONS_PRESENT' : 'NOT_DETECTED',
      uuids: sliceDetails.map((slice) => slice.uuid).filter(Boolean),
    },
    resources: { status: 'NOT_APPLICABLE' },
    parseWarnings: Array.isArray(facts.warnings) ? facts.warnings.slice(0, 20) : [],
    sourceSymbolSummary: structure.data,
  }
}

function unsupportedLanguage(container, facts) {
  const reason = container.reason ?? facts.reason ?? `当前 native Program IR 仅处理 PE、ELF 与 Mach-O；检测到 ${container.container ?? 'unknown'}。`
  return sanitizeText(reason, 1000)
}

export const programIrCapability = {
  id: CAPABILITY_ID,
  title: '原生二进制 Program IR',
    description: '将 PE/ELF/Mach-O 文件头、段/节、导入导出、调试/资源线索、符号估计与可选 Ghidra 函数/基本块/调用边归一化。仅静态读取；不会执行样本。Ghidra 后端锁定 12.1.4/JDK 21，只处理 Core 完整缓冲区的临时副本；超限输入会跳过 Ghidra，并保留局部结构、明确标记 PARTIAL。',
  riskLevel: 'L0',
  targetKind: 'file',
  params: {
    type: 'object',
    properties: {
      includeGhidra: { type: 'boolean', description: '是否请求已锁定版本的 Ghidra 静态分析，默认 true。' },
      maxFunctions: { type: 'integer', minimum: 1, maximum: 5000, description: 'Ghidra 函数输出上限，默认 100。' },
      maxBasicBlocks: { type: 'integer', minimum: 1, maximum: 5000, description: '基本块输出上限，默认 300。' },
      maxCallEdges: { type: 'integer', minimum: 1, maximum: 10000, description: '调用边输出上限，默认 500。' },
      maxSymbols: { type: 'integer', minimum: 1, maximum: 5000, description: 'Ghidra 符号输出上限，默认 500。' },
      timeoutMs: { type: 'number', minimum: 5000, maximum: 300000, description: 'Ghidra 超时，默认 180000。' },
    },
    additionalProperties: false,
  },
  async run(input) {
    const { buffer, source, warnings } = requireBytes(input, CAPABILITY_ID)
    const limits = normalizeLimits(input.limits)
    const truncation = truncationInfo(input, buffer.length)
    warnings.push(...truncation.warnings)
    checkAbort(input.env, CAPABILITY_ID)

    const container = detectContainer(buffer)
    const identified = identify(buffer, limits)
    const structure = analyzeStructure(buffer, limits)
    const facts = identified.data
    const format = NATIVE_FORMATS.has(facts.format) ? facts.format : container.format
    const supported = NATIVE_FORMATS.has(format)
    const program = supported ? formatDetails(buffer, format, facts, limits, structure) : null
    const includeGhidra = input.options?.includeGhidra !== false
    const ghidraOptions = {
      maxFunctions: boundedInteger(input.options?.maxFunctions, 100, 1, 5000),
      maxBasicBlocks: boundedInteger(input.options?.maxBasicBlocks, 300, 1, 5000),
      maxCallEdges: boundedInteger(input.options?.maxCallEdges, 500, 1, 10000),
      maxSymbols: boundedInteger(input.options?.maxSymbols, 500, 1, 5000),
      timeoutMs: boundedInteger(input.options?.timeoutMs, 180000, 5000, 300000),
    }
    const inputComplete = truncation.truncated !== true
      && input.env?.targetTruncated !== true
      && (!Number.isFinite(Number(input.env?.targetSize)) || Number(input.env.targetSize) === buffer.length)
    let ghidra = { status: includeGhidra ? 'UNAVAILABLE' : 'DISABLED', reason: includeGhidra ? null : '调用方关闭了 Ghidra 后端。', data: null, findings: [] }
    if (supported && includeGhidra && !inputComplete) {
      ghidra = { status: 'INPUT_TRUNCATED', reason: 'Core 提供的输入不完整；为避免对有界分析范围外的原文件启动外部工具，已跳过 Ghidra。', data: null, findings: [] }
    } else if (supported && includeGhidra && !input.targetPath) {
      ghidra = { status: 'UNAVAILABLE', reason: 'Ghidra 后端需要 Core 授权的文件路径；当前仅提供内存字节。', data: null, findings: [] }
    } else if (supported && includeGhidra) {
      try {
        const result = await ghidraCapability.run({ ...input, options: ghidraOptions })
        ghidra = { status: 'ANALYZED', reason: null, data: result.data, findings: result.findings }
      } catch (error) {
        const reason = sanitizeText(error?.message ?? String(error), 1000)
        const status = /ETIMEDOUT|timed out|timeout/i.test(reason)
          ? 'TIMED_OUT'
          : /not installed|not executable|未找到已验证|未找到.*analyzeHeadless|Ghidra.*未安装|缺少.*(?:JDK|Ghidra)/i.test(reason)
            ? 'UNAVAILABLE'
            : 'ERROR'
        ghidra = { status, reason, data: null, findings: [] }
      }
    }
    checkAbort(input.env, CAPABILITY_ID)

    const limitations = [
      'Ghidra auto-analysis output is evidence for navigation; it is not recovered source code or a proof of behavior.',
      'ELF and Mach-O relocation entries are not decoded in this slice; PE base-relocation directory is presence/size only.',
      'Function byte hashes cover Ghidra loaded-memory bytes in function-body address order; relocation effects may differ from original file bytes.',
      'Call edges and basic blocks depend on the selected Ghidra language and auto-analysis; indirect calls, data cross-references and unresolved targets remain unknown.',
      'No control-flow/data-flow taint, deobfuscation, unpacking, runtime behavior, or platform execution is claimed.',
    ]
    const data = {
      schemaVersion: 'armorbreak.native-program-ir/v1',
      analysis: {
        level: supported ? 'S2' : 'S0',
        status: supported ? 'PARTIAL' : 'UNSUPPORTED',
        reason: supported ? (['UNAVAILABLE', 'INPUT_TRUNCATED', 'TIMED_OUT', 'ERROR'].includes(ghidra.status) ? ghidra.reason : null) : unsupportedLanguage(container, facts),
        inputExecuted: false,
        backend: ghidra.status === 'ANALYZED' ? 'Ghidra' : 'ArmorBreak structural parsers',
        backendVersion: ghidra.data?.toolVersion ?? null,
        parserWarnings: [...new Set([...(facts.warnings ?? []), ...(program?.parseWarnings ?? [])])].slice(0, 30),
        truncated: truncation.truncated === true
          || ghidra.data?.truncated === true
          || ghidra.data?.functionScopeTruncated === true
          || ghidra.data?.callEdgesTruncated === true
          || ghidra.data?.basicBlocksTruncated === true
          || ghidra.data?.segmentsTruncated === true
          || ghidra.data?.symbolsTruncated === true,
      },
      artifact: {
        format: facts.format ?? container.format,
        container: facts.container ?? container.container,
        fileSize: truncation.fileSize,
        analyzedBytes: buffer.length,
        sha256: facts.hashes?.sha256 ?? null,
        truncated: truncation.truncated,
      },
      program,
      symbols: program?.sourceSymbolSummary ?? null,
      functionCount: ghidra.data?.functionCount ?? program?.sourceSymbolSummary?.functionEstimate?.count ?? 0,
      emittedFunctions: ghidra.data?.emitted ?? 0,
      functions: ghidra.data?.functions ?? [],
      callEdgeCount: ghidra.data?.callEdgeCount ?? 0,
      callEdges: ghidra.data?.callEdges ?? [],
      basicBlockCount: ghidra.data?.basicBlockCount ?? 0,
      basicBlocks: ghidra.data?.basicBlocks ?? [],
      functionHashes: (ghidra.data?.functions ?? []).filter((fn) => fn.byteHashSha256).map((fn) => ({
        function: fn.name, entry: fn.entry, fileOffset: fn.fileOffset, sha256: fn.byteHashSha256,
        bytesHashed: fn.byteHashBytes, status: fn.byteHashStatus,
      })),
      ghidra: { status: ghidra.status, reason: ghidra.reason, toolVersion: ghidra.data?.toolVersion ?? null },
      limitations,
    }
    try {
      if (Buffer.byteLength(JSON.stringify(data), 'utf8') > 256 * 1024) {
        data.analysis.truncated = true
        warnings.push('Native Program IR exceeded the Core result budget; bounded detail arrays may be shortened.')
      }
    } catch {
      data.analysis.truncated = true
      warnings.push('Native Program IR serialization failed; detailed output was conservatively marked truncated.')
    }
    const output = enforceDataSize(data, warnings)
    const formatLabel = facts.format ?? container.format ?? 'unknown'
    const architecture = program?.architecture ?? 'unknown architecture'
    const summary = supported
      ? `Native Program IR (${formatLabel}, ${architecture})：SHA-256 ${facts.hashes?.sha256 ?? '不可用'}；Ghidra ${ghidra.status}，函数 ${data.functionCount}，调用边 ${data.callEdgeCount}，基本块 ${data.basicBlockCount}。结果状态 PARTIAL。`
      : `Native Program IR 不支持 ${facts.container ?? container.container ?? 'unknown'}：${data.analysis.reason}`
    const findings = [...identified.findings, ...structure.findings, ...ghidra.findings].slice(0, limits.maxFindings)
    const evidence = [
      makeEvidence('原生文件身份与哈希', 'native-program-identity', JSON.stringify({ format: facts.format, architecture, sha256: facts.hashes?.sha256, fileSize: truncation.fileSize })),
      ...(ghidra.status === 'ANALYZED' ? [makeEvidence('Ghidra 函数/调用关系', 'native-program-ghidra', JSON.stringify({ version: ghidra.data.toolVersion, functionCount: ghidra.data.functionCount, emittedFunctions: ghidra.data.emitted, callEdgeCount: ghidra.data.callEdgeCount, basicBlockCount: ghidra.data.basicBlockCount }))] : []),
    ]
    return {
      summary: sanitizeText(summary, 4000),
      findings,
      evidence: evidence.slice(0, 8),
      data: output,
      meta: {
        ...makeMeta(CAPABILITY_ID, formatLabel, { analyzedBytes: buffer.length, source, truncated: truncation.truncated }, warnings),
        fileSize: truncation.fileSize,
        supportLevel: supported ? 'S2' : 'S0',
        ghidraStatus: ghidra.status,
        ghidraVersion: ghidra.data?.toolVersion ?? null,
      },
    }
  },
}
