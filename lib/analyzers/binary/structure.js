/**
 * Binary domain — structural analysis (entry points, symbols, exception directory, function heuristics).
 * All counts are labeled as heuristics where they are estimates; nothing is executed.
 */
import { hex, makeFinding, makeEvidence, sanitizeText } from './util.js';
import { parsePe } from './pe.js';
import { parseElf } from './elf.js';
import { parseMachO } from './macho.js';
import { detectContainer } from './identify.js';

function uleb128(buffer, start, end) {
  let pos = start;
  let result = 0n;
  let shift = 0n;
  while (pos < end) {
    const byte = buffer[pos];
    pos += 1;
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value: result, next: pos };
    shift += 7n;
    if (shift > 63n) return null;
  }
  return null;
}

/** Decode LC_FUNCTION_STARTS ULEB128 deltas into a bounded function-start list. */
export function decodeFunctionStarts(buffer, image) {
  const fs = image && image.functionStarts;
  if (!fs || !Number.isFinite(fs.dataOffset) || !Number.isFinite(fs.dataSize) || fs.dataSize <= 0) return null;
  const start = fs.dataOffset;
  const end = Math.min(buffer.length, start + fs.dataSize);
  if (start >= end) return null;
  const result = { entryCount: 0, firstAddresses: [], truncated: false };
  const textSeg = (image.segments || []).find((s) => s.name === '__TEXT');
  const base = textSeg && textSeg.vmaddr ? BigInt(textSeg.vmaddr) : 0n;
  let offset = start;
  let cumulative = 0n;
  let guard = 0;
  const maxEntries = 512;
  while (offset < end && guard < maxEntries) {
    guard += 1;
    const decoded = uleb128(buffer, offset, end);
    if (!decoded) { result.truncated = true; break; }
    offset = decoded.next;
    if (decoded.value === 0n) break;
    cumulative += decoded.value;
    result.entryCount += 1;
    if (result.firstAddresses.length < 24) {
      result.firstAddresses.push(hex(base + cumulative));
    }
  }
  if (guard >= maxEntries) result.truncated = true;
  return result;
}

function peStructure(buffer, limits) {
  const parsed = parsePe(buffer, { maxSections: 96 });
  if (!parsed.ok) return { data: { format: 'pe', parseError: parsed.reason }, findings: [], warnings: parsed.warnings };
  if (parsed.partial) return {
    data: {
      format: 'pe',
      arch: parsed.coff?.machineName ?? null,
      bits: null,
      partial: true,
      parseError: parsed.warnings[0] ?? 'PE 可选头不完整。',
      functions: [],
      exports: [],
      counts: { coffSymbols: 0, coffFunctions: 0, exportFunctions: 0, namedExports: 0, importFunctions: 0, importThunks: 0 },
      coffSymbolTable: { present: false, truncated: true },
      functionEstimate: { count: 0, method: 'PE 可选头不完整，未估算函数数量。', verification: 'observed' },
      warnings: parsed.warnings.slice(0, 10),
    },
    findings: [],
    warnings: parsed.warnings,
  };
  const maxSymbols = Math.min(limits.maxStrings, 300);
  const functions = [];
  for (const fn of parsed.coffSymbols.functions.slice(0, maxSymbols)) {
    functions.push({ name: sanitizeText(fn.name, 200), address: hex(fn.value), source: 'coff-symbol-table', section: fn.sectionNumber });
  }
  const exportFunctions = parsed.exports.exports.slice(0, maxSymbols).map((e) => ({
    name: sanitizeText(e.name, 200),
    address: e.address,
    ordinal: e.ordinal,
    source: 'export-table',
  }));
  const entryPoints = [];
  if (parsed.optional && parsed.optional.entryPointRva) {
    entryPoints.push({ kind: 'pe-address-of-entry-point', rva: parsed.optional.entryPointHex, va: parsed.optional.entryPointVa });
  }
  const exception = parsed.exceptionDirectory;
  const estimateBreakdown = {
    entryPoints: entryPoints.length,
    exportFunctions: parsed.exports.exports.length,
    coffFunctions: parsed.coffSymbols.functions.length,
    exceptionEntries: exception.approxCount || 0,
    importThunks: parsed.imports.functionCount,
  };
  const estimateMethod = exception.approxCount
    ? '异常目录 RUNTIME_FUNCTION 数 + 导出/COFF 符号并集（近似）'
    : '导出表 + COFF 符号表并集（无异常目录时不含未导出内部函数，计数偏小）';
  const estimateCount = (exception.approxCount || 0) > 0
    ? Math.max(exception.approxCount, parsed.exports.exports.length, parsed.coffSymbols.functions.length)
    : Math.max(parsed.exports.exports.length, parsed.coffSymbols.functions.length);
  const data = {
    format: 'pe',
    arch: parsed.coff.machineName,
    bits: parsed.optional ? parsed.optional.bits : null,
    entryPoints,
    functions,
    exports: exportFunctions,
    counts: {
      coffSymbols: parsed.coffSymbols.totalSymbols || 0,
      coffFunctions: parsed.coffSymbols.functions.length,
      exportFunctions: parsed.exports.functionCount,
      namedExports: parsed.exports.namedExportCount,
      importFunctions: parsed.imports.functionCount,
      importThunks: parsed.imports.functionCount,
    },
    exceptionDirectory: exception,
    coffSymbolTable: { present: parsed.coffSymbols.present, truncated: parsed.coffSymbols.truncated },
    functionEstimate: { count: estimateCount, method: estimateMethod, breakdown: estimateBreakdown, verification: 'hypothesis' },
    warnings: parsed.warnings.slice(0, 10),
  };
  const findings = [];
  if (!parsed.coffSymbols.present && parsed.exports.namedExportCount === 0) {
    findings.push(makeFinding({
      title: 'PE 无符号表且无具名导出（已 strip 或加壳）',
      severity: 'info',
      description: 'COFF 符号表与导出名称均不可用，无法直接枚举内部函数名；函数数量只能依据入口点/异常目录/导入 thunk 做粗略估计。这不是漏洞，只是静态可读性下降。',
      verification: 'observed',
      method: '检查 COFF pointerToSymbolTable/numberOfSymbols 与导出目录 NumberOfNames',
      remediation: '如需函数级信息，在授权环境中使用反汇编/调试工具，或对样本脱壳后重试。',
      target: null,
      evidence: [makeEvidence('结构计数', 'pe-structure', JSON.stringify(data.counts))],
    }));
  }
  if (exception.present && exception.approxCount) {
    findings.push(makeFinding({
      title: `PE 异常目录包含约 ${exception.approxCount} 个 RUNTIME_FUNCTION 记录`,
      severity: 'info',
      description: 'x64/ARM64 异常目录通常每个函数一条记录，可作为函数数量的近似上界；计数为估算值（observed 结构，hypothesis 语义）。',
      verification: 'observed',
      method: '异常目录大小 / RUNTIME_FUNCTION 记录大小',
      remediation: '无需处理；该信息用于辅助函数级分析。',
      target: `rva=${hex(exception.rva)}`,
      evidence: [makeEvidence('异常目录', 'pe-exception', JSON.stringify(exception))],
    }));
  }
  return { data, findings, warnings: parsed.warnings };
}

function elfStructure(buffer, limits) {
  const parsed = parseElf(buffer, { maxSymbols: Math.min(limits.maxStrings, 1024) });
  if (!parsed.ok) return { data: { format: 'elf', parseError: parsed.reason }, findings: [], warnings: parsed.warnings };
  const maxSymbols = Math.min(limits.maxStrings, 300);
  const sourceFunctions = parsed.symbols.symtab.present ? parsed.symbols.symtab.functions : [];
  const functions = sourceFunctions.slice(0, maxSymbols).map((f) => ({
    name: sanitizeText(f.name || '', 200),
    address: f.value,
    size: f.size,
    bind: f.bindName,
    type: f.typeName,
    source: 'symtab',
  }));
  const dynamicFunctions = parsed.symbols.dynsym.present
    ? parsed.symbols.dynsym.functions.slice(0, maxSymbols).map((f) => ({
      name: sanitizeText(f.name || '', 200),
      address: f.value,
      size: f.size,
      bind: f.bindName,
      type: f.typeName,
      source: 'dynsym',
    }))
    : [];
  const findings = [];
  if (!parsed.symbols.symtab.present) {
    findings.push(makeFinding({
      title: 'ELF 无 .symtab 静态符号表（可能已 strip）',
      severity: 'info',
      description: '未找到 SHT_SYMTAB 节，只能使用动态符号表（.dynsym）枚举导出/导入符号；内部函数名不可用。',
      verification: 'observed',
      method: '扫描节类型 SHT_SYMTAB (2)',
      remediation: '如需函数级信息，使用授权的反汇编/调试工具或调试符号包（build-id 可用于定位符号服务器）。',
      target: parsed.buildId ? `build-id=${parsed.buildId}` : null,
      evidence: [makeEvidence('动态符号统计', 'elf-structure', JSON.stringify({
        dynsymPresent: parsed.symbols.dynsym.present,
        dynsymCount: parsed.symbols.dynsym.count,
        buildId: parsed.buildId,
      }))],
    }));
  }
  const data = {
    format: 'elf',
    arch: parsed.header.machineName,
    bits: parsed.identity.classBits,
    entryPoints: parsed.header.entryPoint ? [{ kind: 'elf-e_entry', address: parsed.header.entryPoint }] : [],
    interpreter: parsed.interp,
    functions,
    dynamicFunctions,
    imports: parsed.imports.slice(0, Math.min(limits.maxStrings, 200)),
    exports: parsed.exports.slice(0, Math.min(limits.maxStrings, 200)),
    counts: {
      symtabPresent: parsed.symbols.symtab.present,
      symtabCount: parsed.symbols.symtab.count,
      symtabFunctions: parsed.symbols.symtab.present ? parsed.symbols.symtab.functions.length : 0,
      dynsymPresent: parsed.symbols.dynsym.present,
      dynsymCount: parsed.symbols.dynsym.count,
      undefinedDynamicSymbols: parsed.symbols.dynsym.present ? parsed.symbols.dynsym.imports.length : 0,
      definedDynamicFunctions: parsed.symbols.dynsym.present ? parsed.symbols.dynsym.exports.length : 0,
      programHeaders: parsed.programHeaders.length,
      sections: parsed.sections.length,
    },
    buildId: parsed.buildId,
    functionEstimate: {
      count: parsed.symbols.symtab.present
        ? parsed.symbols.symtab.functions.length
        : (parsed.symbols.dynsym.present ? parsed.symbols.dynsym.exports.length : 0),
      method: parsed.symbols.symtab.present
        ? 'STT_FUNC 且已定义的 .symtab 符号计数（未含静态函数以外的未知区域）'
        : '无 .symtab，仅统计已定义动态符号（偏小）',
      verification: 'hypothesis',
    },
    warnings: parsed.warnings.slice(0, 10),
  };
  return { data, findings, warnings: parsed.warnings };
}

function machoStructure(buffer, limits) {
  const parsed = parseMachO(buffer, { maxSymbols: Math.min(limits.maxStrings, 512) });
  if (!parsed.ok) return { data: { format: 'macho', parseError: parsed.reason }, findings: [], warnings: parsed.warnings || [] };
  const maxSymbols = Math.min(limits.maxStrings, 300);
  const slices = parsed.fat ? parsed.slices.filter((s) => s.ok).map((s) => s.image) : [parsed.slices[0]];
  const findings = [];
  const sliceData = slices.slice(0, 4).map((image) => {
    const functionStarts = decodeFunctionStarts(buffer, image);
    const importedSamples = image.symbolTable.importedSamples.slice(0, maxSymbols);
    const exportedSamples = image.symbolTable.exportSamples.slice(0, maxSymbols);
    return {
      arch: image.header.arch,
      bits: image.header.bits,
      entryPoints: image.entryPoint ? [{ kind: 'lc-main-entryoff', address: image.entryPoint, va: image.entryPointVa }] : [],
      functionStarts,
      symbols: {
        imports: importedSamples.map((n) => ({ name: sanitizeText(n, 200), source: 'nlist-undefined' })),
        exports: exportedSamples.map((n) => ({ name: sanitizeText(n, 200), source: 'nlist-defined' })),
      },
      counts: {
        symbolCount: image.symbolTable.count,
        undefinedImports: image.symbolTable.undefinedImports,
        definedExports: image.symbolTable.definedExports,
        dylibs: image.imports.dylibCount,
        loadCommands: image.loadCommands.length,
        sections: image.sections.length,
      },
      encryption: image.encryption,
      codesign: image.codesign,
      functionEstimate: functionStarts
        ? { count: functionStarts.entryCount, method: 'LC_FUNCTION_STARTS ULEB128 差值解码（近似；加密/剥离时可能为空）', verification: 'hypothesis' }
        : { count: image.symbolTable.definedExports, method: '无 LC_FUNCTION_STARTS，使用外部已定义符号数（偏小）', verification: 'hypothesis' },
    };
  });
  if (sliceData.some((s) => s.encryption && s.encryption.encrypted)) {
    findings.push(makeFinding({
      title: 'Mach-O 包含加密段（LC_ENCRYPTION_INFO cryptid != 0）',
      severity: 'low',
      description: '该 Mach-O 镜像声明了加密段（常见于 App Store 加密二进制）。静态符号/字符串分析可能不完整，需要授权解密后才能深入。',
      verification: 'observed',
      method: '解析 LC_ENCRYPTION_INFO(_64) 的 cryptid 字段',
      remediation: '在授权环境中获取已解密镜像或使用具备解密能力的分析流程。',
      target: null,
      evidence: sliceData.filter((s) => s.encryption).map((s) => makeEvidence('加密段', 'macho-encryption', JSON.stringify(s.encryption))),
    }));
  }
  if (sliceData.every((s) => s.functionStarts === null) && sliceData.every((s) => s.symbols.exports.length === 0)) {
    findings.push(makeFinding({
      title: 'Mach-O 函数边界信息缺失（无 function starts 且无已定义符号）',
      severity: 'info',
      description: 'LC_FUNCTION_STARTS 不可用且 nlist 中无外部已定义符号，函数级结构只能依赖反汇编。',
      verification: 'observed',
      method: '检查 LC_FUNCTION_STARTS 与 LC_SYMTAB',
      remediation: '使用授权的反汇编工具；保留样本哈希以供复核。',
      target: null,
      evidence: [],
    }));
  }
  return {
    data: { format: 'macho', fat: parsed.fat, slices: sliceData, warnings: (parsed.warnings || []).slice(0, 10) },
    findings,
    warnings: parsed.warnings || [],
  };
}

/** binary.structure implementation helper. */
export function analyzeStructure(buffer, limits) {
  const container = detectContainer(buffer);
  if (container.format === 'pe') return peStructure(buffer, limits);
  if (container.format === 'elf') return elfStructure(buffer, limits);
  if (container.format === 'macho') return machoStructure(buffer, limits);
  const otherData = {
    format: container.format,
    container: container.container,
    parseError: container.reason || null,
    note: '不是 PE/ELF/Mach-O 可执行容器，binary.structure 无法枚举函数/符号；可用 forensics.filetype、binary.strings 或相应格式的专用能力分析。',
    functions: [],
  };
  return { data: otherData, findings: [], warnings: [] };
}
