/**
 * Binary domain — container identification + summary aggregation.
 * Combines PE/ELF/Mach-O parsers, hashes, packer heuristics, overlay and embedded signatures.
 */
import { hashHex, hex } from './util.js';
import { parsePe } from './pe.js';
import { detectElf, parseElf } from './elf.js';
import { magicInfo, parseMachO } from './macho.js';

const SUSPICIOUS_IMPORTS = new Map([
  ['process-injection', /^(?:VirtualAllocEx|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|RtlCreateUserThread|QueueUserAPC|SetThreadContext|MapViewOfFile|VirtualProtectEx)$/i],
  ['anti-debug', /^(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString[AW]?|GetThreadContext|NtSetInformationThread)$/i],
  ['persistence', /^(?:RegSetValueEx[AW]?|RegCreateKeyEx[AW]?|CreateService[AW]?|ChangeServiceConfig[AW]?|StartService[AW]?)$/i],
  ['credential-access', /^(?:CredRead[AW]?|CredEnumerate[AW]?|LsaEnumerateLogonSessions|LsaOpenPolicy|OpenProcessToken|DuplicateTokenEx|ImpersonateLoggedOnUser)$/i],
  ['network', /^(?:InternetOpen[AW]?|InternetConnect[AW]?|HttpOpenRequest[AW]?|HttpSendRequest[AW]?|URLDownloadToFile[AW]?|WinHttpOpen|WinHttpConnect|WSAStartup|socket|connect|WSAConnect|send|recv)$/i],
  ['file-collection', /^(?:FindFirstFile[AW]?|FindNextFile[AW]?|CopyFile[AW]?|MoveFile[AW]?|DeleteFile[AW]?|CreateFile[AW]?|WriteFile)$/i],
  ['execution', /^(?:WinExec|ShellExecute[AW]?|CreateProcess[AW]?|CreateProcessAsUser[AW]?|system)$/i],
]);

const CONTAINER_HINTS = [
  { kind: 'zip', magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
  { kind: 'png', magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { kind: 'jpeg', magic: Buffer.from([0xff, 0xd8, 0xff]) },
  { kind: 'gzip', magic: Buffer.from([0x1f, 0x8b, 0x08]) },
  { kind: 'pdf', magic: Buffer.from('%PDF-', 'latin1') },
  { kind: 'ole2', magic: Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) },
  { kind: '7z', magic: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { kind: 'rar', magic: Buffer.from('Rar!\x1a\x07', 'latin1') },
  { kind: 'sqlite', magic: Buffer.from('SQLite format 3\u0000', 'latin1') },
];

/**
 * Detect container type. Distinct from forensics.filetype: this only needs to pick
 * the correct structural parser and stays honest about "other"/"unknown".
 */
export function detectContainer(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  if (buf.length === 0) return { format: 'unknown', container: 'empty', reason: '输入为空。' };
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    const det = detectElf(buf);
    return {
      format: 'elf',
      container: 'elf',
      bits: det.classBits,
      endianness: det.endianness,
    };
  }
  if (buf.length >= 0x40 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const pe = parsePe(buf, { maxSections: 96 });
    if (pe.ok) return { format: 'pe', container: 'pe', parsed: pe };
    return { format: 'unknown', container: 'mz-dos', reason: pe.reason, parsed: pe };
  }
  const mach = magicInfo(buf, 0);
  if (mach) {
    const parsed = parseMachO(buf, { maxSymbols: 512 });
    if (parsed.ok) {
      return {
        format: 'macho',
        container: mach.kind === 'fat' ? 'macho-fat' : 'macho-thin',
        bits: mach.bits,
        endianness: mach.endianness,
        fat: mach.kind === 'fat',
        parsed,
      };
    }
    if (parsed.javaClassCandidate) return { format: 'other', container: 'java-class', reason: parsed.reason };
    return { format: 'unknown', container: 'macho-invalid', reason: parsed.reason };
  }
  // Java class file: CAFEBABE with plausible major version; distinguished from fat Mach-O above.
  if (buf.length >= 10 && buf.readUInt32BE(0) === 0xcafebabe) {
    const minor = buf.readUInt16BE(4);
    const major = buf.readUInt16BE(6);
    if (major >= 45 && major <= 70) {
      return { format: 'other', container: 'java-class', details: { minor, major } };
    }
  }
  for (const hint of CONTAINER_HINTS) {
    if (buf.length >= hint.magic.length && buf.subarray(0, hint.magic.length).equals(hint.magic)) {
      return { format: 'other', container: hint.kind };
    }
  }
  return { format: 'unknown', container: 'unrecognized' };
}

/** Scan for embedded executable/archive signatures at non-zero offsets. Bounded. */
export function collectEmbeddedSignatures(buffer, limits = {}) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  const maxScan = Math.min(buf.length, 4 * 1024 * 1024, Math.max(1, Number(limits.maxBytes) || 4 * 1024 * 1024));
  const scan = buf.subarray(0, maxScan);
  const results = [];
  const patterns = [
    { kind: 'pe', needle: Buffer.from([0x4d, 0x5a]) },
    { kind: 'elf', needle: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
    { kind: 'zip', needle: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
    { kind: 'png', needle: Buffer.from([0x89, 0x50, 0x4e, 0x47]) },
    { kind: 'gzip', needle: Buffer.from([0x1f, 0x8b, 0x08]) },
  ];
  for (const pattern of patterns) {
    let start = 1;
    let guard = 0;
    while (start < scan.length && guard < 48 && results.length < 24) {
      guard += 1;
      const idx = scan.indexOf(pattern.needle, start);
      if (idx === -1) break;
      let confirmed = true;
      if (pattern.kind === 'pe') {
        if (idx + 0x40 <= buf.length) {
          const peOff = buf.readUInt32LE(idx + 0x3c);
          confirmed = Number.isFinite(peOff) && peOff > 0x3f && idx + peOff + 4 <= buf.length
            && buf.readUInt32LE(idx + peOff) === 0x00004550;
        } else confirmed = false;
      }
      if (confirmed) results.push({ offset: idx, kind: pattern.kind });
      start = idx + 1;
    }
  }
  results.sort((a, b) => a.offset - b.offset || a.kind.localeCompare(b.kind));
  return results.slice(0, 16);
}

/** File hashes (bounded by the bytes already read; callers report truncation). */
export function computeHashes(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  return {
    md5: hashHex(buf, 'md5'),
    sha1: hashHex(buf, 'sha1'),
    sha256: hashHex(buf, 'sha256'),
    sha512: hashHex(buf, 'sha512'),
  };
}

function suspiciousImportFindings(pe, limits) {
  const findings = [];
  const matched = new Map();
  for (const lib of pe.imports.libraries) {
    for (const fn of lib.functions) {
      if (!fn.name) continue;
      for (const [category, re] of SUSPICIOUS_IMPORTS) {
        if (re.test(fn.name)) {
          if (!matched.has(category)) matched.set(category, new Set());
          matched.get(category).add(fn.name);
        }
      }
    }
  }
  if (matched.size >= 2) {
    const parts = [...matched.entries()].map(([cat, set]) => `${cat}: ${[...set].slice(0, 6).join(', ')}`);
    findings.push({
      title: '导入表包含多类敏感 API 组合（启发式）',
      severity: 'medium',
      description: `导入的函数覆盖 ${matched.size} 类敏感能力（${[...matched.keys()].join(', ')}）。API 组合常见于注入/持久化/凭据访问工具，但也可能出现在正常软件中，需结合行为与上下文复核。`,
      verification: 'hypothesis',
      method: '导入函数名与敏感 API 类别正则匹配（静态，不执行样本）',
      cwe: 'CWE-1104',
      cvss: null,
      remediation: '在授权且隔离的环境中复核调用链与参数；结合签名、来源与动态行为确认，不要仅凭导入名定性。',
      target: null,
      evidence: [{ title: '敏感导入分组', excerpt: parts.join('\n'), meta: { categories: matcherCategories(matched) } }],
    });
  }
  return findings.slice(0, limits.maxFindings);
}

function matcherCategories(matched) {
  const out = {};
  for (const [cat, set] of matched) out[cat] = [...set].slice(0, 12);
  return out;
}

function peModel(buffer, parsed, limits) {
  if (parsed.partial) {
    const parseError = parsed.warnings[0] ?? 'PE 可选头不完整，无法分析装载目录。';
    return {
      format: 'pe',
      container: 'pe',
      arch: parsed.coff?.machineName ?? null,
      bits: null,
      endianness: 'little',
      type: parsed.coff?.characteristicFlags?.includes('dll') ? 'dll' : 'executable',
      subsystem: null,
      entryPoint: null,
      entryPointHex: null,
      entryPointVa: null,
      imageBase: null,
      sectionCount: parsed.sections?.length ?? 0,
      sections: [],
      imports: { present: null, thunkWidth: null, dllCount: 0, functionCount: 0, libraries: [], truncated: true },
      exports: { present: null, moduleName: null, functionCount: 0, namedExportCount: 0, sample: [], truncated: true },
      packer: { detected: false, suspectedFamily: null, score: 0, heuristics: [], note: 'PE 头不完整，未运行加壳启发式。' },
      overlay: { present: false, size: null, offset: null, fileSize: buffer.length, certificateTable: null },
      debugDirectories: [],
      versions: null,
      parseStatus: 'PARTIAL',
      parseError,
      warnings: parsed.warnings.slice(0, 12),
    };
  }
  const data = {
    format: 'pe',
    container: 'pe',
    arch: parsed.coff.machineName,
    bits: parsed.optional ? parsed.optional.bits : null,
    endianness: 'little',
    type: parsed.coff.characteristicFlags.includes('dll') ? 'dll' : 'executable',
    subsystem: parsed.optional ? parsed.optional.subsystemName : null,
    entryPoint: parsed.optional ? parsed.optional.entryPointRva : null,
    entryPointHex: parsed.optional ? parsed.optional.entryPointHex : null,
    entryPointVa: parsed.optional ? parsed.optional.entryPointVa : null,
    imageBase: parsed.optional ? parsed.optional.imageBaseHex : null,
    sectionCount: parsed.sections.length,
    sections: parsed.sections.slice(0, limits.maxItems).map((s) => ({
      name: s.name,
      virtualAddress: s.virtualAddress === null ? null : hex(s.virtualAddress),
      virtualSize: s.virtualSize,
      rawOffset: s.rawPointer,
      rawSize: s.rawSize,
      entropy: typeof s.entropy === 'number' ? s.entropy : null,
      flags: s.characteristicFlags,
    })),
    imports: {
      present: parsed.imports.present,
      thunkWidth: parsed.imports.thunkWidth,
      dllCount: parsed.imports.dllCount,
      functionCount: parsed.imports.functionCount,
      libraries: parsed.imports.libraries.slice(0, Math.min(limits.maxItems, 64)).map((lib) => ({
        name: lib.name,
        functionCount: lib.functionCount,
        sample: lib.functions.slice(0, 24).map((f) => f.name || `#${f.ordinal}`),
      })),
      truncated: parsed.imports.truncated,
    },
    exports: {
      present: parsed.exports.present,
      moduleName: parsed.exports.moduleName,
      functionCount: parsed.exports.functionCount,
      namedExportCount: parsed.exports.namedExportCount,
      sample: parsed.exports.exports.slice(0, Math.min(limits.maxStrings, 64)).map((e) => ({ name: e.name, ordinal: e.ordinal, address: e.address })),
      truncated: parsed.exports.truncated,
    },
    packer: {
      detected: parsed.packer.detected,
      suspectedFamily: parsed.packer.suspectedFamily,
      score: parsed.packer.score,
      heuristics: parsed.packer.heuristics.map((h) => ({ id: h.id, weight: h.weight, detail: h.detail })),
      note: parsed.packer.note,
    },
    overlay: parsed.overlay,
    debugDirectories: parsed.debug.entries.slice(0, 8).map((e) => ({
      type: e.typeName,
      timestamp: e.timestamp,
      ...(e.codeview ? { pdbPath: e.codeview.pdbPath, guid: e.codeview.guid || null } : {}),
    })),
    versions: parsed.optional ? { os: parsed.optional.osVersion, image: parsed.optional.imageVersion, subsystem: parsed.optional.subsystemVersion } : null,
    parseStatus: 'COMPLETE',
    parseError: null,
    warnings: parsed.warnings.slice(0, 12),
  };
  return data;
}

function elfModel(parsed, limits) {
  return {
    format: 'elf',
    container: 'elf',
    arch: parsed.header.machineName,
    machine: parsed.header.machineName,
    bits: parsed.identity.classBits,
    endianness: parsed.identity.endianness,
    type: parsed.header.typeName,
    entryPoint: parsed.header.entryPointNumeric !== null ? hex(parsed.header.entryPointNumeric) : parsed.header.entryPoint,
    interpreter: parsed.interp,
    osabi: parsed.identity.osabiName,
    buildId: parsed.buildId,
    sectionCount: parsed.sections.length,
    programHeaderCount: parsed.programHeaders.length,
    sections: parsed.sections.slice(0, limits.maxItems).map((s) => ({
      name: s.name,
      type: s.typeName,
      address: s.addr,
      offset: s.offset,
      size: s.size,
      flags: s.flagNames,
    })),
    imports: {
      libraries: parsed.dynamic.needed,
      undefinedSymbolCount: parsed.symbols.dynsym.present ? parsed.symbols.dynsym.imports.length : 0,
      sample: parsed.imports.slice(0, Math.min(limits.maxStrings, 64)),
      truncated: parsed.symbols.dynsym.present ? parsed.symbols.dynsym.count > 8192 : false,
    },
    exports: {
      definedSymbolCount: parsed.symbols.dynsym.present ? parsed.symbols.dynsym.exports.length : 0,
      sample: parsed.exports.slice(0, Math.min(limits.maxStrings, 64)),
    },
    dynamic: {
      soname: parsed.dynamic.soname,
      rpath: parsed.dynamic.rpath,
      runpath: parsed.dynamic.runpath,
      needed: parsed.dynamic.needed,
    },
    notes: parsed.notes.slice(0, 16),
    warnings: parsed.warnings.slice(0, 12),
  };
}

function machoModel(parsed, limits) {
  if (parsed.fat) {
    const okSlices = parsed.slices.filter((s) => s.ok);
    return {
      format: 'macho',
      container: 'macho-fat',
      arch: okSlices.length === 1 ? okSlices[0].image.header.arch : 'universal',
      archs: parsed.slices.map((s) => ({ arch: s.arch, offset: s.offset, size: s.size, ok: s.ok })),
      bits: okSlices.length ? okSlices[0].image.header.bits : null,
      endianness: okSlices.length ? okSlices[0].image.header.endianness : null,
      type: 'universal',
      entryPoint: null,
      slices: okSlices.slice(0, 8).map((s) => ({
        arch: s.image.header.arch,
        bits: s.image.header.bits,
        fileType: s.image.header.fileTypeName,
        entryPoint: s.image.entryPoint,
        uuid: s.image.uuid,
        dylibs: s.image.imports.dylibs.slice(0, 24),
        sectionCount: s.image.sections.length,
      })),
      warnings: parsed.warnings.slice(0, 12),
    };
  }
  const image = parsed.slices[0];
  return {
    format: 'macho',
    container: 'macho-thin',
    arch: image.header.arch,
    bits: image.header.bits,
    endianness: image.header.endianness,
    type: image.header.fileTypeName,
    entryPoint: image.entryPoint,
    entryPointVa: image.entryPointVa,
    uuid: image.uuid,
    buildVersion: image.buildVersion,
    sourceVersion: image.sourceVersion,
    codesign: image.codesign,
    encrypted: image.encryption,
    sectionCount: image.sections.length,
    segmentCount: image.segments.length,
    sections: image.sections.slice(0, limits.maxItems).map((s) => ({
      name: `${s.segment}.${s.name}`,
      address: s.addr,
      offset: s.offset,
      size: s.size,
      flags: s.flagNames,
    })),
    imports: {
      dylibCount: image.imports.dylibCount,
      dylibs: image.imports.dylibs,
      undefinedSymbolCount: image.imports.undefinedSymbolCount,
      sample: image.imports.sample.slice(0, 64),
    },
    exports: {
      definedSymbolCount: image.exports.definedSymbolCount,
      sample: image.exports.sample.slice(0, 64),
    },
    rpaths: image.rpaths,
    loadCommandCount: image.loadCommands.length,
    warnings: image.warnings.slice(0, 12),
  };
}

/**
 * Produce the binary.identify payload.
 * @returns {{summary:string, data:object, findings:Array, evidence:Array, warnings:string[], analyzedBytes:number}}
 */
export function identify(buffer, limits) {
  const container = detectContainer(buffer);
  const hashes = computeHashes(buffer);
  const embeddedFiles = collectEmbeddedSignatures(buffer, limits);
  const findings = [];
  const evidence = [];
  const warnings = [];
  const base = {
    fileSize: buffer.length,
    analyzedBytes: buffer.length,
    container: container.container,
    hashes,
    embeddedFiles,
    truncated: null,
  };
  let data;
  let summary;
  if (container.format === 'pe') {
    const parsed = container.parsed;
    data = { ...base, ...peModel(buffer, parsed, limits) };
    warnings.push(...parsed.warnings.slice(0, 8));
    summary = [
      `PE 文件：${data.arch || '未知架构'} ${data.bits || '?'} 位，${data.type}，子系统 ${data.subsystem || '未知'}，${data.sectionCount} 个节。`,
      `入口点 ${data.entryPointHex || 'n/a'}（VA ${data.entryPointVa || 'n/a'}），镜像基址 ${data.imageBase || 'n/a'}。`,
      `导入 ${data.imports.dllCount} 个 DLL / ${data.imports.functionCount} 个函数，导出 ${data.exports.namedExportCount} 个具名符号。`,
      `加壳启发式：${data.packer.detected ? `疑似（${data.packer.suspectedFamily || '未知家族'}，得分 ${data.packer.score}）` : '未命中明显特征'}；overlay：${data.overlay.present ? `${data.overlay.size} 字节 @ ${data.overlay.offset}` : '无'}。`,
    ].join('\n');
    if (data.packer.detected) {
      findings.push({
        title: `PE 加壳/保护器特征（疑似 ${data.packer.suspectedFamily || '未知家族'}）`,
        severity: 'medium',
        description: `静态启发式得分 ${data.packer.score}，命中条件：${data.packer.heuristics.map((h) => h.detail).join('；')}。加壳本身合法，但会影响静态分析深度，需结合样本来源判断。`,
        verification: 'hypothesis',
        method: 'PE 节名 / 导入表 / 入口点位置 / 节熵 启发式组合',
        cwe: null,
        cvss: null,
        remediation: '在授权隔离环境中进一步确认；如需完整分析，先脱壳或改用动态方式，并保留原始样本哈希。',
        target: null,
        evidence: [{ title: '加壳启发式明细', excerpt: data.packer.heuristics.map((h) => `- ${h.detail}`).join('\n'), meta: { score: data.packer.score } }],
      });
    }
    if (data.overlay.present) {
      findings.push({
        title: 'PE 存在 overlay（节后附加数据）',
        severity: 'info',
        description: `文件在最后一个节结束后仍有 ${data.overlay.size} 字节数据（offset ${data.overlay.offset}）。Overlay 可能是安装器/自解压数据，也可能是隐藏载荷。`,
        verification: 'observed',
        method: '按节表 rawPointer+rawSize 计算镜像末端，与文件长度比较',
        cwe: null,
        cvss: null,
        remediation: '提取 overlay 单独哈希分析（本工具后续可用 binary.entropy / forensics.metadata 复核）。',
        target: `offset ${data.overlay.offset}`,
        evidence: [{ title: 'Overlay 边界', excerpt: `文件长度=${data.overlay.fileSize}, 镜像末端=${data.overlay.offset}, overlay 大小=${data.overlay.size}`, meta: data.overlay.certificateTable }],
      });
    }
    if (data.imports.present && data.imports.functionCount === 0) {
      findings.push({
        title: 'PE 导入表为空',
        severity: 'low',
        description: '存在导入目录但未解析出任何导入函数，常见于加壳/手工解析导入的样本，也可能是极简可执行文件。',
        verification: 'hypothesis',
        method: '导入目录存在性 + 导入 thunk 遍历',
        cwe: null,
        cvss: null,
        remediation: '结合加壳启发式与导入表原始字节人工复核。',
        target: null,
        evidence: [{ title: '导入目录', excerpt: JSON.stringify({ present: data.imports.present, dllCount: data.imports.dllCount, functionCount: data.imports.functionCount }) }],
      });
    }
    if (!parsed.partial) findings.push(...suspiciousImportFindings(parsed, limits));
    if (data.debugDirectories.some((d) => d.pdbPath)) {
      evidence.push({
        title: '调试目录 PDB 路径',
        kind: 'pe-debug',
        excerpt: data.debugDirectories.filter((d) => d.pdbPath).map((d) => `${d.pdbPath} (${d.guid || 'n/a'})`).join('\n'),
      });
    }
  } else if (container.format === 'elf') {
    const parsed = parseElf(buffer, { maxSymbols: Math.min(limits.maxStrings, 1024) });
    if (!parsed.ok) {
      data = { ...base, format: 'elf', parseError: parsed.reason, warnings: parsed.warnings };
      warnings.push(parsed.reason);
      summary = `ELF 魔数存在但结构不可解析：${parsed.reason}`;
    } else {
      data = { ...base, ...elfModel(parsed, limits) };
      warnings.push(...parsed.warnings.slice(0, 8));
      summary = [
        `ELF 文件：${data.machine} ${data.bits} 位 ${data.endianness}-endian，类型 ${data.type}，OSABI ${data.osabi}。`,
        `入口点 ${data.entryPoint || 'n/a'}，解释器 ${data.interpreter || '无'}，build-id ${data.buildId || '缺失'}。`,
        `节 ${data.sectionCount} 个、程序头 ${data.programHeaderCount} 个；依赖库 ${data.dynamic.needed.length} 个；未定义动态符号 ${data.imports.undefinedSymbolCount} 个，导出 ${data.exports.definedSymbolCount} 个。`,
      ].join('\n');
    }
  } else if (container.format === 'macho') {
    data = { ...base, ...machoModel(container.parsed, limits) };
    warnings.push(...(container.parsed.warnings || []).slice(0, 8));
    const first = container.parsed.fat ? (container.parsed.slices.find((s) => s.ok) || {}).image : container.parsed.slices[0];
    summary = [
      container.parsed.fat
        ? `Mach-O universal 二进制，包含 ${container.parsed.archCount} 个架构切片。`
        : `Mach-O 文件：${data.arch} ${data.bits} 位 ${data.endianness}-endian，类型 ${data.type}。`,
      first ? `入口点 ${first.entryPoint || 'n/a'}，UUID ${first.uuid || '无'}，加载命令 ${first.loadCommands.length} 条，动态库 ${first.imports.dylibCount} 个。` : '',
      first && first.buildVersion ? `构建版本：${first.buildVersion.platformName} minos=${first.buildVersion.minos} sdk=${first.buildVersion.sdk}。` : '',
    ].filter(Boolean).join('\n');
  } else {
    data = {
      ...base,
      format: container.format === 'other' ? 'other' : 'unknown',
      container: container.container,
      details: container.details || null,
      notes: container.reason ? [container.reason] : [],
    };
    summary = `不是 PE/ELF/Mach-O 可执行容器，识别为 ${container.container}${container.details ? `（${JSON.stringify(container.details)}）` : ''}。可改用 forensics.filetype / forensics.metadata 进一步分析。`;
  }
  if (embeddedFiles.length > 0 && container.format !== 'unknown') {
    findings.push({
      title: '检测到内嵌文件签名',
      severity: 'low',
      description: `在文件内部偏移发现 ${embeddedFiles.length} 个疑似内嵌文件签名：${embeddedFiles.map((e) => `${e.kind}@${e.offset}`).join(', ')}。可能是合法的资源/自解压结构，也可能是隐藏载荷。`,
      verification: 'hypothesis',
      method: '全文件魔数扫描（PE 使用 PE 头二次校验）',
      cwe: null,
      cvss: null,
      remediation: '按偏移提取内嵌数据后单独哈希与结构分析，并核对样本来源。',
      target: embeddedFiles.map((e) => `${e.kind}@${e.offset}`).join(', '),
      evidence: [{ title: '内嵌签名', excerpt: embeddedFiles.map((e) => `${e.kind} offset=${e.offset}`).join('\n') }],
    });
  }
  const result = {
    summary,
    data,
    findings: findings.slice(0, limits.maxFindings),
    evidence: evidence.slice(0, 6),
    warnings,
    analyzedBytes: buffer.length,
    format: data.format,
    truncated: null,
  };
  return result;
}

export { SUSPICIOUS_IMPORTS };
