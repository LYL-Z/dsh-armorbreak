/**
 * ArmorBreak — binary domain capability manifest.
 *
 * Domain: offline static analysis of PE/ELF/Mach-O executables.
 * Hard rules honored: zero dependencies (node:* only), no sample execution,
 * no shell, no network, bounded loops, deterministic output, honest verification levels.
 */
import {
  checkAbort,
  enforceDataSize,
  excerptOf,
  makeEvidence,
  makeFinding,
  makeMeta,
  normalizeLimits,
  requireBytes,
  sanitizeText,
  truncationInfo,
} from './util.js';
import { analyzeEntropy, sectionsForEntropy, segmentEntropies } from './entropy.js';
import { detectContainer, identify } from './identify.js';
import { parsePe } from './pe.js';
import { parseElf } from './elf.js';
import { parseMachO } from './macho.js';
import { extractBinaryStrings, interestingStrings, STRING_CATEGORIES } from './strings.js';
import { analyzeStructure } from './structure.js';

const DOMAIN = 'binary';

function prepare(input, capId) {
  const { buffer, source, warnings } = requireBytes(input, capId);
  const limits = normalizeLimits(input.limits);
  const trunc = truncationInfo(input, buffer.length);
  const allWarnings = [...warnings, ...trunc.warnings];
  return { buffer, source, limits, trunc, warnings: allWarnings };
}

function finish({ capId, format, prepared, summary, data, findings = [], evidence = [], meta = {} }) {
  const warnings = [...prepared.warnings];
  const finalData = enforceDataSize(data, warnings);
  return {
    summary: sanitizeText(summary, 4000),
    findings: findings.slice(0, prepared.limits.maxFindings),
    evidence: evidence.slice(0, 8),
    data: finalData,
    meta: {
      ...makeMeta(capId, format, {
        analyzedBytes: prepared.buffer.length,
        source: prepared.source,
        truncated: prepared.trunc.truncated,
      }, warnings),
      fileSize: prepared.trunc.fileSize,
      ...meta,
    },
  };
}

const emptyParams = { type: 'object', properties: {}, additionalProperties: false };

const capabilities = [
  {
    id: 'binary.identify',
    title: '可执行文件类型与架构识别',
    description: '识别 PE/ELF/Mach-O（含 fat/universal）容器、CPU 架构、位数、端序、类型、入口点、节表摘要、导入/导出、加壳启发式、overlay、文件哈希与内嵌文件签名。用于样本初筛与决定后续分析路径，纯离线只读。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: emptyParams,
    async run(input) {
      const capId = 'binary.identify';
      const prepared = prepare(input, capId);
      checkAbort(input.env, capId);
      const result = identify(prepared.buffer, prepared.limits);
      checkAbort(input.env, capId);
      return finish({
        capId,
        format: result.format,
        prepared,
        summary: `${result.summary}\n哈希：MD5 ${result.data.hashes.md5} / SHA-256 ${result.data.hashes.sha256}。`,
        data: {
          ...result.data,
          ...(prepared.trunc.fileSize !== null ? { fileSize: prepared.trunc.fileSize, truncated: prepared.trunc.truncated } : {}),
        },
        findings: result.findings,
        evidence: [
          {
            title: '文件身份与哈希',
            kind: 'binary-identity',
            excerpt: [
              `format=${result.data.format} container=${result.data.container}`,
              `arch=${result.data.arch || 'n/a'} bits=${result.data.bits || 'n/a'} endianness=${result.data.endianness || 'n/a'}`,
              `entry=${result.data.entryPointHex || result.data.entryPoint || 'n/a'}`,
              `md5=${result.data.hashes.md5}`,
              `sha256=${result.data.hashes.sha256}`,
              `analyzedBytes=${prepared.buffer.length}${prepared.trunc.truncated === true ? ` (fileSize=${prepared.trunc.fileSize})` : ''}`,
            ].join('\n'),
          },
          ...result.evidence,
        ],
        meta: { warnings: result.warnings.slice(0, 8) },
      });
    },
  },

  {
    id: 'binary.strings',
    title: 'ASCII / UTF-16LE 字符串提取与分类',
    description: '从二进制中提取可打印 ASCII 与 UTF-16LE 字符串（可设最小长度），并分类 URL、域名、IPv4、邮箱、注册表路径、文件路径、Windows API、命令片段、加密算法标识、GUID、PDB 路径、疑似 Base64。用于 IOC 初筛、功能线索与加壳判断的输入。输出有界且去除控制字符。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        minLength: { type: 'integer', minimum: 4, maximum: 64, description: '最短字符串长度，默认 4。' },
        includeUtf16: { type: 'boolean', description: '是否提取 UTF-16LE 宽字符串，默认 true。' },
        onlyInteresting: { type: 'boolean', description: '只输出已分类的“有意义”字符串样本，默认 false。' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'binary.strings';
      const prepared = prepare(input, capId);
      const opts = input.options || {};
      const minLen = Number.isFinite(opts.minLength) ? Math.max(4, Math.min(64, Math.floor(opts.minLength))) : 4;
      const includeUtf16 = opts.includeUtf16 !== false;
      checkAbort(input.env, capId);
      const extraction = extractBinaryStrings(prepared.buffer, {
        minLen,
        max: Math.min(prepared.limits.maxStrings, 2000),
      });
      checkAbort(input.env, capId);
      const categories = extraction.categories;
      const interesting = interestingStrings(extraction, 16);
      const allSamples = extraction.all
        .slice(0, prepared.limits.maxStrings)
        .map((s) => ({ offset: s.offset, encoding: s.encoding, value: sanitizeText(s.value, 512) }));
      const findings = [];
      const commandCount = categories.counts.command || 0;
      const urlCount = categories.counts.url || 0;
      const registryCount = categories.counts.registryKey || 0;
      const pdbCount = categories.counts.pdbPath || 0;
      if (commandCount > 0) {
        findings.push(makeFinding({
          title: `发现 ${commandCount} 条命令执行/脚本相关字符串`,
          severity: 'medium',
          description: '样本包含 powershell/cmd/mshta 等命令解释器或脚本调用片段。仅字符串存在不能证明执行，需结合上下文与行为复核。',
          verification: 'hypothesis',
          method: 'ASCII+UTF-16LE 字符串提取 + 命令模式正则匹配',
          cwe: 'CWE-78',
          cvss: null,
          remediation: '定位引用这些字符串的代码路径并人工复核参数来源；在隔离环境中进行动态验证。',
          target: null,
          evidence: [makeEvidence('命令字符串样例', 'strings-command', (categories.samples.command || []).slice(0, 6).map((s) => s.value).join('\n'))],
        }));
      }
      if (registryCount > 0) {
        const hasRunKey = (categories.samples.registryKey || []).some((s) => /CurrentVersion\\+Run/i.test(s.value));
        findings.push(makeFinding({
          title: `发现 ${registryCount} 条注册表路径字符串${hasRunKey ? '（含 Run 自启动键）' : ''}`,
          severity: hasRunKey ? 'medium' : 'info',
          description: hasRunKey
            ? '样本字符串包含 CurrentVersion\\Run 自启动注册表路径，常见于持久化行为，但需确认是否实际写入。'
            : '样本字符串包含硬编码注册表路径，可能用于配置读写或持久化；未观察到实际写入行为。',
          verification: 'hypothesis',
          method: '字符串提取 + 注册表路径模式匹配',
          cwe: hasRunKey ? 'CWE-1104' : null,
          cvss: null,
          remediation: '定位引用字符串的代码并复核注册表操作 API（如 RegSetValueEx）的使用。',
          target: null,
          evidence: [makeEvidence('注册表路径样例', 'strings-registry', (categories.samples.registryKey || []).slice(0, 6).map((s) => s.value).join('\n'))],
        }));
      }
      if (urlCount > 0) {
        findings.push(makeFinding({
          title: `发现 ${urlCount} 条 URL/FTP 字符串`,
          severity: 'info',
          description: '样本包含网络地址字符串，可能用于更新、回连或正常网络功能；未观察到网络行为本身。',
          verification: 'hypothesis',
          method: '字符串提取 + URL 正则匹配',
          cwe: null,
          cvss: null,
          remediation: '如需确认是否为 C2，请在授权且隔离环境做动态网络分析，并核对域名归属与时间。',
          target: null,
          evidence: [makeEvidence('URL 样例', 'strings-url', (categories.samples.url || []).slice(0, 6).map((s) => s.value).join('\n'))],
        }));
      }
      if (pdbCount > 0) {
        findings.push(makeFinding({
          title: `发现 ${pdbCount} 条 PDB 调试路径字符串`,
          severity: 'info',
          description: 'PDB 路径可能泄露开发者用户名/构建目录等环境信息；也可能是正常构建产物。',
          verification: 'observed',
          method: '字符串提取 + .pdb 路径模式匹配',
          cwe: 'CWE-538',
          cvss: null,
          remediation: '发布前剥离调试信息；对泄露路径信息做脱敏处理。',
          target: null,
          evidence: [makeEvidence('PDB 路径样例', 'strings-pdb', (categories.samples.pdbPath || []).slice(0, 6).map((s) => s.value).join('\n'))],
        }));
      }
      const summary = [
        `提取字符串：ASCII ${extraction.asciiCount} 条，UTF-16LE ${extraction.utf16Count} 条（maxStrings=${prepared.limits.maxStrings}${extraction.truncated ? '，已达上限并截断' : ''}）。`,
        `分类计数：${STRING_CATEGORIES.map((c) => `${c}=${categories.counts[c] || 0}`).join(', ')}。`,
        interesting.length > 0 ? `高价值样例：${interesting.slice(0, 5).map((i) => `[${i.category}] ${i.value}`).join(' | ')}` : '未命中高价值分类模式。',
      ].join('\n');
      const data = {
        counts: {
          ascii: extraction.asciiCount,
          utf16le: extraction.utf16Count,
          total: extraction.asciiCount + extraction.utf16Count,
          categorized: categories.totalCategorized,
        },
        categoryCounts: categories.counts,
        categorySamples: categories.samples,
        strings: opts.onlyInteresting === true ? interesting.map((i) => ({ category: i.category, value: i.value })) : allSamples,
        truncated: extraction.truncated,
        minLength: minLen,
        includeUtf16,
      };
      return finish({
        capId,
        format: detectContainer(prepared.buffer).format,
        prepared,
        summary,
        data,
        findings,
        evidence: [
          {
            title: '高价值字符串样例',
            kind: 'binary-strings',
            excerpt: excerptOf(interesting.map((i) => `[${i.category}] ${i.value}`).join('\n'), 2000),
          },
        ],
        meta: { extractedCount: data.counts.total, categories: categoryCountsMeta(categories.counts) },
      });
    },
  },

  {
    id: 'binary.entropy',
    title: '整体/分块/分节熵计算与压缩加密提示',
    description: '计算文件整体香农熵、分块熵地图（块大小与块数有界）以及 PE/ELF/Mach-O 各节熵，给出压缩/加密/加壳的启发式提示与零字节占比等统计。用于判断是否需要脱壳或把高熵数据单独提取。结果是统计提示，不是加壳确认。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        blockSize: { type: 'integer', minimum: 256, maximum: 1048576, description: '分块大小（字节），默认 4096；文件较大时会自动放大以限制块数。' },
        maxBlocks: { type: 'integer', minimum: 1, maximum: 5000, description: '最大块数，默认 256。' },
        includeSections: { type: 'boolean', description: '是否计算容器节级熵，默认 true。' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'binary.entropy';
      const prepared = prepare(input, capId);
      const opts = input.options || {};
      const blockSize = Number.isFinite(opts.blockSize) ? Math.max(256, Math.min(1048576, Math.floor(opts.blockSize))) : 4096;
      const maxBlocks = Number.isFinite(opts.maxBlocks) ? Math.max(1, Math.min(5000, Math.floor(opts.maxBlocks))) : Math.min(prepared.limits.maxItems, 256);
      checkAbort(input.env, capId);
      const analysis = analyzeEntropy(prepared.buffer, { blockSize, maxBlocks });
      checkAbort(input.env, capId);
      const container = detectContainer(prepared.buffer);
      let sectionEntropies = [];
      let sectionsTruncated = false;
      if (opts.includeSections !== false && container.format !== 'unknown' && container.format !== 'other') {
        const segments = sectionsForEntropy(container.format, container.parsed || parseForEntropy(container, prepared));
        sectionEntropies = segmentEntropies(prepared.buffer, segments, Math.min(prepared.limits.maxItems, 128));
        sectionsTruncated = segments.length > sectionEntropies.length;
      }
      const highSections = sectionEntropies.filter((s) => s.entropy !== null && s.entropy >= 7.2);
      const findings = [];
      if (analysis.likelyPackedOrEncrypted) {
        findings.push(makeFinding({
          title: '熵分析提示压缩/加密数据（疑似加壳或加密载荷）',
          severity: 'medium',
          description: `整体熵 ${analysis.overall.entropy} bits/byte，${analysis.highEntropyBlockCount}/${analysis.blockCount} 个块熵 ≥ 7.2。高熵可能来自压缩的资源、加密配置或加壳，不能单独作为恶意结论。`,
          verification: 'hypothesis',
          method: 'Shannon 熵（整体 + 分块）+ 可打印字符/零字节统计',
          cwe: null,
          cvss: null,
          remediation: '结合 binary.identify 的加壳启发式与字符串占比复核；必要时在授权环境脱壳后再分析。',
          target: null,
          evidence: [makeEvidence('熵提示', 'entropy-hints', analysis.hints.map((h) => `- [${h.severity}] ${h.detail}`).join('\n'))],
        }));
      }
      if (highSections.length > 0) {
        findings.push(makeFinding({
          title: `${highSections.length} 个节/段熵 ≥ 7.2 bits/byte`,
          severity: 'info',
          description: `高熵节：${highSections.map((s) => `${s.name}(${s.entropy})`).join(', ')}。可能是压缩/加密代码或数据、也可能只是随机资源。`,
          verification: 'observed',
          method: '节级 Shannon 熵计算（observed 数值），语义解释为 hypothesis',
          cwe: null,
          cvss: null,
          remediation: '对高熵节单独提取并做字符串/结构分析；确认是否属于正常资源。',
          target: null,
          evidence: [makeEvidence('节熵', 'entropy-sections', JSON.stringify(highSections.slice(0, 12)))],
        }));
      }
      const summary = [
        `整体熵 ${analysis.overall.entropy} bits/byte（${analysis.overall.classification}），分析字节 ${analysis.overall.analyzedBytes}。`,
        `分块：${analysis.blockCount} 块 × ${analysis.blockSize} 字节，高熵块 ${analysis.highEntropyBlockCount}，零字节占比 ${(analysis.overall.stats.zeroByteRatio * 100).toFixed(1)}%，可打印占比 ${(analysis.overall.stats.printableRatio * 100).toFixed(1)}%。`,
        sectionEntropies.length > 0 ? `节熵：${sectionEntropies.slice(0, 8).map((s) => `${s.name || '(无名)'}=${s.entropy ?? 'n/a'}`).join(', ')}。` : '未解析到节级熵（未知容器或未启用）。',
        `提示：${analysis.hints.map((h) => h.detail).join('；')}`,
      ].join('\n');
      const data = {
        overall: analysis.overall,
        blockSize: analysis.blockSize,
        blockCount: analysis.blockCount,
        blocks: analysis.blocks,
        highEntropyBlockCount: analysis.highEntropyBlockCount,
        zeroBlockCount: analysis.zeroBlockCount,
        sectionEntropies,
        sectionsTruncated,
        hints: analysis.hints,
        likelyPackedOrEncrypted: analysis.likelyPackedOrEncrypted,
      };
      return finish({
        capId,
        format: container.format,
        prepared,
        summary,
        data,
        findings,
        evidence: [makeEvidence('熵摘要', 'binary-entropy', summary.slice(0, 2000))],
        meta: { blockSize: analysis.blockSize, blockCount: analysis.blockCount },
      });
    },
  },

  {
    id: 'binary.headers',
    title: 'PE/ELF/Mach-O 头部结构转储',
    description: '转储 PE COFF 头/可选头/数据目录/节表标志，ELF 标识与程序头表（含解释器），Mach-O 头/加载命令/段与 fat 切片概览。用于核对编译选项、缓解措施（ASLR/DEP/CFG）与加载结构；空/畸形输入返回结构化说明而不是崩溃。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: emptyParams,
    async run(input) {
      const capId = 'binary.headers';
      const prepared = prepare(input, capId);
      checkAbort(input.env, capId);
      const container = detectContainer(prepared.buffer);
      let data;
      let summary;
      const findings = [];
      const evidence = [];
      if (container.format === 'pe') {
        const pe = parsePe(prepared.buffer, { maxSections: Math.min(prepared.limits.maxItems, 96) });
        if (!pe.ok) {
          data = { format: 'pe', container: 'pe', parseError: pe.reason, warnings: pe.warnings };
          summary = `PE 结构不可解析：${pe.reason}`;
        } else {
          const optional = pe.optional ? { ...pe.optional, imageBase: pe.optional.imageBaseHex } : null;
          data = {
            format: 'pe',
            peOffset: pe.peOffset,
            coffHeader: pe.coff,
            optionalHeader: optional,
            dataDirectories: pe.directories,
            sectionFlags: pe.sections.map((s) => ({ name: s.name, virtualAddress: s.virtualAddress === null ? null : `0x${s.virtualAddress.toString(16)}`, virtualSize: s.virtualSize, rawPointer: s.rawPointer, rawSize: s.rawSize, characteristicFlags: s.characteristicFlags })),
            hardening: optional ? {
              aslr: optional.dllCharacteristicFlags.includes('dynamic-base (ASLR)'),
              dep: optional.dllCharacteristicFlags.includes('nx-compat (DEP)'),
              cfg: optional.dllCharacteristicFlags.includes('guard-cf (CFG)'),
              highEntropyVa: optional.dllCharacteristicFlags.includes('high-entropy-va'),
              flags: optional.dllCharacteristicFlags,
            } : null,
            note: '未校验 PE CheckSum 字段；此处只做结构转储，不验证签名。',
            warnings: pe.warnings,
          };
          summary = [
            `PE 头：machine=${pe.coff.machineName}，${optional ? optional.bits : '?'} 位，${pe.sections.length} 个节，${pe.directories.filter((d) => d.present).length} 个非空数据目录。`,
            optional ? `可选头：magic=${optional.magic}，imageBase=${optional.imageBase}，entry=0x${(optional.entryPointRva || 0).toString(16)}，subsystem=${optional.subsystemName}，align=${optional.sectionAlignment}/${optional.fileAlignment}。` : '可选头不可用。',
            data.hardening ? `缓解措施：ASLR=${data.hardening.aslr ? 'on' : 'off'}，DEP=${data.hardening.dep ? 'on' : 'off'}，CFG=${data.hardening.cfg ? 'on' : 'off'}。` : '',
          ].filter(Boolean).join('\n');
          if (data.hardening && !data.hardening.aslr && !data.hardening.dep) {
            findings.push(makeFinding({
              title: 'PE 未启用 ASLR 与 DEP（DllCharacteristics 缺失）',
              severity: 'info',
              description: 'DllCharacteristics 中 DYNAMIC_BASE（ASLR）与 NX_COMPAT（DEP）均未设置，说明构建时未启用这两项常见内存缓解措施。这是构建属性观察，不等于存在漏洞。',
              verification: 'observed',
              method: '解析 PE 可选头 DllCharacteristics 位标志',
              cwe: null,
              cvss: null,
              remediation: '如为自研软件，建议使用 /DYNAMICBASE /NXCOMPAT 重新编译；若是第三方样本仅作为分析信息记录。',
              target: null,
              evidence: [makeEvidence('DllCharacteristics', 'pe-hardening', JSON.stringify({ value: optional ? optional.dllCharacteristics : null, flags: data.hardening.flags }))],
            }));
          }
          evidence.push(makeEvidence('PE 头部结构', 'pe-headers', [
            `machine=${pe.coff.machineName} sections=${pe.sections.length} timestamp=${pe.coff.compiledAt || 'n/a'}`,
            `directories=${pe.directories.map((d) => `${d.name}:${d.present ? `0x${d.rva.toString(16)}+${d.size}` : 'empty'}`).join(', ')}`,
          ].join('\n')));
        }
      } else if (container.format === 'elf') {
        const elf = parseElf(prepared.buffer, { maxSymbols: 0, maxProgramHeaders: Math.min(prepared.limits.maxItems, 256) });
        if (!elf.ok) {
          data = { format: 'elf', container: 'elf', parseError: elf.reason, warnings: elf.warnings };
          summary = `ELF 结构不可解析：${elf.reason}`;
        } else {
          data = {
            format: 'elf',
            identity: elf.identity,
            header: elf.header,
            programHeaders: elf.programHeaders,
            programHeaderCount: elf.programHeaders.length,
            interpreter: elf.interp,
            buildId: elf.buildId,
            notes: elf.notes.slice(0, 16),
            hardening: {
              nx: elf.programHeaders.some((p) => p.typeName === 'gnu-stack' && Array.isArray(p.flagNames) && !p.flagNames.includes('x')),
              pie: elf.header.typeName === 'shared-object' && Boolean(elf.interp),
              relro: elf.programHeaders.some((p) => p.typeName === 'gnu-relro'),
              stackCanarySymbol: Array.isArray(elf.symbols.dynsym.imports) && elf.symbols.dynsym.imports.some((s) => /__stack_chk_fail/.test(s.name || '')),
            },
            note: 'ELF 无内建编译时间戳；时间信息通常来自构建系统/打包流程。',
            warnings: elf.warnings,
          };
          summary = [
            `ELF 头：${elf.header.machineName} ${elf.identity.classBits} 位 ${elf.identity.endianness}-endian，type=${elf.header.typeName}，osabi=${elf.identity.osabiName}，entry=${elf.header.entryPoint || 'n/a'}。`,
            `程序头 ${elf.programHeaders.length} 个，解释器 ${elf.interp || '无'}，build-id ${elf.buildId || '缺失'}。`,
            `硬ening：NX=${data.hardening.nx ? 'on' : 'off'}，PIE/Loader=${data.hardening.pie ? 'yes' : 'no'}，RELRO=${data.hardening.relro ? 'yes' : 'no'}，stack-canary 导入=${data.hardening.stackCanarySymbol ? 'yes' : 'no'}。`,
          ].join('\n');
          evidence.push(makeEvidence('ELF 程序头', 'elf-headers', elf.programHeaders.slice(0, 16).map((p) => `${p.typeName} off=0x${(p.offset || 0).toString(16)} vaddr=${p.vaddr} flags=${p.flags}`).join('\n')));
        }
      } else if (container.format === 'macho') {
        const macho = parseMachO(prepared.buffer, { maxSymbols: 0 });
        if (!macho.ok) {
          data = { format: 'macho', parseError: macho.reason, warnings: macho.warnings || [] };
          summary = `Mach-O 结构不可解析：${macho.reason}`;
        } else if (macho.fat) {
          data = {
            format: 'macho',
            container: 'macho-fat',
            archCount: macho.archCount,
            slices: macho.slices.map((s) => (s.ok ? {
              arch: s.arch,
              offset: s.offset,
              size: s.size,
              header: s.image.header,
              loadCommandCount: s.image.loadCommands.length,
              uuid: s.image.uuid,
              entryPoint: s.image.entryPoint,
              dylibs: s.image.imports.dylibs.slice(0, 32),
              buildVersion: s.image.buildVersion,
            } : { arch: s.arch, offset: s.offset, size: s.size, ok: false, reason: s.reason })),
            warnings: macho.warnings,
          };
          summary = `Mach-O universal：${macho.archCount} 个切片（${macho.slices.map((s) => `${s.arch}${s.ok ? '' : '(损坏)'}`).join(', ')}）。`;
          evidence.push(makeEvidence('fat 架构表', 'macho-fat', macho.slices.map((s) => `${s.arch} offset=${s.offset} size=${s.size} ok=${s.ok}`).join('\n')));
        } else {
          const image = macho.slices[0];
          data = {
            format: 'macho',
            container: 'macho-thin',
            header: image.header,
            uuid: image.uuid,
            entryPoint: image.entryPoint,
            entryPointVa: image.entryPointVa,
            buildVersion: image.buildVersion,
            sourceVersion: image.sourceVersion,
            segments: image.segments,
            loadCommands: image.loadCommands,
            loadCommandCount: image.loadCommands.length,
            dylibs: image.dylibs,
            rpaths: image.rpaths,
            codesign: image.codesign,
            encryption: image.encryption,
            hardening: {
              pie: Boolean(image.header.flagNames && image.header.flagNames.includes('pie')),
              hardened: Boolean(image.codesign),
              encrypted: Boolean(image.encryption && image.encryption.encrypted),
              stackCanarySymbol: Array.isArray(image.imports.sample) && image.imports.sample.includes('___stack_chk_fail'),
            },
            warnings: image.warnings,
          };
          summary = [
            `Mach-O 头：${image.header.arch} ${image.header.bits} 位，type=${image.header.fileTypeName}，load commands ${image.loadCommands.length} 条，segments ${image.segments.length} 个，sections ${image.sections.length} 个。`,
            `UUID ${image.uuid || '无'}，entry=${image.entryPoint || 'n/a'}，codesign=${image.codesign ? `offset=${image.codesign.dataOffset} size=${image.codesign.dataSize}` : '无'}，加密=${image.encryption && image.encryption.encrypted ? 'yes' : 'no'}。`,
            `dylibs：${image.imports.dylibs.slice(0, 8).join(', ') || '无'}`,
          ].join('\n');
          evidence.push(makeEvidence('Mach-O 加载命令', 'macho-headers', image.loadCommands.slice(0, 24).map((c) => `${c.command} (size=${c.size})`).join('\n')));
        }
      } else {
        data = { format: container.format, container: container.container, parseError: container.reason || null, note: '不是 PE/ELF/Mach-O 容器，binary.headers 无法转储可执行文件头；可改用 forensics.metadata / forensics.filetype。' };
        summary = `输入不是 PE/ELF/Mach-O 容器（识别为 ${container.container}），无结构头可转储。`;
      }
      return finish({
        capId,
        format: data.format,
        prepared,
        summary,
        data,
        findings,
        evidence,
        meta: { parserWarnings: Array.isArray(data.warnings) ? data.warnings.slice(0, 8) : [] },
      });
    },
  },

  {
    id: 'binary.structure',
    title: '符号/函数结构启发式提取',
    description: '从 PE（COFF 符号表、导出表、异常目录、导入 thunk）、ELF（.symtab/.dynsym 函数符号、入口点、build-id）与 Mach-O（nlist 符号、LC_FUNCTION_STARTS、加密段）提取函数/符号结构，并给出带方法说明的函数数量估计。所有数量估计标注为 hypothesis；输入非可执行容器时返回结构化说明。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        maxSymbols: { type: 'integer', minimum: 1, maximum: 300, description: '每个列表最多返回的符号数，默认 120。' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'binary.structure';
      const prepared = prepare(input, capId);
      checkAbort(input.env, capId);
      const result = analyzeStructure(prepared.buffer, prepared.limits);
      checkAbort(input.env, capId);
      return finish({
        capId,
        format: result.data.format,
        prepared,
        summary: summarizeStructure(result.data),
        data: result.data,
        findings: result.findings,
        evidence: [makeEvidence('结构统计', 'binary-structure', JSON.stringify(result.data.counts || result.data.note || {}).slice(0, 2000))],
        meta: { parserWarnings: result.warnings.slice(0, 8) },
      });
    },
  },
];

function summarizeStructure(data) {
  if (data.parseError) return `结构解析失败：${data.parseError}${data.note ? `\n${data.note}` : ''}`;
  if (data.format === 'pe') {
    return [
      `PE 结构：${data.counts.coffSymbols} 个 COFF 符号（函数 ${data.counts.coffFunctions}），导出函数 ${data.counts.exportFunctions}（具名 ${data.counts.namedExports}），导入函数 ${data.counts.importFunctions}。`,
      `函数数量估计约 ${data.functionEstimate.count}（方法：${data.functionEstimate.method}）。`,
      data.exceptionDirectory.present ? `异常目录约 ${data.exceptionDirectory.approxCount ?? 'n/a'} 条 RUNTIME_FUNCTION。` : '无异常目录。',
    ].join('\n');
  }
  if (data.format === 'elf') {
    return [
      `ELF 结构：.symtab ${data.counts.symtabPresent ? `存在（${data.counts.symtabFunctions} 个函数）` : '不存在（strip）'}；.dynsym ${data.counts.dynsymPresent ? `存在（未定义 ${data.counts.undefinedDynamicSymbols}，已定义函数 ${data.counts.definedDynamicFunctions}）` : '不存在'}。`,
      `入口 ${data.entryPoints[0] ? data.entryPoints[0].address : 'n/a'}，解释器 ${data.interpreter || '无'}，build-id ${data.buildId || '缺失'}。`,
      `函数数量估计约 ${data.functionEstimate.count}（方法：${data.functionEstimate.method}）。`,
    ].join('\n');
  }
  if (data.format === 'macho') {
    return data.slices.map((s) => {
      const fs = s.functionStarts;
      return `${s.arch}：符号 ${s.counts.symbolCount}（未定义导入 ${s.counts.undefinedImports}，已定义导出 ${s.counts.definedExports}），function-starts ${fs ? fs.entryCount : '不可用'}，估计函数约 ${s.functionEstimate.count}（${s.functionEstimate.method}）。`;
    }).join('\n');
  }
  return `格式 ${data.format || 'unknown'}：${data.note || '无结构信息。'}`;
}

function categoryCountsMeta(counts) {
  const out = {};
  for (const [k, v] of Object.entries(counts)) if (v > 0) out[k] = v;
  return out;
}

function parseForEntropy(container, prepared) {
  if (container.format === 'elf') return parseElf(prepared.buffer, { maxSymbols: 0 });
  if (container.format === 'macho') return parseMachO(prepared.buffer, { maxSymbols: 0 });
  return null;
}

export default {
  domain: DOMAIN,
  capabilities,
};
