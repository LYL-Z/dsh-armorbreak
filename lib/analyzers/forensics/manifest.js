/**
 * ArmorBreak — forensics domain capability manifest.
 *
 * Domain: offline file-forensics (hashes, metadata, timelines, IOCs, heuristic rule matching, file type).
 * Hard rules honored: zero dependencies (node:* only), no sample execution, no shell, no network,
 * bounded loops, deterministic output, honest verification levels.
 */
import {
  checkAbort,
  excerptOf,
  makeEvidence,
  makeFinding,
} from '../binary/util.js';
import { finishResult, prepareInput } from './util.js';
import { hashFile, summarizeHash } from './hashes.js';
import { detectFileType } from './filetype.js';
import { extractMetadata } from './metadata.js';
import { extractTimeline } from './timeline.js';
import { extractIocs, IOC_CATEGORIES } from './ioc.js';
import { excerptAt, RULES, runYaraLite } from './yara-lite.js';

const DOMAIN = 'forensics';

const emptyParams = { type: 'object', properties: {}, additionalProperties: false };

function typeMeta(typeInfo) {
  return {
    fileType: typeInfo.type,
    category: typeInfo.category,
    mime: typeInfo.mime,
    confidence: typeInfo.confidence,
  };
}

const capabilities = [
  {
    id: 'forensics.hash',
    title: '多算法文件哈希与完整性标识',
    description: '计算 md5/sha1/sha256/sha512 文件哈希，报告字节大小、检测到的文件类型以及是否因 limits.maxBytes 被截断。用于样本登记、去重、证据固定与后续比对；输出仅覆盖核心实际传入的字节，截断时明确标注。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        algorithms: {
          type: 'array',
          items: { type: 'string', enum: ['md5', 'sha1', 'sha256', 'sha512'] },
          minItems: 1,
          maxItems: 4,
          uniqueItems: true,
          description: '要计算的算法子集，默认全部四种。',
        },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'forensics.hash';
      const prepared = prepareInput(input, capId);
      checkAbort(input.env, capId);
      const result = hashFile(prepared.buffer, input.options || {}, {
        fileSize: prepared.fileSize,
        truncated: prepared.truncated,
      });
      const warnings = result.truncated === true
        ? ['输入被截断：哈希不是完整文件哈希，不能用于与外部样本库直接比对。']
        : [];
      return finishResult({
        capId,
        format: result.type.type,
        prepared: { ...prepared, warnings: [...prepared.warnings, ...warnings] },
        summary: summarizeHash(result),
        data: result,
        findings: [],
        evidence: [makeEvidence('文件哈希', 'file-hashes', [
          `size=${result.size}${result.fileSize !== null ? ` fileSize=${result.fileSize}` : ''} truncated=${result.truncated}`,
          `type=${result.type.type} (${result.type.mime})`,
          ...result.algorithms.map((a) => `${a}=${result.digests[a]}`),
        ].join('\n'))],
        meta: { algorithms: result.algorithms, complete: result.complete },
      });
    },
  },

  {
    id: 'forensics.metadata',
    title: '文件格式元数据提取',
    description: '按文件类型提取元数据：PE 编译时间戳/版本信息/资源/调试 PDB、ELF build-id/依赖库/解释器、Mach-O UUID/build 版本/签名/加密段、ZIP 条目与注释、PNG 尺寸与文本块、JPEG EXIF、OLE2 流线索、PDF Info、gzip 原始文件名与时间。用于来源研判与构建环境泄露检查；结构事实标 observed，推断标 hypothesis。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: emptyParams,
    async run(input) {
      const capId = 'forensics.metadata';
      const prepared = prepareInput(input, capId);
      const typeInfo = detectFileType(prepared.buffer);
      checkAbort(input.env, capId);
      const outcome = extractMetadata(prepared.buffer, typeInfo, prepared.limits, input.env || {});
      checkAbort(input.env, capId);
      return finishResult({
        capId,
        format: outcome.data.format || typeInfo.type,
        prepared,
        summary: outcome.summary,
        data: outcome.data,
        findings: outcome.findings,
        evidence: outcome.evidence,
        meta: { ...typeMeta(typeInfo), parserWarnings: (outcome.warnings || []).slice(0, 8) },
      });
    },
  },

  {
    id: 'forensics.timeline',
    title: '文件内结构时间线提取',
    description: '从文件结构中提取时间戳并排序：PE COFF 编译时间与调试目录时间、ZIP 条目 DOS 时间与扩展时间戳、PNG tIME、JPEG EXIF 日期、PDF Info 创建/修改时间、gzip MTIME。输出确定性的时间有序事件列表；可选 includeTextScan 时从字符串扫描日期（明确标记为 hypothesis）。用于构建时间线、判断构建/打包顺序。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        maxEvents: { type: 'integer', minimum: 1, maximum: 1000, description: '最多返回的时间事件数，默认 200。' },
        includeTextScan: { type: 'boolean', description: '结构时间戳为空时是否扫描字符串中的日期（启发式，默认 false）。' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'forensics.timeline';
      const prepared = prepareInput(input, capId);
      const typeInfo = detectFileType(prepared.buffer);
      checkAbort(input.env, capId);
      const timeline = extractTimeline(prepared.buffer, typeInfo, prepared.limits, input.options || {}, input.env || {});
      checkAbort(input.env, capId);
      const evidence = timeline.data.events.length > 0
        ? [makeEvidence('时间线事件（按时间排序）', 'forensics-timeline', timeline.data.events.slice(0, 40).map((e) => `${e.time} [${e.source}/${e.field}] ${e.target || ''}${e.timezone === 'local-unassigned' ? ' (tz未指定)' : ''}`).join('\n'))]
        : [makeEvidence('时间线备注', 'forensics-timeline-notes', timeline.data.notes.join('\n'))];
      return finishResult({
        capId,
        format: timeline.format,
        prepared,
        summary: timeline.summary,
        data: timeline.data,
        findings: [],
        evidence,
        meta: { ...typeMeta(typeInfo), eventCount: timeline.data.eventCount },
      });
    },
  },

  {
    id: 'forensics.ioc',
    title: 'IOC 指标提取（IP/域名/URL/邮箱/哈希/注册表/路径）',
    description: '从 ASCII 与 UTF-16LE 字符串中提取 IPv4/IPv6、域名、URL、邮箱、MD5/SHA1/SHA256/SHA512、注册表路径、Windows/Unix 绝对路径，去重并统计出现次数与首次偏移，标注私有/回环等属性。只抽取指标事实，不判定恶意性；用于样本线索快速汇总与后续情报比对。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        categories: {
          type: 'array',
          items: { type: 'string', enum: IOC_CATEGORIES },
          minItems: 1,
          description: '要抽取的指标类别子集，默认全部类别。',
        },
        includePrivateIps: { type: 'boolean', description: '是否包含私有/回环 IPv4 指标，默认 true。' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'forensics.ioc';
      const prepared = prepareInput(input, capId);
      checkAbort(input.env, capId);
      const outcome = extractIocs(prepared.buffer, prepared.limits, input.options || {});
      checkAbort(input.env, capId);
      const findings = [];
      const networkUnique = (outcome.data.counts.url.unique || 0) + (outcome.data.counts.domain.unique || 0) + (outcome.data.counts.ipv4.unique || 0) + (outcome.data.counts.ipv6.unique || 0);
      if (networkUnique > 0) {
        findings.push(makeFinding({
          title: `提取到 ${networkUnique} 个网络指标（URL/域名/IP）`,
          severity: 'info',
          description: '样本字节中包含网络指标，可能对应 C2、下载源或正常联网功能；本能力只做抽取，不验证指标归属或恶意性。',
          verification: 'observed',
          method: 'ASCII+UTF-16LE 字符串提取 + 指标正则与格式校验',
          cwe: null,
          cvss: null,
          remediation: '在授权范围内用威胁情报/被动 DNS 核对指标；不要主动访问可疑地址。',
          target: null,
          evidence: [makeEvidence('网络指标样例', 'ioc-network', [
            ...(outcome.data.iocs.url || []).slice(0, 5).map((i) => `url: ${i.value}`),
            ...(outcome.data.iocs.domain || []).slice(0, 5).map((i) => `domain: ${i.value}`),
            ...(outcome.data.iocs.ipv4 || []).slice(0, 5).map((i) => `ipv4: ${i.value}`),
          ].join('\n'))],
        }));
      }
      const autorun = (outcome.data.iocs.registryKey || []).filter((i) => i.flags && i.flags.autorun);
      if (autorun.length > 0) {
        findings.push(makeFinding({
          title: `发现 ${autorun.length} 个自启动注册表路径指标`,
          severity: 'medium',
          description: '提取到 CurrentVersion\\Run / RunOnce 等自启动注册表路径字符串，常见于持久化行为，但需确认是否实际写入。',
          verification: 'hypothesis',
          method: '注册表路径正则 + 自启动位置匹配',
          cwe: 'CWE-1104',
          cvss: null,
          remediation: '定位引用字符串的代码路径，复核注册表写入 API 使用；在隔离环境验证。',
          target: null,
          evidence: [makeEvidence('自启动键样例', 'ioc-autorun', autorun.slice(0, 8).map((i) => i.value).join('\n'))],
        }));
      }
      const summary = [
        outcome.summary,
        `类别统计：${IOC_CATEGORIES.filter((c) => outcome.data.counts[c].unique > 0).map((c) => `${c}=${outcome.data.counts[c].unique}`).join(', ') || '无'}。`,
        '说明：IOC 为静态抽取结果，不包含恶意性判定。',
      ].join('\n');
      return finishResult({
        capId,
        format: detectFileType(prepared.buffer).type,
        prepared,
        summary,
        data: outcome.data,
        findings,
        evidence: [makeEvidence('IOC 类别计数', 'ioc-counts', JSON.stringify(outcome.data.counts))],
        meta: { totals: outcome.data.totals },
      });
    },
  },

  {
    id: 'forensics.yara_lite',
    title: '启发式规则匹配（yara_lite 内置规则集）',
    description: '用内置的声明式字符串/条件规则集（UPX 加壳、PowerShell 执行、进程注入 API、反调试、自启动、凭据窃取、勒索文案、加密算法、网络标记、PDB 路径等）扫描文件，同时匹配 ASCII 与 UTF-16LE。规则是启发式（hypothesis），不是 YARA 兼容格式，只用于初筛。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: {
      type: 'object',
      properties: {
        ruleIds: {
          type: 'array',
          items: { type: 'string', enum: RULES.map((r) => r.id) },
          minItems: 1,
          uniqueItems: true,
          description: '只运行指定规则 id（默认全部内置规则）。',
        },
        maxRuleMatches: { type: 'integer', minimum: 1, maximum: 12, description: '最多返回的命中规则数，默认全部。' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const capId = 'forensics.yara_lite';
      const prepared = prepareInput(input, capId);
      const typeInfo = detectFileType(prepared.buffer);
      checkAbort(input.env, capId);
      const outcome = runYaraLite(prepared.buffer, input.options || {});
      checkAbort(input.env, capId);
      const findings = outcome.data.matchedRules.map((rule) => {
        const evidenceLines = rule.matchedStrings.map((s) => {
          const first = s.firstOffsets[0];
          const snippet = typeof first === 'number' ? excerptAt(prepared.buffer, first, 40) : '';
          return `${s.value} ×${s.hitCount} @${(s.firstOffsets || []).join(',')}${snippet ? ` | ${snippet}` : ''}`;
        }).join('\n');
        return makeFinding({
          title: `规则命中：${rule.name}`,
          severity: rule.severity,
          description: `${rule.description}\n命中条件：${rule.condition.kind}${rule.condition.kind === 'count' ? `>=${rule.condition.required}` : ''}，实际命中 ${rule.condition.hitCount} 个字符串特征。`,
          verification: 'hypothesis',
          method: 'yara_lite 内置声明式字符串规则（ASCII+UTF-16LE 匹配，启发式）',
          cwe: null,
          cvss: null,
          remediation: '命中只是静态字符串组合证据：请结合上下文、签名、来源与（授权环境下的）动态行为复核，勿单独据此定性。',
          target: typeof rule.matchedStrings[0]?.firstOffsets[0] === 'number' ? `offset ${rule.matchedStrings[0].firstOffsets[0]}` : null,
          evidence: [makeEvidence(`规则 ${rule.ruleId} 命中串`, 'yara-lite-match', evidenceLines)],
        });
      });
      const summary = outcome.data.matchedCount > 0
        ? `yara_lite：命中 ${outcome.data.matchedCount} 条规则（${outcome.data.matchedRules.map((r) => `${r.ruleId}:${r.severity}`).join(', ')}）；扫描 ${outcome.data.scannedBytes} 字节。结果为启发式 hypothesis。`
        : `yara_lite：${outcome.data.ruleset.selectedRuleCount} 条规则均未命中（扫描 ${outcome.data.scannedBytes} 字节）。`;
      return finishResult({
        capId,
        format: typeInfo.type,
        prepared: { ...prepared, warnings: [...prepared.warnings, ...outcome.warnings] },
        summary,
        data: outcome.data,
        findings,
        evidence: [makeEvidence('规则集信息', 'yara-lite-ruleset', `${outcome.data.ruleset.name} v${outcome.data.ruleset.version}（${outcome.data.ruleset.ruleCount} 条规则，启发式）`)],
        meta: { matchedCount: outcome.data.matchedCount, ...typeMeta(typeInfo) },
      });
    },
  },

  {
    id: 'forensics.filetype',
    title: '文件类型识别（魔数与内容特征）',
    description: '基于魔数与内容特征识别可执行文件、压缩包、Office/OOXML/APK/JAR、图片、音视频、字体、数据库、网络抓包、脚本与文本、Java class/DEX/WASM 等，并给出类别、MIME、置信度与检测细节（如 PE 架构、ZIP 子类型、PNG/JPEG 尺寸）。用于在打开/解析前确定正确分析路径。',
    riskLevel: 'L0',
    targetKind: 'file',
    params: emptyParams,
    async run(input) {
      const capId = 'forensics.filetype';
      const prepared = prepareInput(input, capId);
      checkAbort(input.env, capId);
      const typeInfo = detectFileType(prepared.buffer);
      checkAbort(input.env, capId);
      const magicHex = prepared.buffer.subarray(0, 32).toString('hex');
      const asciiExcerpt = excerptOf(prepared.buffer.subarray(0, 256).toString('latin1').replace(/[^\x20-\x7e\n\t]/g, '.'), 400);
      const data = {
        type: typeInfo.type,
        category: typeInfo.category,
        mime: typeInfo.mime,
        confidence: typeInfo.confidence,
        extensions: typeInfo.extensions,
        details: typeInfo.details,
        notes: typeInfo.notes,
        size: prepared.buffer.length,
        magic: { offset: 0, hex: magicHex, ascii: asciiExcerpt },
      };
      return finishResult({
        capId,
        format: typeInfo.type,
        prepared,
        summary: `文件类型：${typeInfo.type}（类别 ${typeInfo.category}，MIME ${typeInfo.mime}，置信度 ${typeInfo.confidence}，${prepared.buffer.length} 字节）。${typeInfo.notes.length > 0 ? `\n备注：${typeInfo.notes.join('；')}` : ''}`,
        data,
        findings: [],
        evidence: [makeEvidence('文件魔数', 'filetype-magic', `hex(32)=${magicHex}\nascii=${asciiExcerpt}`)],
        meta: typeMeta(typeInfo),
      });
    },
  },
];

export default {
  domain: DOMAIN,
  capabilities,
};
