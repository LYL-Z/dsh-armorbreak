// ArmorBreak SAST domain — capability manifest (source / supply-chain analysis).
// All capabilities are offline (riskLevel L0) and zero-dependency.

import {
  baseName,
  clampInt,
  collectSources,
  compact,
  severityRank,
  sortFindings,
} from './common.js';
import { auditManifests, collectManifests, KNOWN_RISKY, manifestKindForFile } from './deps.js';
import { buildPatchSuggestion, extractFindingInput } from './patch.js';
import { buildSbomFromSources, isManifestPath } from './sbom.js';
import { scanSources } from './scanner.js';
import { scanSecrets } from './secrets.js';
import { LANGUAGES, RULES, RULES_BY_ID, languageForFile } from './rules.js';
import { semgrepCapability, trivyCapability } from './external-adapters.js';
import { syftCapability } from './syft.js';

const MIN_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];

function budget(input) {
  const limits = input.limits ?? {};
  return {
    maxBytes: clampInt(limits.maxBytes, 1024 * 1024, 1024, 64 * 1024 * 1024),
    maxFindings: clampInt(limits.maxFindings, 100, 1, 1000),
    maxItems: clampInt(limits.maxItems, 200, 1, 5000),
    maxStrings: clampInt(limits.maxStrings, 500, 1, 20000),
    timeoutMs: clampInt(limits.timeoutMs, 60000, 1000, 600000),
  };
}

function scanCaps(options, limits) {
  return {
    maxFiles: clampInt(options.maxFiles, 400, 1, 2000),
    maxFileBytes: clampInt(options.maxFileBytes, 256 * 1024, 1024, limits.maxBytes),
    maxTotalBytes: clampInt(options.maxTotalBytes, 16 * 1024 * 1024, 4096, 128 * 1024 * 1024),
  };
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

const EXCLUDE_DIRS_SCHEMA = {
  type: 'array',
  items: { type: 'string' },
  description: '额外排除的目录名（默认已排除 node_modules/.git/dist/build/vendor 等）',
};

const SOURCE_EXTENSIONS = Object.entries(LANGUAGES)
  .flatMap(([language, exts]) => exts.map((ext) => `${language}:${ext}`))
  .join(', ');

export default {
  domain: 'sast',
  capabilities: [
    {
      id: 'sast.scan',
      title: '多语言源码危险 API 扫描',
      description:
        '通过核心 env.listFiles/env.readFile 有界扫描项目目录：针对 JS/TS、Python、Java、Go、C/C++、PHP 检测 eval/exec 动态执行、命令注入、SQL 拼接、XSS 汇聚点、不安全反序列化、路径穿越、SSRF、开放重定向、弱哈希/弱加密、弱随机数、XXE、TLS 校验关闭等危险构造，输出 CWE 映射、文件:行号与修复建议。规则为逐行正则，未做数据流污点分析；taint 相关命中标注为 hypothesis。',
      riskLevel: 'L0',
      targetKind: 'directory',
      params: {
        type: 'object',
        properties: {
          languages: {
            type: 'array',
            items: { type: 'string', enum: Object.keys(LANGUAGES) },
            description: '仅扫描指定语言（默认全部支持的语言）',
          },
          rules: {
            type: 'array',
            items: { type: 'string' },
            description: `仅运行指定规则 id（默认全部 ${RULES.length} 条）`,
          },
          minSeverity: { type: 'string', enum: MIN_SEVERITIES, description: '最低报告严重级别（默认 info）' },
          maxFiles: { type: 'integer', minimum: 1, maximum: 2000, description: '最多读取/扫描的文件数（默认 400）' },
          maxFileBytes: { type: 'integer', minimum: 1024, maximum: 4194304, description: '单文件最多读取字节数（默认 262144）' },
          maxLinesPerFile: { type: 'integer', minimum: 100, maximum: 200000, description: '单文件最多扫描行数（默认 20000）' },
          excludeDirs: EXCLUDE_DIRS_SCHEMA,
          excludePaths: {
            type: 'array',
            items: { type: 'string' },
            description: '按路径子串排除文件（大小写不敏感，例如 ["tests/","lib/analyzers/sast/rules.js","docs/known-issues.md"]），用于降低规则自匹配/测试夹具噪声',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const caps = scanCaps(options, limits);

        let languageFilter = null;
        if (Array.isArray(options.languages) && options.languages.length) {
          const invalid = options.languages.filter((l) => !Object.hasOwn(LANGUAGES, l));
          if (invalid.length) {
            throw new Error(
              `未知语言：${invalid.join(', ')}。支持的语言：${Object.keys(LANGUAGES).join(', ')}。`,
            );
          }
          languageFilter = new Set(options.languages);
        }
        let selectedRules = null;
        if (Array.isArray(options.rules) && options.rules.length) {
          const invalid = options.rules.filter((id) => !RULES_BY_ID.has(id));
          if (invalid.length) {
            throw new Error(
              `未知规则 id：${invalid.slice(0, 10).join(', ')}${invalid.length > 10 ? ' 等' : ''}。` +
                `可用规则共 ${RULES.length} 条，例如 ${RULES.slice(0, 8).map((r) => r.id).join(', ')}。`,
            );
          }
          selectedRules = options.rules.map((id) => RULES_BY_ID.get(id));
        }
        const minSeverity = MIN_SEVERITIES.includes(options.minSeverity) ? options.minSeverity : 'info';
        const minRank = severityRank(minSeverity);

        const isSource = (filePath) => {
          const language = languageForFile(filePath);
          if (!language) return false;
          if (languageFilter && !languageFilter.has(language)) return false;
          return true;
        };
        const collected = await collectSources(
          input,
          { excludeDirs: options.excludeDirs, excludePaths: options.excludePaths },
          caps,
          isSource,
        );
        if (!collected.sources.length) {
          throw new Error(
            '未发现可扫描的源代码文件：支持 ' +
              `${Object.entries(LANGUAGES).map(([l, exts]) => `${l}(${exts.join('/')})`).join('、')}。` +
              ' 请确认 targetPath 指向项目根目录（而非空目录/依赖目录），或检查核心 env.listFiles 的枚举范围与 excludeDirs 设置。',
          );
        }

        const scanResult = scanSources(collected.sources, {
          rules: selectedRules ?? undefined,
          maxFindings: limits.maxFindings,
          maxLinesPerFile: clampInt(options.maxLinesPerFile, 20000, 100, 200000),
          maxFindingsPerFile: 300,
          signal: input.env?.signal,
        });
        const findings = sortFindings(
          scanResult.findings.filter((f) => severityRank(f.severity) >= minRank),
        );
        const counts = severityCounts(findings);
        const topTargets = [...new Set(findings.map((f) => (f.target ?? '').replace(/:\d+$/, '')))].slice(0, 5);
        const summary = compact(
          `扫描 ${scanResult.stats.filesScanned} 个源文件（跳过二进制 ${scanResult.stats.filesSkipped}，` +
            `共 ${scanResult.stats.totalLines} 行），命中 ${scanResult.stats.matchedRuleCount} 条规则 / ${findings.length} 条候选发现：` +
            `critical ${counts.critical} / high ${counts.high} / medium ${counts.medium} / low ${counts.low} / info ${counts.info}。` +
            (topTargets.length ? ` 问题最集中：${topTargets.join('、')}。` : '') +
            ' 规则为逐行正则匹配（无数据流分析），taint 相关命中需人工确认可达性。',
          4000,
        );
        const data = {
          directoryScan: collected.directoryScan,
          filesScanned: scanResult.stats.filesScanned,
          filesSkippedBinary: scanResult.stats.filesSkipped,
          totalLines: scanResult.stats.totalLines,
          findingsCount: findings.length,
          matchedRuleCount: scanResult.stats.matchedRuleCount,
          ruleHits: scanResult.stats.ruleHits,
          byLanguage: scanResult.stats.byLanguage,
          bySeverity: counts,
          files: scanResult.files.slice(0, limits.maxItems).map((file) => ({
            path: file.path,
            language: file.language,
            lines: file.lines,
            matches: file.matches,
            truncated: Boolean(file.truncated || file.bytesTruncated),
          })),
          truncated: {
            files: Boolean(collected.truncated.files),
            bytes: Boolean(collected.truncated.totalBytes) || scanResult.stats.byteTruncatedFiles > 0,
            findings: findings.length >= limits.maxFindings,
            lines: scanResult.stats.truncatedFiles > 0,
          },
          limits: { maxFiles: caps.maxFiles, maxFileBytes: caps.maxFileBytes, minSeverity },
        };
        return {
          summary,
          findings,
          evidence: [
            {
              title: '源码扫描统计',
              kind: 'sast-scan',
              excerpt: compact(
                [
                  `files=${scanResult.stats.filesScanned} skippedBinary=${scanResult.stats.filesSkipped} lines=${scanResult.stats.totalLines}`,
                  `matchedRules=${scanResult.stats.matchedRuleIds.join(', ') || '(none)'}`,
                  `byLanguage=${JSON.stringify(scanResult.stats.byLanguage)}`,
                  `readErrors=${collected.readErrors.length}`,
                ].join('\n'),
                2000,
              ),
              meta: { rules: scanResult.stats.matchedRuleIds, byLanguage: scanResult.stats.byLanguage },
            },
          ],
          data,
          meta: {
            domain: 'sast',
            capability: 'sast.scan',
            rulesAvailable: RULES.length,
            rulesSelected: (selectedRules ?? RULES).length,
            directoryScan: collected.directoryScan,
            readErrors: collected.readErrors,
            truncated: data.truncated,
            limits,
          },
        };
      },
    },
    {
      id: 'sast.secrets',
      title: '硬编码凭据与密钥检测',
      targetKind: 'directory',
      description:
        '有界扫描项目文件（env.listFiles/env.readFile）：识别 AWS/GCP/Azure 凭据、私钥块、GitHub/Slack/Stripe/SendGrid/OpenAI/Twilio 密钥、JWT、连接串口令，以及带熵阈值的通用 password/token/.env 赋值（含占位符 allowlist）。所有命中值一律脱敏为前 4 字符 + ***，输出文件:行号、类型与熵值，用于凭据轮换与仓库清理。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          minEntropy: { type: 'number', minimum: 1, maximum: 8, description: '通用凭据赋值的熵阈值（默认 3.0）' },
          maxFiles: { type: 'integer', minimum: 1, maximum: 2000, description: '最多读取文件数（默认 400）' },
          maxFileBytes: { type: 'integer', minimum: 1024, maximum: 4194304, description: '单文件最多读取字节数（默认 262144）' },
          maxLinesPerFile: { type: 'integer', minimum: 100, maximum: 200000, description: '单文件最多扫描行数（默认 20000）' },
          excludeDirs: EXCLUDE_DIRS_SCHEMA,
          excludePaths: {
            type: 'array',
            items: { type: 'string' },
            description: '按路径子串排除文件（大小写不敏感，例如 ["tests/","lib/analyzers/sast/rules.js","docs/known-issues.md"]），用于降低规则自匹配/测试夹具噪声',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const caps = scanCaps(options, limits);
        const collected = await collectSources(input, { excludeDirs: options.excludeDirs, excludePaths: options.excludePaths }, caps);
        if (!collected.sources.length) {
          throw new Error(
            '未读取到任何文件：凭据检测需要可读的项目文件。请确认 targetPath 指向项目目录，' +
              '或核心已提供 env.listFiles / env.readFile 且目录非空。',
          );
        }
        const result = scanSecrets(collected.sources, {
          maxFindings: limits.maxFindings,
          minEntropy: Number.isFinite(options.minEntropy) ? options.minEntropy : 3.0,
          maxLinesPerFile: clampInt(options.maxLinesPerFile, 20000, 100, 200000),
          signal: input.env?.signal,
        });
        const counts = severityCounts(result.findings);
        const types = Object.keys(result.stats.byType);
        const summary = compact(
          `凭据扫描：读取 ${collected.sources.length} 个文件，发现 ${result.secrets.length} 个唯一疑似凭据` +
            `（候选出现 ${result.stats.candidateOccurrences} 次，跳过二进制 ${result.stats.skippedBinaryFiles} 个文件）：` +
            `critical ${counts.critical} / high ${counts.high} / medium ${counts.medium} / low ${counts.low}。` +
            (types.length ? ` 类型：${types.join('、')}。` : ' 未命中已知凭据格式。') +
            ' 所有值已脱敏；若为真实凭据请立即轮换。',
          4000,
        );
        return {
          summary,
          findings: result.findings,
          evidence: [
            {
              title: '凭据扫描统计（值已脱敏）',
              kind: 'secret-scan',
              excerpt: compact(
                [
                  `files=${collected.sources.length} skippedBinary=${result.stats.skippedBinaryFiles}`,
                  `uniqueSecrets=${result.secrets.length} candidateOccurrences=${result.stats.candidateOccurrences}`,
                  `byType=${JSON.stringify(result.stats.byType)}`,
                ].join('\n'),
                2000,
              ),
              meta: { byType: result.stats.byType },
            },
          ],
          data: {
            directoryScan: collected.directoryScan,
            filesRead: collected.sources.length,
            skippedBinaryFiles: result.stats.skippedBinaryFiles,
            candidateOccurrences: result.stats.candidateOccurrences,
            uniqueSecrets: result.secrets.length,
            byType: result.stats.byType,
            secrets: result.secrets.slice(0, limits.maxItems),
            bySeverity: counts,
            truncated: {
              files: Boolean(collected.truncated.files),
              bytes:
                Boolean(collected.truncated.totalBytes) ||
                collected.sources.some((source) => Number.isFinite(source.size) && source.size > source.buffer.length),
              findings: result.findings.length >= limits.maxFindings,
            },
          },
          meta: {
            domain: 'sast',
            capability: 'sast.secrets',
            directoryScan: collected.directoryScan,
            readErrors: collected.readErrors,
            limits,
          },
        };
      },
    },
    {
      id: 'sast.deps',
      title: '依赖清单与供应链启发式审计',
      targetKind: 'directory',
      description:
        '扫描目录中的 package.json / requirements.txt / go.mod / pom.xml：输出依赖清单（名称/版本/scope）、锁定与范围版本统计、明文 HTTP 依赖源、安装期脚本、直接 URL/git 依赖、锁文件缺失，以及内置“版本低于已知修复版本”公告表匹配。明确标注：未查询实时漏洞库，风险匹配为版本启发式（hypothesis），需以上游 advisory/SCA 工具确认。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          maxDepsPerManifest: { type: 'integer', minimum: 1, maximum: 5000, description: '每个清单最多输出的依赖数（默认 500）' },
          maxManifests: { type: 'integer', minimum: 1, maximum: 200, description: '最多审计的清单数（默认 50）' },
          excludeDirs: EXCLUDE_DIRS_SCHEMA,
          excludePaths: {
            type: 'array',
            items: { type: 'string' },
            description: '按路径子串排除文件（大小写不敏感，例如 ["tests/","lib/analyzers/sast/rules.js","docs/known-issues.md"]），用于降低规则自匹配/测试夹具噪声',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const caps = scanCaps(options, limits);
        const collected = await collectSources(input, { excludeDirs: options.excludeDirs, excludePaths: options.excludePaths }, caps, isManifestPath);
        if (!collected.sources.length) {
          throw new Error(
            '未发现依赖清单：支持 package.json / requirements.txt / go.mod / pom.xml。' +
              ' 请确认 targetPath 指向项目根目录（含依赖清单），或检查 excludeDirs 是否把目标目录排除。',
          );
        }
        const maxDepsPerManifest = clampInt(options.maxDepsPerManifest, 500, 1, 5000);
        const maxManifests = clampInt(options.maxManifests, 50, 1, 200);
        const { manifests, parseErrors } = collectManifests(collected.sources, {
          maxDepsPerManifest,
          maxManifests,
        });
        if (!manifests.length) {
          throw new Error(
            '已读取文件但没有可识别的依赖清单（按文件名匹配 package.json / requirements*.txt / go.mod / pom.xml）。' +
              ' 请确认文件名正确；单文件模式下 targetPath 必须指向清单文件本身。',
          );
        }
        const audit = auditManifests(manifests, {
          fileList: collected.fileList,
          parseErrors,
          maxFindings: limits.maxFindings,
          maxDepsPerManifest,
          maxManifests,
          maxItems: limits.maxItems,
        });
        return {
          summary: audit.summaryText,
          findings: audit.findings,
          evidence: audit.evidence,
          data: {
            ...audit.data,
            directoryScan: collected.directoryScan,
            knownRiskyRules: KNOWN_RISKY.length,
            parseErrors,
            truncatedAll: {
              files: Boolean(collected.truncated.files),
              bytes: Boolean(collected.truncated.totalBytes),
            },
          },
          meta: {
            domain: 'sast',
            capability: 'sast.deps',
            manifestCount: manifests.length,
            parseErrorCount: parseErrors.length,
            directoryScan: collected.directoryScan,
            noVulnDb: true,
            limits,
          },
        };
      },
    },
    {
      id: 'sast.sbom',
      title: '生成 CycloneDX 1.5 SBOM',
      targetKind: 'directory',
      description:
        '从 package.json / requirements.txt / go.mod / pom.xml 生成 CycloneDX 1.5 JSON BOM：组件去重并按 bom-ref 排序，purl 标准化（npm/pypi/golang/maven），serialNumber 由组件集合 SHA-256 确定性派生；完整 BOM 作为 artifact（bom.cdx.json）落盘，data 中提供组件摘要与统计。零网络、零依赖。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          projectName: { type: 'string', description: '覆盖 metadata.component.name（默认取清单 name）' },
          projectVersion: { type: 'string', description: '覆盖 metadata.component.version（默认取清单 version）' },
          maxComponents: { type: 'integer', minimum: 1, maximum: 20000, description: '最多输出的组件数（默认 5000）' },
          excludeDirs: EXCLUDE_DIRS_SCHEMA,
          excludePaths: {
            type: 'array',
            items: { type: 'string' },
            description: '按路径子串排除文件（大小写不敏感，例如 ["tests/","lib/analyzers/sast/rules.js","docs/known-issues.md"]），用于降低规则自匹配/测试夹具噪声',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const caps = scanCaps(options, limits);
        const collected = await collectSources(input, { excludeDirs: options.excludeDirs, excludePaths: options.excludePaths }, caps, isManifestPath);
        if (!collected.sources.length) {
          throw new Error(
            '未发现依赖清单，无法生成 SBOM：需要 package.json / requirements.txt / go.mod / pom.xml。' +
              ' 请确认 targetPath 指向项目根目录。',
          );
        }
        const built = buildSbomFromSources(collected.sources, {
          projectName: typeof options.projectName === 'string' ? options.projectName : undefined,
          projectVersion: typeof options.projectVersion === 'string' ? options.projectVersion : undefined,
          maxComponents: clampInt(options.maxComponents, 5000, 1, 20000),
          maxDepsPerManifest: 20000,
          maxManifests: 200,
          timestamp: input.env?.nowIso,
        });
        const bomJson = JSON.stringify(built.bom, null, 2);
        const componentDataLimit = Math.min(limits.maxItems, 500);
        const componentsForData = built.components.slice(0, componentDataLimit);
        const ecosystems = Object.entries(built.ecosystemCounts)
          .map(([k, v]) => `${k}=${v}`)
          .join(', ');
        const summary = compact(
          `生成 CycloneDX 1.5 SBOM：${built.components.length} 个组件` +
            (ecosystems ? `（${ecosystems}）` : '') +
            `，覆盖 ${built.manifests.filter((m) => m.parseOk).length} 个依赖清单；` +
            `项目 ${built.project.name}@${built.project.version}；serialNumber ${built.bom.serialNumber}。` +
            ' 完整 BOM 见 artifacts/bom.cdx.json。',
          4000,
        );
        return {
          summary,
          findings: [],
          evidence: [
            {
              title: 'SBOM 概览',
              kind: 'cyclonedx-bom',
              excerpt: compact(
                [
                  `bomFormat=CycloneDX specVersion=1.5 serialNumber=${built.bom.serialNumber}`,
                  `project=${built.project.name}@${built.project.version}`,
                  `components=${built.components.length} ecosystems=${ecosystems || '(none)'}`,
                  `manifests=${built.manifests.map((m) => m.path).join(', ')}`,
                ].join('\n'),
                2000,
              ),
              meta: { serialNumber: built.bom.serialNumber, componentCount: built.components.length },
            },
          ],
          data: {
            bomFormat: 'CycloneDX',
            specVersion: '1.5',
            serialNumber: built.bom.serialNumber,
            project: built.project,
            componentCount: built.components.length,
            ecosystems: built.ecosystemCounts,
            components: componentsForData,
            manifests: built.manifests.map((m) => ({
              path: m.path,
              ecosystem: m.ecosystem,
              parseOk: m.parseOk,
              dependencyCount: m.dependencyCount ?? 0,
              error: m.error ?? null,
            })),
            parseErrors: built.parseErrors,
            truncated: {
              components: built.components.length > componentsForData.length,
              maxComponentsHit: built.truncated,
              files: Boolean(collected.truncated.files),
            },
          },
          artifacts: [
            { name: 'bom.cdx.json', content: bomJson, contentType: 'application/json' },
          ],
          meta: {
            domain: 'sast',
            capability: 'sast.sbom',
            bomBytes: Buffer.byteLength(bomJson, 'utf8'),
            directoryScan: collected.directoryScan,
            limits,
          },
        };
      },
    },
    {
      id: 'sast.patch_suggestion',
      title: '生成修复补丁与回归测试建议',
      description:
        '输入一条 finding（sast.scan 等输出，通过 options.finding 或 JSON 文本传入），按 CWE 与语言生成“统一 diff 风格”修复建议与回归测试骨架：命令注入/SQL 注入/XSS/路径穿越/反序列化/弱哈希/SSRF/弱随机等模板。仅生成建议，绝不写文件、不自动应用；缺少原始代码行时明确标注 illustrative。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          finding: {
            type: 'object',
            additionalProperties: true,
            description: '待修复的 finding 对象（title/target/cwe/evidence 等）',
          },
          file: { type: 'string', description: '覆盖目标文件路径' },
          line: { type: 'integer', minimum: 1, description: '覆盖目标行号' },
          codeLine: { type: 'string', description: '命中行原始代码（用于生成真实删除行；缺省则 diff 为示意）' },
          language: {
            type: 'string',
            enum: Object.keys(LANGUAGES),
            description: '覆盖语言推断（默认按文件扩展名）',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const text = typeof input.text === 'string' ? input.text : null;
        const findingInput = extractFindingInput(text, options);
        const result = buildPatchSuggestion(findingInput, {
          file: typeof options.file === 'string' ? options.file : undefined,
          line: Number.isFinite(options.line) ? options.line : undefined,
          codeLine: typeof options.codeLine === 'string' ? options.codeLine : undefined,
          language: typeof options.language === 'string' ? options.language : undefined,
        });
        return {
          ...result,
          data: { ...result.data, limits },
          meta: {
            domain: 'sast',
            capability: 'sast.patch_suggestion',
            ruleHint: result.data.ruleHint,
            cwe: result.data.cwe,
            illustrative: result.data.illustrative,
            applyPolicy: 'manual-only',
            limits,
          },
        };
      },
    },
    semgrepCapability,
    trivyCapability,
    syftCapability,
  ],
};

// Keep the module graph explicit for reviewers: baseName is used in summaries.
void baseName;
