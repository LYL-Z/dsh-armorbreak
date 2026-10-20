// ArmorBreak CTF domain — capability manifest.
//
// Domain: offline CTF triage (classification, decoding chains, hash ID,
// classical-crypto heuristics, flag scanning). All riskLevel L0.

import {
  asciiStrings,
  artifactFromInput,
  clampInt,
  compact,
  finding,
  isPrintableText,
  printableRatio,
  shannonEntropy,
  sortFindings,
} from './common.js';
import { analyzeClassical } from './crypto-basics.js';
import { decodeChain, TRANSFORM_NAMES } from './encoding.js';
import { classifyArtifact } from './filetype.js';
import { FLAG_PATTERNS, findEntropyCandidates, flagFindings, scanFlagsArtifact, scanFlagsInBuffer, scanFlagsInText } from './flagscan.js';
import { analyzeHashes } from './hash_id.js';

function budget(input) {
  const limits = input.limits ?? {};
  return {
    maxBytes: clampInt(limits.maxBytes, 1024 * 1024, 1, 64 * 1024 * 1024),
    maxFindings: clampInt(limits.maxFindings, 100, 1, 1000),
    maxItems: clampInt(limits.maxItems, 200, 1, 5000),
    maxStrings: clampInt(limits.maxStrings, 500, 1, 20000),
  };
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const findingItem of findings) counts[findingItem.severity] += 1;
  return counts;
}

const SEVERITY_ENUM = ['info', 'low', 'medium', 'high', 'critical'];

export default {
  domain: 'ctf',
  capabilities: [
    {
      id: 'ctf.classify',
      title: '多层编码与文件格式识别',
      description:
        '离线识别 CTF 常见数据形态：文件魔数（PNG/JPEG/PDF/ZIP/APK/OOXML/GZIP/BZIP2/XZ/7z/RAR/ELF/PE/Mach-O/Java class/SQLite/WASM/TAR/PCAP/PCAPNG/媒体容器等）、文本编码（base64/base64url/base32/hex/二进制位串/URL 编码/Morse/ROT13 提示）、ZIP 条目与容器类型，并按优先级自动跟随解码链（深度受限、防循环），汇总每层中间结果、熵值与 flag 命中。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          maxDepth: { type: 'integer', minimum: 1, maximum: 10, description: '自动解码链最大层数（默认 5）' },
          maxCandidates: { type: 'integer', minimum: 1, maximum: 50, description: '最多列出的编码候选数（默认 8）' },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const artifact = artifactFromInput(input);
        const result = classifyArtifact(artifact, {
          maxDepth: clampInt(options.maxDepth, 5, 1, 10),
          maxCandidates: clampInt(options.maxCandidates, 8, 1, 50),
          signal: input.env?.signal,
        });

        const findings = flagFindings(result.flags, 'regex-flag-scan');
        if (result.chain.length >= 2) {
          findings.push(
            finding({
              title: `[ctf-multi-layer] 检测到 ${result.chain.length} 层编码链`,
              severity: 'info',
              description:
                `按优先级自动解码 ${result.chain.length} 层：${result.chain
                  .map((layer) => `${layer.encoding}(第${layer.depth}层)`)
                  .join(' → ')}。最终输出 ${result.final.byteLength} 字节，` +
                `${result.final.printable ? '可读文本' : '仍为二进制'}。中间结果与熵值见 data.chain。`,
              verification: 'observed',
              method: 'recursive-encoding-detection',
              cwe: null,
              remediation: '逐层核对 data.chain 的 preview；若层序不符合预期，改用 ctf.decode 指定变换链。',
              target: null,
              evidence: [
                {
                  title: '自动解码链',
                  excerpt: result.chain.map((layer) => `L${layer.depth} ${layer.encoding}: ${layer.preview}`).join('\n'),
                },
              ],
            }),
          );
        }
        const unknownBinary =
          result.magic.length === 0 && !result.isText && result.textEncodings.length === 0;
        if (unknownBinary && result.initial.entropy >= 7.2) {
          findings.push(
            finding({
              title: `[ctf-high-entropy] 高熵二进制数据（${result.initial.entropy} bits/byte）`,
              severity: 'info',
              description:
                '输入未匹配已知文件魔数、不是可读文本，且字节熵很高，可能是加密数据、压缩流片段或自定义格式。' +
                ' 建议结合题目提示尝试 XOR/RC4/AES 或查找隐藏的密钥材料。',
              verification: 'hypothesis',
              method: 'entropy-anomaly-detection',
              cwe: null,
              remediation: '人工确认格式/密钥；可用 ctf.crypto_basics 检查单字节 XOR。',
              target: null,
              evidence: [{ title: '起始字节', excerpt: result.initial.hexPreview }],
            }),
          );
        } else if (unknownBinary && result.magic.length === 0) {
          findings.push(
            finding({
              title: '[ctf-unknown-binary] 未识别的二进制数据',
              severity: 'info',
              description:
                `输入 ${result.initial.byteLength} 字节，未匹配已知文件魔数，也不是可读文本或常见文本编码。` +
                ` 高熵候选 ${result.textEncodings.length} 个；建议先做 strings/熵分析或结合题目格式定位。`,
              verification: 'hypothesis',
              method: 'magic-and-encoding-detection',
              cwe: null,
              remediation: '结合题目提示与 ctf.decode 尝试已知变换。',
              target: null,
              evidence: [{ title: '起始字节', excerpt: result.initial.hexPreview }],
            }),
          );
        }

        const sorted = sortFindings(findings).slice(0, limits.maxFindings);
        const magicLabels = result.magic.map((entry) => entry.label);
        const encodingLabels = result.textEncodings.map((entry) => entry.encoding);
        const summary = compact(
          `识别 ${result.initial.byteLength} 字节输入：` +
            (magicLabels.length ? `文件格式 ${magicLabels.join('、')}；` : '未匹配文件魔数；') +
            (encodingLabels.length ? `文本编码候选 ${encodingLabels.join('、')}；` : '无文本编码候选；') +
            (result.chain.length ? `自动解码 ${result.chain.length} 层 → ${result.final.byteLength} 字节；` : '未自动解码；') +
            `熵=${result.initial.entropy} bits/byte；flag 命中 ${result.flags.length} 个。`,
          4000,
        );

        return {
          summary,
          findings: sorted,
          evidence: [
            {
              title: '分类概览',
              kind: 'ctf-classify',
              excerpt: compact(
                [
                  `bytes=${result.initial.byteLength} isText=${result.isText} entropy=${result.initial.entropy}`,
                  `magic=${magicLabels.join(', ') || '(none)'}`,
                  `textEncodings=${encodingLabels.join(', ') || '(none)'}`,
                  `chain=${result.chain.map((l) => l.encoding).join(' -> ') || '(none)'}`,
                  `flags=${result.flags.map((f) => f.flag).join(', ') || '(none)'}`,
                ].join('\n'),
                2000,
              ),
              meta: { magic: magicLabels, textEncodings: encodingLabels, chainLength: result.chain.length },
            },
          ],
          data: {
            byteLength: result.initial.byteLength,
            isText: result.isText,
            magic: result.magic,
            textEncodings: result.textEncodings,
            candidates: result.candidates.map((candidate) => ({
              ...candidate,
              preview: candidate.preview ? compact(candidate.preview, 300) : null,
            })),
            chain: result.chain,
            final: result.final,
            flags: result.flags,
            initial: result.initial,
            truncated: result.truncated,
            bySeverity: severityCounts(sorted),
          },
          meta: {
            domain: 'ctf',
            capability: 'ctf.classify',
            maxDepth: result.maxDepth,
            limits,
          },
        };
      },
    },
    {
      id: 'ctf.decode',
      title: '指定编码链解码',
      description:
        '按给定顺序执行编码/压缩变换并输出每步中间结果：base64、base64url、base32、hex、url、rot13、binary（0/1 位串）、morse、gzip、zlib、inflate-raw、utf16le。链长度与输出字节数受限，某步失败立刻返回可操作错误与已完成步骤；可打印的最终结果作为 artifact（decoded.txt）输出。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          transforms: {
            type: 'array',
            items: { type: 'string', enum: TRANSFORM_NAMES },
            minItems: 1,
            maxItems: 64,
            description: `按顺序应用的变换，可选：${TRANSFORM_NAMES.join(', ')}`,
          },
          maxDepth: { type: 'integer', minimum: 1, maximum: 64, description: '最多执行的变换步数（默认 10）' },
          maxBytes: { type: 'integer', minimum: 1024, maximum: 67108864, description: '每步输出字节上限（默认 4 MiB）' },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const artifact = artifactFromInput(input);
        const transforms = Array.isArray(options.transforms)
          ? options.transforms.filter((name) => typeof name === 'string')
          : [];
        if (!transforms.length) {
          throw new Error(
            '未指定 transforms：请按顺序给出编码名，例如 ["base64","gzip"]。' +
              ` 可用变换：${TRANSFORM_NAMES.join(', ')}。`,
          );
        }
        const result = decodeChain(artifact.bytes, transforms, {
          maxDepth: clampInt(options.maxDepth, 10, 1, 64),
          maxBytes: clampInt(options.maxBytes, 4 * 1024 * 1024, 1024, 64 * 1024 * 1024),
          signal: input.env?.signal,
        });

        const finalPrintable = isPrintableText(result.finalText, 0.8);
        const finalFlags = [];
        const seenFlags = new Set();
        for (const hit of [...scanFlagsInText(result.finalText, { maxItems: 20 }), ...scanFlagsInBuffer(result.finalBytes, { maxItems: 20 })]) {
          if (seenFlags.has(hit.flag)) continue;
          seenFlags.add(hit.flag);
          finalFlags.push(hit);
        }
        const findings = flagFindings(finalFlags, 'transform-chain-flag-scan').slice(0, limits.maxFindings);
        const failed = result.steps.find((step) => !step.ok) ?? null;
        const summary = compact(
          `按链 [${transforms.join(' → ')}] 解码：成功 ${result.steps.filter((s) => s.ok).length}/${result.steps.length} 步` +
            (failed ? `（第 ${failed.step} 步 ${failed.transform} 失败：${failed.error}）` : '') +
            `，输出 ${result.finalBytes.length} 字节（${finalPrintable ? '可读文本' : '二进制'}，熵 ${Number(
              shannonEntropy(result.finalBytes).toFixed(3),
            )} bits/byte）` +
            (result.truncated ? '；链长度超过 maxDepth 已截断' : '') +
            (finalFlags.length ? `；发现 flag ${finalFlags.map((f) => f.flag).join('、')}。` : '；未发现 flag。'),
          4000,
        );

        const artifacts = [];
        if (finalPrintable && result.finalText.length > 0 && Buffer.byteLength(result.finalText, 'utf8') <= 256 * 1024) {
          artifacts.push({ name: 'decoded.txt', content: result.finalText, contentType: 'text/plain' });
        }

        return {
          summary,
          findings,
          evidence: [
            {
              title: '解码链中间结果',
              kind: 'decode-chain',
              excerpt: compact(
                result.steps
                  .map((step) =>
                    step.ok
                      ? `#${step.step} ${step.transform}: ${step.outputBytes}B printable=${step.printable} preview=${step.preview}`
                      : `#${step.step} ${step.transform}: FAILED ${step.error}`,
                  )
                  .join('\n'),
                2000,
              ),
              meta: { transforms, used: result.usedTransforms },
            },
          ],
          data: {
            transforms,
            usedTransforms: result.usedTransforms,
            steps: result.steps,
            final: {
              bytesLength: result.finalBytes.length,
              printable: finalPrintable,
              printableRatio: Number(printableRatio(result.finalText).toFixed(3)),
              entropy: Number(shannonEntropy(result.finalBytes).toFixed(3)),
              preview: compact(result.finalText, 1000),
              hexPreview: result.finalBytes.subarray(0, 32).toString('hex'),
              flags: finalFlags.map((hit) => hit.flag),
            },
            truncated: { chain: result.truncated },
          },
          artifacts,
          meta: {
            domain: 'ctf',
            capability: 'ctf.decode',
            stepsOk: result.steps.filter((step) => step.ok).length,
            stepsTotal: result.steps.length,
            limits,
          },
        };
      },
    },
    {
      id: 'ctf.hash_id',
      title: '哈希与摘要格式识别',
      description:
        '按长度、字符集与已知前缀识别哈希/摘要格式并给出置信度：MD5/NTLM/MD4（32 hex）、SHA1/RIPEMD160（40）、SHA224/SHA3-224（56）、SHA256/SHA3-256/BLAKE2b（64）、SHA384（96）、SHA512/Whirlpool（128）、bcrypt/argon2/Unix crypt/mysql41、Base64 编码摘要、UUID、JWT。同长度算法会并列列出并注明歧义，不声称已破解。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          maxItems: { type: 'integer', minimum: 1, maximum: 500, description: '最多识别的哈希候选数（默认取 limits.maxItems）' },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const artifact = artifactFromInput(input);
        let sourceText = artifact.text;
        if (!isPrintableText(sourceText, 0.4)) {
          sourceText = asciiStrings(artifact.bytes, { minLength: 8, maxItems: 100 })
            .map((item) => item.text)
            .join('\n');
        }
        if (!sourceText.trim()) {
          throw new Error(
            '输入中没有可识别的文本/字符串：哈希识别需要哈希字符串或包含哈希的文本。' +
              ' 请提供输入内容；若目标是二进制文件，请先用 ctf.decode/ctf.classify 提取字符串。',
          );
        }
        const result = analyzeHashes(sourceText, { maxItems: clampInt(options.maxItems, limits.maxItems, 1, 500) });
        return {
          summary: result.summary,
          findings: result.findings.slice(0, limits.maxFindings),
          evidence: result.evidence,
          data: {
            ...result.data,
            hashes: result.data.hashes.slice(0, limits.maxItems),
            truncated: { hashes: result.data.hashes.length > limits.maxItems },
          },
          meta: {
            domain: 'ctf',
            capability: 'ctf.hash_id',
            hashCount: result.data.hashCount,
            limits,
          },
        };
      },
    },
    {
      id: 'ctf.crypto_basics',
      title: '古典密码启发式分析',
      description:
        '对文本做字母频率、重合指数 IoC、Caesar ROT1-25 暴力破解（英文字母频率对数似然 + 常见 n-gram 评分）与单字节 XOR 0-255 暴力破解（可打印比例门控 + 英文评分）；输入密文支持 hex/base64/raw 自动识别。所有候选明确标注为启发式（hypothesis），不声称是已验证明文。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          encoding: {
            type: 'string',
            enum: ['auto', 'hex', 'base64', 'raw'],
            description: 'XOR 密文输入编码（默认 auto：hex/base64 自动识别，否则按原始字节）',
          },
          maxCandidates: { type: 'integer', minimum: 1, maximum: 10, description: '每种攻击输出的候选数（默认 5）' },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const artifact = artifactFromInput(input);
        const text = isPrintableText(artifact.text, 0.4) ? artifact.text : artifact.bytes.toString('latin1');
        if (!text.trim()) {
          throw new Error('输入为空：古典密码分析需要密文文本（或可解析为 hex/base64 的密文字节）。');
        }
        const result = analyzeClassical({
          text,
          bytes: artifact.bytes,
          encoding: options.encoding,
          maxCandidates: clampInt(options.maxCandidates, 5, 1, 10),
        });
        return {
          summary: result.summary,
          findings: result.findings.slice(0, limits.maxFindings),
          evidence: result.evidence,
          data: {
            ...result.data,
            frequency: result.data.frequency,
            truncated: { frequency: false },
          },
          meta: {
            domain: 'ctf',
            capability: 'ctf.crypto_basics',
            heuristics: ['english-frequency-loglikelihood', 'ngram-bonus', 'index-of-coincidence', 'caesar-bruteforce', 'single-byte-xor-bruteforce'],
            limits,
          },
        };
      },
    },
    {
      id: 'ctf.flag_scan',
      title: 'flag 与高熵字符串扫描',
      description:
        '在文本或二进制（打印字符串）中扫描常见 flag 格式（flag{...}/CTF{...}/picoCTF{...}/HTB{...}/通用 tag{...}/flag_xxx）并提取高熵 token（可能是编码数据/密钥）。输出偏移、匹配模式与熵值；flag 为直接观察（observed），高熵异常为启发式提示（hypothesis）。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          minEntropy: { type: 'number', minimum: 1, maximum: 8, description: '高熵 token 阈值（默认 3.6 bits/char）' },
          maxItems: { type: 'integer', minimum: 1, maximum: 500, description: '最多返回的 flag / 高熵候选数（默认取 limits.maxItems）' },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const artifact = artifactFromInput(input);
        const maxItems = clampInt(options.maxItems, limits.maxItems, 1, 500);
        const flags = scanFlagsArtifact(artifact, { maxItems });
        const sourceText = isPrintableText(artifact.text, 0.4)
          ? artifact.text
          : asciiStrings(artifact.bytes, { minLength: 16, maxItems: 200 })
              .map((item) => item.text)
              .join('\n');
        const entropyCandidates = findEntropyCandidates(sourceText, {
          minEntropy: Number.isFinite(options.minEntropy) ? options.minEntropy : 3.6,
          maxItems: Math.min(maxItems, 50),
        });

        const findings = flagFindings(flags).slice(0, limits.maxFindings);
        if (entropyCandidates.length && findings.length < limits.maxFindings) {
          findings.push(
            finding({
              title: `[ctf-entropy] 发现 ${entropyCandidates.length} 个高熵 token`,
              severity: 'info',
              description:
                `扫描到 ${entropyCandidates.length} 个高熵字符串（熵阈值 ${Number.isFinite(options.minEntropy) ? options.minEntropy : 3.6}），` +
                '可能是 base64/hex 编码数据、随机密钥或哈希；需结合 ctf.decode 验证。',
              verification: 'hypothesis',
              method: 'entropy-anomaly-detection',
              cwe: null,
              remediation: '对候选依次尝试 base64/hex/gzip 解码；不要直接假设是最终 flag。',
              target: null,
              evidence: [
                {
                  title: '高熵候选（前 5，已截断）',
                  excerpt: entropyCandidates
                    .slice(0, 5)
                    .map((candidate) => `entropy=${candidate.entropy} len=${candidate.length} ${candidate.value}`)
                    .join('\n'),
                },
              ],
            }),
          );
        }

        const severityCountsMap = severityCounts(findings);
        const summary = compact(
          `flag/熵扫描 ${artifact.bytes.length} 字节：命中 flag ${flags.length} 个` +
            (flags.length ? `（${flags.map((hit) => hit.flag).join('、')}）` : '') +
            `，高熵 token ${entropyCandidates.length} 个，熵 ${Number(shannonEntropy(artifact.bytes).toFixed(3))} bits/byte。` +
            ' flag 为直接正则观察；高熵候选仅为启发式提示。',
          4000,
        );

        return {
          summary,
          findings: sortFindings(findings),
          evidence: [
            {
              title: 'flag/熵扫描结果',
              kind: 'ctf-flag-scan',
              excerpt: compact(
                [
                  `flags=${flags.map((hit) => `${hit.patternId}@${hit.offset}:${hit.flag}`).join(', ') || '(none)'}`,
                  `entropyCandidates=${entropyCandidates.length}`,
                  `patterns=${FLAG_PATTERNS.map((pattern) => pattern.id).join(',')}`,
                ].join('\n'),
                2000,
              ),
              meta: { flags: flags.length, entropyCandidates: entropyCandidates.length },
            },
          ],
          data: {
            flags,
            entropyCandidates,
            patternsTested: FLAG_PATTERNS.map((pattern) => pattern.id),
            scannedBytes: artifact.bytes.length,
            entropy: Number(shannonEntropy(artifact.bytes).toFixed(3)),
            bySeverity: severityCountsMap,
          },
          meta: {
            domain: 'ctf',
            capability: 'ctf.flag_scan',
            flagCount: flags.length,
            limits,
          },
        };
      },
    },
  ],
};

void SEVERITY_ENUM;
