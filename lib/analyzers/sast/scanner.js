// ArmorBreak SAST domain — bounded, line-oriented source scanner.
//
// Honesty model: a regex hit proves a dangerous construct is present, not that
// it is reachable/exploitable. Taint-dependent rules are marked
// verification="hypothesis"; only config/algorithm facts are "observed".

import {
  baseName,
  clip,
  excerptLine,
  finding,
  isLikelyBinary,
  redactInlineSecrets,
} from './common.js';
import { RULES, languageForFile, rulesForLanguage } from './rules.js';

const MAX_LINE_LENGTH = 8000;
const DEFAULT_MAX_LINES_PER_FILE = 20000;
const DEFAULT_MAX_FINDINGS_PER_FILE = 200;

/**
 * Scan one { path, buffer } source.
 * @returns {{findings:object[], language:string|null, lines:number, matches:number,
 *   skippedBinary:boolean, truncated:boolean, ruleHits:Map<string,number>}}
 */
export function scanSource(source, opts = {}) {
  const language = opts.language ?? languageForFile(source.path);
  let rules;
  if (opts.rules) {
    // Caller supplied a subset; still restrict it to rules valid for the language.
    const languageRuleIds = language ? new Set(rulesForLanguage(language).map((r) => r.id)) : null;
    rules = languageRuleIds ? opts.rules.filter((r) => languageRuleIds.has(r.id)) : opts.rules;
  } else {
    rules = language ? rulesForLanguage(language) : RULES;
  }
  const maxLinesPerFile = Number.isFinite(opts.maxLinesPerFile)
    ? Math.max(1, Math.min(200000, Math.trunc(opts.maxLinesPerFile)))
    : DEFAULT_MAX_LINES_PER_FILE;
  const maxFindingsPerFile = Number.isFinite(opts.maxFindingsPerFile)
    ? Math.max(1, Math.trunc(opts.maxFindingsPerFile))
    : DEFAULT_MAX_FINDINGS_PER_FILE;
  const signal = opts.signal;

  const result = {
    findings: [],
    language,
    lines: 0,
    matches: 0,
    skippedBinary: false,
    truncated: false,
    ruleHits: new Map(),
  };

  if (isLikelyBinary(source.buffer)) {
    result.skippedBinary = true;
    return result;
  }
  const text = source.buffer.toString('utf8');
  const lines = text.split('\n');
  const limit = Math.min(lines.length, maxLinesPerFile);
  result.truncated = lines.length > limit;

  for (let index = 0; index < limit; index += 1) {
    if (signal?.aborted) {
      result.truncated = true;
      break;
    }
    const rawLine = lines[index];
    if (!rawLine || rawLine.length < 4) continue;
    result.lines += 1;
    const line = rawLine.length > MAX_LINE_LENGTH ? rawLine.slice(0, MAX_LINE_LENGTH) : rawLine;
    for (const rule of rules) {
      if (result.findings.length >= maxFindingsPerFile) {
        result.truncated = true;
        break;
      }
      // Defensive: shared RegExp objects are non-global, but reset anyway.
      rule.pattern.lastIndex = 0;
      if (!rule.pattern.test(line)) continue;
      result.matches += 1;
      result.ruleHits.set(rule.id, (result.ruleHits.get(rule.id) ?? 0) + 1);
      const evidenceText = excerptLine(redactInlineSecrets(rawLine), 400);
      result.findings.push(
        finding({
          title: `[${rule.id}] ${rule.title}`,
          severity: rule.severity,
          description:
            `${rule.title}。` +
            (rule.taintDependent
              ? ' 该命中只说明危险汇聚点存在于源码中；输入是否可达、是否可控未经数据流/污点分析验证。'
              : ' 该事实由源码直接观察得到，实际影响需结合上下文确认。'),
          verification: rule.taintDependent ? 'hypothesis' : 'observed',
          method: 'line-regex-source-analysis',
          cwe: rule.cwe,
          cvss: null,
          remediation: rule.remediation,
          target: `${clip(source.path, 400)}:${index + 1}`,
          evidence: [
            {
              title: `${baseName(source.path)}:${index + 1}`,
              excerpt: evidenceText,
              meta: { ruleId: rule.id, language, line: index + 1 },
            },
          ],
        }),
      );
    }
  }
  return result;
}

/**
 * Scan a set of sources, aggregating per-file stats.
 * @returns {{findings:object[], files:object[], stats:object}}
 */
export function scanSources(sources, opts = {}) {
  const findings = [];
  const files = [];
  const ruleHits = new Map();
  const languages = new Map();
  let totalLines = 0;
  let skippedBinary = 0;
  let truncatedFiles = 0;
  let byteTruncatedFiles = 0;
  const maxFindings = Number.isFinite(opts.maxFindings) ? Math.max(1, Math.trunc(opts.maxFindings)) : 100;

  for (const source of sources) {
    if (opts.signal?.aborted) break;
    const remaining = Math.max(1, maxFindings - findings.length);
    const result = scanSource(source, { ...opts, maxFindingsPerFile: Math.min(opts.maxFindingsPerFile ?? 300, remaining) });
    if (result.skippedBinary) {
      skippedBinary += 1;
      files.push({ path: clip(source.path, 400), language: null, lines: 0, matches: 0, skipped: 'binary' });
      continue;
    }
    if (result.truncated) truncatedFiles += 1;
    totalLines += result.lines;
    const bytesTruncated = Number.isFinite(source.size) && source.size > source.buffer.length;
    if (bytesTruncated) byteTruncatedFiles += 1;
    for (const [ruleId, count] of result.ruleHits) ruleHits.set(ruleId, (ruleHits.get(ruleId) ?? 0) + count);
    const langKey = result.language ?? 'unknown';
    languages.set(langKey, (languages.get(langKey) ?? 0) + 1);
    files.push({
      path: clip(source.path, 400),
      language: result.language,
      lines: result.lines,
      matches: result.findings.length,
      truncated: result.truncated,
      bytesTruncated,
    });
    findings.push(...result.findings);
    if (findings.length >= maxFindings) break;
  }

  const matchedRuleIds = [...ruleHits.keys()].sort();
  const cappedFindings = findings.slice(0, maxFindings);
  return {
    findings: cappedFindings,
    files,
    stats: {
      filesScanned: files.filter((f) => !f.skipped).length,
      filesSkipped: skippedBinary,
      truncatedFiles,
      byteTruncatedFiles,
      totalLines,
      matches: cappedFindings.length,
      matchedRuleCount: matchedRuleIds.length,
      matchedRuleIds,
      ruleHits: matchedRuleIds.map((id) => ({ id, count: ruleHits.get(id) })),
      byLanguage: Object.fromEntries([...languages.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
    },
  };
}
