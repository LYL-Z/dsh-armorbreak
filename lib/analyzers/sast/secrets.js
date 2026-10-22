// ArmorBreak SAST domain — hardcoded credential / secret detection.
//
// Detection = known credential formats + entropy-gated generic assignments with
// an allowlist for placeholders. Raw secret values NEVER leave this module:
// every value is redacted to first 4 chars + "***" in findings, evidence and data.

import {
  baseName,
  clip,
  excerptLine,
  finding,
  isLikelyBinary,
  redactSecretValue,
  shannonEntropy,
} from './common.js';

const MIN_ENTROPY_DEFAULT = 3.0;

// Placeholder / documentation values that must not be reported.
const ALLOWLIST_EXACT = new Set([
  'changeme',
  'change_me',
  'changeit',
  'example',
  'examples',
  'sample',
  'dummy',
  'fake',
  'placeholder',
  'redacted',
  'todo',
  'fixme',
  'null',
  'none',
  'undefined',
  'password',
  'secret',
  'token',
  'apikey',
  'api_key',
  'your_password_here',
  'your_secret_here',
  'your_token_here',
  'xxxxxxxx',
]);

function knownFalsePositive(pattern, value, rawLine, sourcePath) {
  const path = String(sourcePath ?? '').replaceAll('\\', '/');
  if (pattern.id === 'aws-access-key' && value === 'AKIAIOSFODNN7EXAMPLE' && path.endsWith('/scripts/v2/core-benchmark.mjs')) return 'aws-documentation-example';
  if (pattern.id === 'private-key-block' && path.endsWith('/lib/analyzers/sast/secrets.js') && /(?:matchText\.replace|-----BEGIN PRIVATE KEY-----)/.test(rawLine)) return 'scanner-own-redaction-rule-text';
  return null;
}

function isAllowlisted(value, { generic = false } = {}) {
  const v = String(value ?? '').trim();
  if (!v) return true;
  const lower = v.toLowerCase();
  if (ALLOWLIST_EXACT.has(lower)) return true;
  if (/^(?:x{4,}|\*+|\.{3,}|-{4,}|_{4,})$/.test(v)) return true;
  if (/^x+$/i.test(v.replace(/[_-]/g, ''))) return true;
  if (/^(?:your|my|example|sample|demo|test|fake|dummy|placeholder|change)[_-]/i.test(v)) return true;
  if (/^(?:<.*>|\$\{.*\}|%.*%|__.*__|\{\{.*\}\})$/.test(v)) return true;
  if (/(?:process\.env|os\.environ|os\.getenv|env\[|ENV\[|getenv|secrets\.|secret_manager|vault)/i.test(v)) return true;
  if (/^(?:\.{0,2}\/|\/|https?:\/\/|[A-Za-z]:\\)/.test(v) && !generic) return true;
  if (generic && v.length < 8) return true;
  if (generic && !/[A-Za-z]/.test(v)) return true;
  if (generic && !/[0-9]/.test(v) && !/[A-Z]/.test(v) && v.length < 16) return true;
  return false;
}

/**
 * Credential patterns. `group` selects the value to redact; `minEntropy` gates
 * generic patterns; `generic` patterns are suppressed when they overlap a
 * specific-format match on the same line.
 */
export const SECRET_PATTERNS = Object.freeze([
  {
    id: 'aws-access-key',
    title: 'AWS Access Key ID',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    id: 'aws-secret-key',
    title: 'AWS Secret Access Key',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /(?:aws_secret_access_key|aws_secret_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g,
    group: 1,
    minEntropy: 2.8,
  },
  {
    id: 'gcp-service-account-key',
    title: 'GCP 服务账号私钥',
    severity: 'critical',
    cwe: 'CWE-321',
    regex: /"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    id: 'private-key-block',
    title: '私钥内容',
    severity: 'critical',
    cwe: 'CWE-321',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'github-token',
    title: 'GitHub Token',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
  },
  {
    id: 'google-api-key',
    title: 'Google API Key',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: 'slack-token',
    title: 'Slack Token',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  },
  {
    id: 'stripe-secret-key',
    title: 'Stripe Secret Key',
    severity: 'critical',
    cwe: 'CWE-798',
    regex: /\bsk_live_[0-9A-Za-z]{20,}\b/g,
  },
  {
    id: 'sendgrid-api-key',
    title: 'SendGrid API Key',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
  },
  {
    id: 'openai-api-key',
    title: 'OpenAI API Key',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\bsk-[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: 'twilio-api-key',
    title: 'Twilio API Key',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\bSK[0-9a-f]{32}\b/g,
  },
  {
    id: 'azure-storage-key',
    title: 'Azure Storage Account Key',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /AccountKey\s*=\s*[A-Za-z0-9+/=]{40,}/g,
  },
  {
    id: 'jwt',
    title: 'JWT Token',
    severity: 'medium',
    cwe: 'CWE-798',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    id: 'connection-string-password',
    title: '连接串中包含口令',
    severity: 'high',
    cwe: 'CWE-798',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^\s:/@]+:([^\s@/]+)@/g,
    group: 1,
  },
  {
    id: 'generic-credential-assignment',
    title: '疑似硬编码凭据赋值',
    severity: 'medium',
    cwe: 'CWE-798',
    generic: true,
    regex:
      /(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret|signing[_-]?key)\w*\s*[:=]\s*['"]([^'"\s]{8,120})['"]/gi,
    group: 1,
    minEntropy: MIN_ENTROPY_DEFAULT,
  },
  {
    id: 'env-credential-assignment',
    title: '疑似硬编码凭据（环境变量风格）',
    severity: 'medium',
    cwe: 'CWE-798',
    generic: true,
    regex:
      /^\s*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|AUTH_TOKEN)\s*=\s*([^\s#]{8,160})/i,
    group: 1,
    minEntropy: MIN_ENTROPY_DEFAULT,
  },
]);

// Defensive normalization: every pattern must be global, otherwise a shared
// RegExp would return the same match forever in the scan loop.
for (const pattern of SECRET_PATTERNS) {
  if (!pattern.regex.global) {
    pattern.regex = new RegExp(pattern.regex.source, `${pattern.regex.flags}g`);
  }
}

function rangesOverlap(a, b) {
  return a.start < b.end && b.start < a.end;
}

function redactForPattern(pattern, matchText, value) {
  if (pattern.id === 'private-key-block' || pattern.id === 'gcp-service-account-key') {
    return matchText.replace(/-----[A-Z ]*PRIVATE KEY-----/g, '-----BEGIN PRIVATE KEY----- [内容已省略]');
  }
  if (pattern.id === 'connection-string-password') {
    return matchText.split(value).join(redactSecretValue(value));
  }
  return redactSecretValue(value);
}

/**
 * Scan one source for secrets.
 * @returns {{findings:object[], secrets:object[], occurrences:number, skippedBinary:boolean}}
 */
export function scanSourceForSecrets(source, opts = {}) {
  const minEntropy = Number.isFinite(opts.minEntropy) ? Number(opts.minEntropy) : MIN_ENTROPY_DEFAULT;
  const maxFindingsPerFile = Number.isFinite(opts.maxFindingsPerFile)
    ? Math.max(1, Math.trunc(opts.maxFindingsPerFile))
    : 100;
  const signal = opts.signal;
  const findings = [];
  const secrets = [];
  const suppressed = [];
  const seen = new Set();
  let occurrences = 0;

  if (isLikelyBinary(source.buffer)) {
    return { findings, secrets, occurrences: 0, suppressed, skippedBinary: true };
  }
  const lines = source.buffer.toString('utf8').split('\n');
  const maxLines = Number.isFinite(opts.maxLinesPerFile) ? Math.max(1, opts.maxLinesPerFile) : 20000;
  const limit = Math.min(lines.length, maxLines);

  for (let index = 0; index < limit; index += 1) {
    if (signal?.aborted) break;
    if (findings.length >= maxFindingsPerFile) break;
    const rawLine = lines[index];
    if (!rawLine || rawLine.length < 8) continue;
    const specificSpans = [];
    const lineFindings = [];

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.generic) continue;
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(rawLine)) !== null) {
        if (match[0].length === 0) {
          pattern.regex.lastIndex += 1;
          continue;
        }
        const value = match[pattern.group ?? 0] ?? match[0];
        specificSpans.push({ start: match.index, end: match.index + match[0].length });
        occurrences += 1;
        if (isAllowlisted(value, { generic: false })) continue;
        const suppression = knownFalsePositive(pattern, value, rawLine, source.path);
        if (suppression) { suppressed.push({ rule: pattern.id, file: clip(String(source.path), 400), line: index + 1, reason: suppression }); continue; }
        if (pattern.minEntropy != null && shannonEntropy(value) < pattern.minEntropy) continue;
        lineFindings.push({ pattern, match, value });
      }
    }
    for (const pattern of SECRET_PATTERNS) {
      if (!pattern.generic) continue;
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(rawLine)) !== null) {
        if (match[0].length === 0) {
          pattern.regex.lastIndex += 1;
          continue;
        }
        const span = { start: match.index, end: match.index + match[0].length };
        const value = match[pattern.group ?? 0] ?? match[0];
        occurrences += 1;
        if (specificSpans.some((s) => rangesOverlap(s, span))) continue;
        if (isAllowlisted(value, { generic: true })) continue;
        const entropy = shannonEntropy(value);
        if (entropy < Math.max(minEntropy, pattern.minEntropy ?? minEntropy)) continue;
        lineFindings.push({ pattern, match, value });
      }
    }

    for (const { pattern, match, value } of lineFindings) {
      if (findings.length >= maxFindingsPerFile) break;
      const dedupeKey = `${pattern.id}|${value}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      const redacted = redactForPattern(pattern, match[0], value);
      const entropy = Number(shannonEntropy(value).toFixed(3));
      // Replace the raw secret occurrence before excerpt redaction so the
      // evidence can never leak it (even when it is not assignment-shaped).
      const excerptSource = match[0] && match[0] !== value ? rawLine.replace(match[0], redacted) : rawLine.split(value).join(redacted);
      const target = `${clip(source.path, 400)}:${index + 1}`;
      secrets.push({
        type: pattern.id,
        title: pattern.title,
        severity: pattern.severity,
        cwe: pattern.cwe,
        path: clip(source.path, 400),
        line: index + 1,
        entropy,
        length: value.length,
        redacted: clip(redacted, 120),
      });
      findings.push(
        finding({
          title: `[secret:${pattern.id}] ${pattern.title}`,
          severity: pattern.severity,
          description:
            `在源码中观察到符合 “${pattern.title}” 形态的凭据字符串（已脱敏显示为 ${clip(redacted, 80)}）。` +
            ' 可能是真实凭据，也可能是测试数据/占位符；请人工确认有效性。若为真实凭据，任何读过仓库的人都应视为已泄露。',
          verification: 'observed',
          method: 'regex-entropy-secret-scan',
          cwe: pattern.cwe,
          cvss: null,
          remediation:
            '立即在对应平台轮换/吊销该凭据，从 git 历史中清除（filter-repo/BFG），改用环境变量或密钥管理服务（Vault/KMS/Secrets Manager），并启用 secret scanning 防止再次提交。',
          target,
          evidence: [
            {
              title: `${baseName(source.path)}:${index + 1}`,
              excerpt: excerptLine(excerptSource, 400),
              meta: { patternId: pattern.id, line: index + 1, entropy, length: value.length },
            },
          ],
        }),
      );
    }
  }

  return { findings, secrets, occurrences, suppressed, skippedBinary: false };
}

/**
 * Scan many sources; deduplicates identical (pattern, value) across files
 * (first occurrence wins) and returns bounded results.
 */
export function scanSecrets(sources, opts = {}) {
  const findings = [];
  const secrets = [];
  const seen = new Set();
  const byType = new Map();
  const suppressed = [];
  let occurrences = 0;
  let skippedBinary = 0;
  const maxFindings = Number.isFinite(opts.maxFindings) ? Math.max(1, Math.trunc(opts.maxFindings)) : 100;

  for (const source of sources) {
    if (opts.signal?.aborted) break;
    if (findings.length >= maxFindings) break;
    const result = scanSourceForSecrets(source, { ...opts, maxFindingsPerFile: maxFindings - findings.length });
    if (result.skippedBinary) {
      skippedBinary += 1;
      continue;
    }
    occurrences += result.occurrences;
    suppressed.push(...(result.suppressed ?? []));
    for (const secret of result.secrets) {
      const key = `${secret.type}|${secret.redacted}`;
      const existing = byType.get(secret.type);
      byType.set(secret.type, (existing ?? 0) + 1);
      if (seen.has(key)) continue;
      seen.add(key);
      secrets.push(secret);
    }
    findings.push(...result.findings);
  }

  return {
    findings: findings.slice(0, maxFindings),
    secrets: secrets.slice(0, maxFindings),
    suppressed,
    stats: {
      suppressed: suppressed.length,
      suppressedReasons: [...new Set(suppressed.map((item) => item.reason).filter(Boolean))],
      candidateOccurrences: occurrences,
      uniqueSecrets: secrets.length,
      skippedBinaryFiles: skippedBinary,
      byType: Object.fromEntries([...byType.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
    },
  };
}
