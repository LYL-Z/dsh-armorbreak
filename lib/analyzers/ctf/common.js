// ArmorBreak CTF domain — shared, dependency-free helpers.
//
// CTF data is intentionally weird: everything is treated as untrusted data,
// control characters are stripped from previews/evidence, and every result is
// bounded by the caller's limits.

export const SEVERITY_RANK = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, info: 1 });

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

export function stripControl(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
}

export function clip(value, max = 2000) {
  const s = stripControl(typeof value === 'string' ? value : String(value ?? ''));
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

export function compact(value, max = 2000) {
  return clip(value, max).replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function normalizeEvidence(item) {
  if (item == null) return { title: 'evidence', excerpt: '' };
  if (typeof item !== 'object') return { title: 'evidence', excerpt: clip(String(item)) };
  const ev = { title: compact(item.title ?? 'evidence', 200), excerpt: clip(item.excerpt ?? '', 2000) };
  if (item.meta && typeof item.meta === 'object' && !Array.isArray(item.meta)) ev.meta = item.meta;
  return ev;
}

const VERIFICATIONS = new Set(['observed', 'corroborated', 'hypothesis', 'unverified']);

export function finding(spec = {}) {
  return {
    title: compact(spec.title || 'finding', 300),
    severity: Object.hasOwn(SEVERITY_RANK, spec.severity) ? spec.severity : 'info',
    description: compact(spec.description || '', 4000),
    verification: VERIFICATIONS.has(spec.verification) ? spec.verification : 'unverified',
    method: compact(spec.method || '', 300),
    cwe: typeof spec.cwe === 'string' && /^CWE-\d+$/.test(spec.cwe) ? spec.cwe : null,
    cvss: Number.isFinite(spec.cvss) ? Math.max(0, Math.min(10, spec.cvss)) : null,
    remediation: compact(spec.remediation || '', 2000),
    target: spec.target == null ? null : compact(String(spec.target), 500),
    evidence: Array.isArray(spec.evidence) ? spec.evidence.slice(0, 20).map(normalizeEvidence) : [],
  };
}

function cmp(a, b) {
  const x = String(a ?? '');
  const y = String(b ?? '');
  return x < y ? -1 : x > y ? 1 : 0;
}

export function sortFindings(findings) {
  return findings.slice().sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      cmp(a.target, b.target) ||
      cmp(a.title, b.title),
  );
}

export function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

export function shannonEntropy(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? ''), 'utf8');
  if (!data.length) return 0;
  const counts = new Map();
  for (const byte of data) counts.set(byte, (counts.get(byte) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / data.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Fraction of characters that are printable ASCII / whitespace. */
export function printableRatio(text) {
  const s = String(text ?? '');
  if (!s.length) return 0;
  let printable = 0;
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126)) printable += 1;
  }
  return printable / s.length;
}

export function isPrintableText(text, threshold = 0.85) {
  return printableRatio(text) >= threshold;
}

/** Safe, single-block preview used in summaries/data/steps. */
export function previewText(text, max = 300) {
  return compact(String(text ?? '').replace(/\u0000/g, '␀'), max);
}

export function hexDump(buffer, maxBytes = 32) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) return '';
  return buffer
    .subarray(0, maxBytes)
    .toString('hex')
    .match(/.{1,2}/g)
    .join(' ');
}

/** Extract printable ASCII runs (useful for scanning binary payloads for flags). */
export function asciiStrings(buffer, opts = {}) {
  const minLength = clampInt(opts.minLength, 4, 1, 64);
  const maxItems = clampInt(opts.maxItems, 100, 1, 1000);
  const out = [];
  if (!Buffer.isBuffer(buffer) || !buffer.length) return out;
  let start = -1;
  for (let i = 0; i <= buffer.length; i += 1) {
    const byte = i < buffer.length ? buffer[i] : 0;
    const printable = byte >= 32 && byte <= 126;
    if (printable && start < 0) start = i;
    else if (!printable && start >= 0) {
      const length = i - start;
      if (length >= minLength) {
        out.push({ offset: start, text: buffer.subarray(start, i).toString('latin1') });
        if (out.length >= maxItems) return out;
      }
      start = -1;
    }
  }
  return out;
}

export function bytesEqual(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && a.equals(b);
}

/** Coerce input.text / input.buffer into a single Buffer + text pair. */
export function artifactFromInput(input) {
  const buffer = Buffer.isBuffer(input?.buffer) && input.buffer.length ? input.buffer : null;
  const text = typeof input?.text === 'string' ? input.text : buffer ? buffer.toString('utf8') : '';
  if (!buffer && !text) {
    throw new Error(
      '输入为空：请提供待分析数据（targetPath 指向文件得到 input.buffer/text，或直接在 input.text 中提供文本）。',
    );
  }
  const bytes = buffer ?? Buffer.from(text, 'utf8');
  return { bytes, text, fromBuffer: Boolean(buffer) };
}
