// ArmorBreak web domain — shared, dependency-free helpers.
//
// Safety rules enforced here:
//   * every string that leaves this module passes stripControl()/clip();
//   * credential values are NEVER echoed raw: use redactHeaderValue(),
//     redactParamValue(), redactUrl() or describeCookie();
//   * all parsing helpers throw actionable Errors (what is missing + why + how to fix).

export const SEVERITY_RANK = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, info: 1 });

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

/** Strip ANSI escapes / C0+C1 control characters but keep \n and \t. */
export function stripControl(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
}

/** Hard clip (after control-char stripping) to `max` characters. */
export function clip(value, max = 2000) {
  const s = stripControl(typeof value === 'string' ? value : String(value ?? ''));
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

/** Clip + collapse runs of whitespace; used for summaries/excerpts. */
export function compact(value, max = 2000) {
  return clip(value, max).replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

export function normSeverity(severity, fallback = 'info') {
  return Object.hasOwn(SEVERITY_RANK, severity) ? severity : fallback;
}

const VERIFICATIONS = new Set(['observed', 'corroborated', 'hypothesis', 'unverified']);

function normalizeEvidence(item) {
  if (item == null) return { title: 'evidence', excerpt: '' };
  if (typeof item !== 'object') return { title: 'evidence', excerpt: clip(String(item)) };
  const ev = {
    title: compact(item.title ?? 'evidence', 200),
    excerpt: clip(item.excerpt ?? '', 2000),
  };
  if (item.meta && typeof item.meta === 'object' && !Array.isArray(item.meta)) ev.meta = item.meta;
  return ev;
}

/** Build a contract-shaped finding with safe defaults. */
export function finding(spec = {}) {
  return {
    title: compact(spec.title || 'finding', 300),
    severity: normSeverity(spec.severity),
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

/** Deterministic finding order: severity desc, title asc, target asc. */
export function sortFindings(findings) {
  return findings
    .slice()
    .sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        cmp(a.title, b.title) ||
        cmp(a.target, b.target),
    );
}

// ---------------------------------------------------------------------------
// Header / cookie redaction and parsing
// ---------------------------------------------------------------------------

const SECRET_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
  'api-key',
  'apikey',
  'x-amz-security-token',
  'x-goog-api-key',
  'x-access-token',
  'x-session-token',
]);

/** Parse one Set-Cookie header value into name/value/attributes. */
export function parseSetCookie(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  const parts = raw
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean);
  const first = parts.shift() || '';
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  const name = first.slice(0, eq).trim();
  const value = first.slice(eq + 1).trim();
  const attrs = {};
  for (const part of parts) {
    const i = part.indexOf('=');
    const key = (i < 0 ? part : part.slice(0, i)).trim().toLowerCase();
    if (!key) continue;
    const value2 = i < 0 ? true : part.slice(i + 1).trim();
    if (key === 'samesite') attrs.sameSite = String(value2);
    else if (key === 'max-age') attrs.maxAge = String(value2);
    else if (key === 'domain') attrs.domain = String(value2);
    else if (key === 'path') attrs.path = String(value2);
    else if (key === 'expires') attrs.expires = String(value2);
    else attrs[key] = value2;
  }
  return { name, value, attrs };
}

/** Render a cookie with a masked value but visible security attributes. */
export function describeCookie(cookie) {
  if (!cookie || typeof cookie !== 'object') return 'cookie=••••';
  const bits = [`${clip(cookie.name, 80)}=••••`];
  const attrs = cookie.attrs || {};
  if (attrs.path) bits.push(`Path=${clip(String(attrs.path), 120)}`);
  if (attrs.domain) bits.push(`Domain=${clip(String(attrs.domain), 120)}`);
  if (attrs.maxAge !== undefined) bits.push(`Max-Age=${clip(String(attrs.maxAge), 20)}`);
  if (attrs.secure) bits.push('Secure');
  if (attrs.httponly) bits.push('HttpOnly');
  if (attrs.sameSite) bits.push(`SameSite=${clip(String(attrs.sameSite), 20)}`);
  return bits.join('; ');
}

/** Redact one header value; never returns raw credential material. */
export function redactHeaderValue(name, value) {
  const n = String(name || '').toLowerCase().trim();
  const v = compact(value, 400);
  if (n === 'authorization' || n === 'proxy-authorization') {
    const m = /^([A-Za-z][A-Za-z0-9+.-]*)\s+\S/.exec(v);
    return m ? `${m[1]} ••••` : '••••';
  }
  if (n === 'cookie') return 'cookie=••••';
  if (n === 'set-cookie') {
    const cookie = parseSetCookie(v);
    return cookie ? describeCookie(cookie) : 'set-cookie=••••';
  }
  if (SECRET_HEADERS.has(n)) return '••••';
  return v;
}

function parseHeaderLine(line, lineNo, source) {
  const idx = line.indexOf(':');
  if (idx <= 0) {
    throw new Error(
      `${source} 第 ${lineNo} 行不是合法 HTTP 头（缺少冒号）："${clip(line, 120)}"。` +
        ' 期望格式为 “Header-Name: value”，每行一个头。',
    );
  }
  const name = line.slice(0, idx).trim();
  const value = line.slice(idx + 1).trim();
  if (!name) {
    throw new Error(
      `${source} 第 ${lineNo} 行头名称为空："${clip(line, 120)}"。请检查输入。`,
    );
  }
  return { name, value };
}

/** Parse raw "Name: value" lines, honouring obsolete line folding. */
export function parseHeaderLines(raw, { source = '头文本' } = {}) {
  const out = [];
  const lines = stripControl(String(raw ?? '')).split('\n');
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (!line.trim()) continue;
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1].value = `${out[out.length - 1].value} ${line.trim()}`.trim();
      continue;
    }
    out.push(parseHeaderLine(line, i + 1, source));
  }
  return out;
}

/**
 * Normalize many header shapes into ordered [{name, value}] pairs.
 * Accepts: raw text, object map (values string|string[]), [{name,value}], [[name,value]], string[].
 */
export function normalizeHeaderPairs(input, opts = {}) {
  const source = opts.source || 'header 输入';
  if (input == null) return [];
  if (typeof input === 'string') return parseHeaderLines(input, { source });
  if (Array.isArray(input)) {
    const out = [];
    for (const item of input) {
      if (item == null) continue;
      if (typeof item === 'string') out.push(...parseHeaderLines(item, { source }));
      else if (Array.isArray(item) && item.length >= 2) {
        out.push({ name: String(item[0]).trim(), value: String(item[1] ?? '').trim() });
      } else if (typeof item === 'object' && item.name != null) {
        const names = Array.isArray(item.name) ? item.name : [item.name];
        const values = Array.isArray(item.value) ? item.value : [item.value];
        for (let i = 0; i < Math.max(names.length, values.length); i += 1) {
          out.push({ name: String(names[i] ?? '').trim(), value: String(values[i] ?? '').trim() });
        }
      }
    }
    return out.filter((p) => p.name);
  }
  if (typeof input === 'object') {
    const out = [];
    for (const [name, value] of Object.entries(input)) {
      if (value == null) continue;
      if (Array.isArray(value)) {
        for (const v of value) out.push({ name: String(name), value: String(v) });
      } else if (typeof value === 'object') {
        out.push({ name: String(name), value: JSON.stringify(value) });
      } else {
        out.push({ name: String(name), value: String(value) });
      }
    }
    return out;
  }
  throw new Error(
    `无法解析${source}：期望 JSON 对象/数组、[[name, value]]，或 “Header-Name: value” 文本行。`,
  );
}

export function getHeaderValues(pairs, name) {
  const n = String(name || '').toLowerCase();
  return pairs.filter((p) => String(p.name || '').toLowerCase() === n).map((p) => p.value);
}

export function getHeader(pairs, name) {
  const values = getHeaderValues(pairs, name);
  return values.length ? values[values.length - 1] : null;
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

export function tryParseUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  try {
    return new URL(raw.trim());
  } catch {
    return null;
  }
}

/** Mask sensitive values inside a raw (possibly relative) query string. */
export function redactQueryString(raw) {
  const value = typeof raw === 'string' ? raw : '';
  const queryIndex = value.indexOf('?');
  if (queryIndex < 0) return value;
  const prefix = value.slice(0, queryIndex + 1);
  const rest = value.slice(queryIndex + 1);
  const hashIndex = rest.indexOf('#');
  const hash = hashIndex >= 0 ? rest.slice(hashIndex) : '';
  const query = hashIndex >= 0 ? rest.slice(0, hashIndex) : rest;
  const parts = query.split('&').map((part) => {
    const eq = part.indexOf('=');
    if (eq < 0) return part;
    const name = part.slice(0, eq);
    const encoded = part.slice(eq + 1);
    if (!isSensitiveParamName(name)) return part;
    let decoded = encoded;
    try {
      decoded = decodeURIComponent(encoded);
    } catch {
      // keep encoded form for masking
    }
    return `${name}=${redactParamValue(decoded)}`;
  });
  return `${prefix}${parts.join('&')}${hash}`;
}

export function redactUrl(raw, max = 500) {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (!value) return '';
  const parsed = tryParseUrl(value);
  if (!parsed) return clip(redactQueryString(value), max);
  try {
    for (const key of [...parsed.searchParams.keys()]) {
      if (isSensitiveParamName(key)) {
        parsed.searchParams.set(key, redactParamValue(parsed.searchParams.get(key)));
      }
    }
    if (parsed.username) parsed.username = '••••';
    if (parsed.password) parsed.password = '••••';
    return clip(parsed.toString(), max);
  } catch {
    return clip(value, max);
  }
}

const STRONG_PARAM_MARKERS = [
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'authtoken',
  'apitoken',
  'sessiontoken',
  'bearertoken',
  'sessionid',
  'clientsecret',
  'apikey',
  'privatekey',
  'authorization',
  'password',
  'passwd',
  'pwd',
  'token',
  'secret',
  'session',
  'jwt',
  'signature',
  'credential',
  'auth',
];

/**
 * If `rawName` looks like a credential-bearing parameter, return
 * { name, marker, severity }; otherwise null.
 */
export function sensitiveParamInfo(rawName) {
  const original = String(rawName ?? '').trim();
  if (!original) return null;
  const normalized = original.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!normalized) return null;
  for (const marker of STRONG_PARAM_MARKERS) {
    if (normalized === marker || normalized.includes(marker)) {
      return { name: original, marker, severity: 'medium' };
    }
  }
  if (normalized === 'code') return { name: original, marker: 'code', severity: 'low' };
  return null;
}

export function isSensitiveParamName(rawName) {
  return sensitiveParamInfo(rawName) !== null;
}

/** Mask a sensitive value: first 4 chars + *** (short values fully masked). */
export function redactParamValue(value) {
  const v = typeof value === 'string' ? value : value == null ? '' : String(value);
  if (v.length <= 6) return '••••';
  return `${v.slice(0, 4)}***`;
}

const SENSITIVE_PATH_RE = /(?:login|signin|sign-in|auth|session|account|admin|user|profile|password|passwd|token|oauth|checkout|payment|billing|secret|key|credential)/i;

export function isSensitiveUrlPath(urlOrParsed) {
  const parsed = typeof urlOrParsed === 'string' ? tryParseUrl(urlOrParsed) : urlOrParsed;
  if (!parsed) return false;
  const path = String(parsed.pathname || '');
  if (SENSITIVE_PATH_RE.test(path)) return true;
  for (const key of parsed.searchParams.keys()) {
    if (isSensitiveParamName(key)) return true;
  }
  return false;
}

export function isHtmlMime(value) {
  return /(?:^text\/html\b|application\/xhtml\+xml)/i.test(String(value ?? ''));
}

// ---------------------------------------------------------------------------
// Small parsers
// ---------------------------------------------------------------------------

export function parseCacheControl(value) {
  const map = new Map();
  for (const part of String(value ?? '').split(',')) {
    const t = part.trim();
    if (!t) continue;
    const i = t.indexOf('=');
    const key = (i < 0 ? t : t.slice(0, i)).trim().toLowerCase();
    const val = i < 0 ? true : t.slice(i + 1).trim().replace(/^"|"$/g, '');
    if (key) map.set(key, val);
  }
  return map;
}

/**
 * Parse a text input that is either JSON (object / array-encoded HAR docs)
 * or a plain document. Throws actionable errors on invalid JSON.
 */
export function parseJsonText(text, what = '输入') {
  const raw = stripControl(String(text ?? '')).replace(/^\uFEFF/, '').trim();
  if (!raw) {
    throw new Error(
      `${what}为空：请把 JSON 内容放在输入文本（input.text）或目标文件（targetPath）中。`,
    );
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `${what}不是合法 JSON：${error.message}。请确认输入是完整的 JSON 文档（常见原因：尾随逗号、注释、被截断）。`,
    );
  }
}

/** Coerce whatever the core gave us to text, with an actionable error. */
export function textFromInput(input, what = '输入') {
  if (typeof input?.text === 'string' && input.text.length > 0) return input.text;
  if (Buffer.isBuffer(input?.buffer) && input.buffer.length > 0) {
    return input.buffer.toString('utf8');
  }
  throw new Error(
    `${what}为空：未提供 input.text 或 input.buffer。请把要分析的内容作为目标文件或文本传入。`,
  );
}

/** Boolean helper for testing bound limits. */
export function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}
