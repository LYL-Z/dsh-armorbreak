/**
 * ArmorBreak binary domain — shared bounded helpers.
 * Zero dependencies: node:* builtins only.
 *
 * All helpers are deterministic, bounded, and never trust sample bytes:
 * parsing code must stay defensive and report problems as warnings instead of throwing.
 */
import { createHash } from 'node:crypto';
import { statSync } from 'node:fs';

export const DEFAULT_LIMITS = Object.freeze({
  maxBytes: 8 * 1024 * 1024,
  maxItems: 200,
  maxStrings: 500,
  maxFindings: 100,
  timeoutMs: 15000,
});

export const HARD_MAX_SCAN_BYTES = 64 * 1024 * 1024;

/** Coerce arbitrary limits input into safe bounded integers. */
export function normalizeLimits(limits) {
  const l = limits && typeof limits === 'object' ? limits : {};
  const int = (v, def, min, max) => {
    const n = Number(v);
    if (!Number.isFinite(n)) return def;
    return Math.min(max, Math.max(min, Math.floor(n)));
  };
  return {
    maxBytes: int(l.maxBytes, DEFAULT_LIMITS.maxBytes, 1, HARD_MAX_SCAN_BYTES),
    maxItems: int(l.maxItems, DEFAULT_LIMITS.maxItems, 1, 5000),
    maxStrings: int(l.maxStrings, DEFAULT_LIMITS.maxStrings, 1, 20000),
    maxFindings: int(l.maxFindings, DEFAULT_LIMITS.maxFindings, 1, 1000),
    timeoutMs: int(l.timeoutMs, DEFAULT_LIMITS.timeoutMs, 1, 300000),
  };
}

/** Cooperative cancellation. Long loops call this; abort surfaces as a normal Error. */
export function checkAbort(env, capId) {
  if (env && env.signal && env.signal.aborted) {
    throw new Error(`${capId}: 分析被中止（AbortSignal 已触发）。已产生的部分结果未写回；如需完整结果请重新发起且不要取消。`);
  }
}

/**
 * Resolve the bytes to analyze from the run(input) contract.
 * Prefers input.buffer; falls back to re-encoding input.text and records that provenance.
 * Throws an actionable Error when there is nothing analyzable.
 */
export function requireBytes(input, capId) {
  const buffer = input && Buffer.isBuffer(input.buffer) ? input.buffer : null;
  if (buffer && buffer.length > 0) {
    return { buffer, source: 'buffer', warnings: [] };
  }
  if (buffer && buffer.length === 0) {
    throw new Error(`${capId}: 目标文件为 0 字节，无法进行二进制分析。请确认 targetPath 指向非空文件；目录型目标请改用 web/sast 等目录能力。`);
  }
  const text = input && typeof input.text === 'string' ? input.text : '';
  if (text.length > 0) {
    return {
      buffer: Buffer.from(text, 'utf8'),
      source: 'text-reencoded',
      warnings: [`核心未提供 buffer，已把 input.text 按 UTF-8 重新编码为字节（可能丢失非文本字节，仅作为降级路径）。`],
    };
  }
  throw new Error(`${capId}: 缺少可分析字节：input.buffer 与 input.text 均为空。请通过 targetPath 指定存在的普通文件，核心会读取并传入 buffer；若文件不可读请先修复路径/权限。`);
}

/**
 * Offline file-size discovery from targetPath (single read-only stat, no I/O amplification).
 * Used only to report truncation honestly when the core passes a capped buffer.
 */
export function statTargetFile(input) {
  const p = input && typeof input.targetPath === 'string' ? input.targetPath : null;
  if (!p) return { fileSize: null };
  try {
    const st = statSync(p);
    if (!st.isFile()) return { fileSize: null };
    return { fileSize: st.size };
  } catch {
    return { fileSize: null };
  }
}

/** Compare known file size with the buffer length actually available. */
export function truncationInfo(input, analyzedBytes) {
  const env = input && input.env ? input.env : null;
  let fileSize = null;
  if (env && Number.isFinite(env.targetSize)) {
    fileSize = env.targetSize;
  } else {
    fileSize = statTargetFile(input).fileSize;
  }
  if (!Number.isFinite(fileSize)) return { fileSize: null, truncated: null, warnings: [] };
  const truncated = env && env.targetTruncated === true ? true : analyzedBytes < fileSize;
  return {
    fileSize,
    truncated,
    warnings: truncated
      ? [`核心仅提供 ${analyzedBytes}/${fileSize} 字节（受 limits 上限限制），哈希与结构解析仅覆盖已读入部分。`]
      : [],
  };
}

export function hashHex(buffer, algo) {
  const allowed = new Set(['md5', 'sha1', 'sha256', 'sha512']);
  if (!allowed.has(algo)) throw new Error(`不支持的哈希算法: ${String(algo)}。可用: ${[...allowed].join(', ')}`);
  return createHash(algo).update(buffer).digest('hex');
}

export function hex(n, width = 0) {
  if (typeof n === 'bigint') {
    const s = n.toString(16);
    return '0x' + (width ? s.padStart(width, '0') : s);
  }
  const v = Number(n);
  if (!Number.isFinite(v)) return null;
  const s = Math.trunc(v).toString(16);
  return '0x' + (width ? s.padStart(width, '0') : s);
}

export function toBigInt(value) {
  if (typeof value === 'bigint') return value;
  const n = Number(value);
  return Number.isFinite(n) ? BigInt(Math.trunc(n)) : 0n;
}

export function bigIntToSafeNumber(v) {
  if (v <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(v);
  return null;
}

/** Read little/big endian unsigned integers defensively. Returns null when out of bounds. */
export function readU8(buf, off) {
  if (!Buffer.isBuffer(buf) || off < 0 || off + 1 > buf.length) return null;
  return buf[off];
}
export function readU16(buf, off, littleEndian = true) {
  if (!Buffer.isBuffer(buf) || off < 0 || off + 2 > buf.length) return null;
  return littleEndian ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
}
export function readU32(buf, off, littleEndian = true) {
  if (!Buffer.isBuffer(buf) || off < 0 || off + 4 > buf.length) return null;
  return littleEndian ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
}
export function readBigU64(buf, off, littleEndian = true) {
  if (!Buffer.isBuffer(buf) || off < 0 || off + 8 > buf.length) return null;
  return littleEndian ? buf.readBigUInt64LE(off) : buf.readBigUInt64BE(off);
}
export function readU64NumberIfSafe(buf, off, littleEndian = true) {
  const v = readBigU64(buf, off, littleEndian);
  if (v === null) return null;
  return bigIntToSafeNumber(v);
}

/** BigInt-safe width padding for hex output. */
export function hexBig(v, width = 0) {
  const s = v.toString(16);
  return '0x' + (width ? s.padStart(width, '0') : s);
}

/** Shannon entropy in bits per byte (0..8). Bounded by caller; caps internally too. */
export function entropyOf(data, maxScan = 4 * 1024 * 1024) {
  const buf = Buffer.isBuffer(data) ? data.subarray(0, Math.min(data.length, maxScan)) : Buffer.alloc(0);
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i += 1) counts[buf[i]] += 1;
  let h = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const p = counts[i] / buf.length;
    h -= p * Math.log2(p);
  }
  return Math.round(h * 1e6) / 1e6;
}

export function byteStats(data, maxScan = 4 * 1024 * 1024) {
  const buf = Buffer.isBuffer(data) ? data.subarray(0, Math.min(data.length, maxScan)) : Buffer.alloc(0);
  const total = buf.length;
  const counts = new Uint32Array(256);
  for (let i = 0; i < total; i += 1) counts[buf[i]] += 1;
  let printable = 0;
  let zero = 0;
  for (let i = 0; i < total; i += 1) {
    const b = buf[i];
    if (b === 0) zero += 1;
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable += 1;
  }
  let unique = 0;
  let maxCount = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] > 0) unique += 1;
    if (counts[i] > maxCount) maxCount = counts[i];
  }
  return {
    analyzedBytes: total,
    zeroByteRatio: total ? Math.round((zero / total) * 1e6) / 1e6 : 0,
    printableRatio: total ? Math.round((printable / total) * 1e6) / 1e6 : 0,
    uniqueByteCount: unique,
    mostCommonByteRatio: total ? Math.round((maxCount / total) * 1e6) / 1e6 : 0,
  };
}

/** Strip control characters (keep \n and \t), collapse whitespace, cap length. */
export function sanitizeText(value, maxLen = 2000) {
  if (value === null || value === undefined) return '';
  let s = typeof value === 'string' ? value : String(value);
  s = s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  s = s.replace(/\r\n?/g, '\n');
  s = s.replace(/\t/g, ' ');
  s = s.replace(/ {2,}/g, ' ');
  s = s.replace(/\n{3,}/g, '\n\n');
  s = s.trim();
  if (s.length > maxLen) s = `${s.slice(0, Math.max(0, maxLen - 14))}…[truncated]`;
  return s;
}

export function excerptOf(value, maxLen = 2000) {
  return sanitizeText(value, Math.min(2000, maxLen));
}

export function capArray(arr, cap) {
  const list = Array.isArray(arr) ? arr : [];
  if (list.length <= cap) return { items: list, truncated: false };
  return { items: list.slice(0, cap), truncated: true };
}

export function round(n, digits = 4) {
  if (!Number.isFinite(n)) return null;
  const f = 10 ** digits;
  return Math.round(n * f) / f;
}

export function formatUnixTime(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  const ms = Math.trunc(seconds) * 1000;
  if (ms < Date.UTC(1970, 0, 2) || ms > Date.UTC(2100, 0, 1)) return null;
  return new Date(ms).toISOString().replace('.000Z', 'Z');
}

/** DOS date/time pair -> approximated ISO string (no zone info in DOS timestamps). */
export function formatDosDateTime(dateWord, timeWord) {
  if (!Number.isInteger(dateWord) || !Number.isInteger(timeWord)) return null;
  const year = 1980 + ((dateWord >> 9) & 0x7f);
  const month = (dateWord >> 5) & 0x0f;
  const day = dateWord & 0x1f;
  const hours = (timeWord >> 11) & 0x1f;
  const minutes = (timeWord >> 5) & 0x3f;
  const seconds = (timeWord & 0x1f) * 2;
  if (month < 1 || month > 12 || day < 1 || day > 31 || hours > 23 || minutes > 59 || seconds > 59) return null;
  const iso = `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
  const epochSeconds = Math.floor(Date.UTC(year, month - 1, day, hours, minutes, seconds) / 1000);
  return { iso, epochSeconds, timezone: 'local-unassigned' };
}

/** Read a NUL-terminated printable ASCII string at offset. */
export function readAsciiZ(buffer, offset, maxLen = 256) {
  if (!Buffer.isBuffer(buffer) || !Number.isInteger(offset) || offset < 0 || offset >= buffer.length) return null;
  const end = Math.min(buffer.length, offset + maxLen);
  const bytes = [];
  for (let i = offset; i < end; i += 1) {
    const b = buffer[i];
    if (b === 0) break;
    if (b < 0x20 || b > 0x7e) return bytes.length > 0 ? sanitizeText(Buffer.from(bytes).toString('latin1'), 512) : null;
    bytes.push(b);
  }
  if (bytes.length === 0) return null;
  return sanitizeText(Buffer.from(bytes).toString('latin1'), 512);
}

/** ASCII printable-string extraction, bounded and deterministic (ascending offsets). */
export function extractAsciiStrings(buffer, opts = {}) {
  const minLen = Math.max(4, Math.floor(Number(opts.minLen) || 4));
  const max = Math.max(1, Math.floor(Number(opts.max) || 500));
  const maxScan = Math.max(0, Math.min(buffer.length, Math.floor(Number(opts.maxScan) || buffer.length)));
  const out = [];
  let runStart = -1;
  const scan = Math.min(buffer.length, maxScan);
  for (let i = 0; i < scan; i += 1) {
    const b = buffer[i];
    const printable = (b >= 0x20 && b <= 0x7e) || b === 0x09;
    if (printable) {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      if (i - runStart >= minLen) out.push({ offset: runStart, value: Buffer.from(buffer.subarray(runStart, i)).toString('latin1') });
      runStart = -1;
      if (out.length >= max) return { strings: out, truncated: true };
    }
  }
  if (runStart >= 0 && scan - runStart >= minLen && out.length < max) {
    out.push({ offset: runStart, value: Buffer.from(buffer.subarray(runStart, scan)).toString('latin1') });
  }
  return { strings: out, truncated: out.length >= max };
}

/** UTF-16LE/BE printable-string extraction. */
export function extractUtf16Strings(buffer, opts = {}) {
  const minLen = Math.max(4, Math.floor(Number(opts.minLen) || 4));
  const max = Math.max(1, Math.floor(Number(opts.max) || 500));
  const littleEndian = opts.endian !== 'be';
  const maxScan = Math.max(0, Math.min(buffer.length, Math.floor(Number(opts.maxScan) || buffer.length)));
  const scan = Math.min(buffer.length, maxScan) & ~1;
  const out = [];
  let runStart = -1;
  let chars = [];
  const flush = (endOff) => {
    if (runStart >= 0 && chars.length >= minLen) out.push({ offset: runStart, value: chars.join('') });
    runStart = -1;
    chars = [];
    return out.length >= max;
  };
  for (let i = 0; i + 1 < scan; i += 2) {
    const code = littleEndian ? buffer[i] | (buffer[i + 1] << 8) : (buffer[i] << 8) | buffer[i + 1];
    const printable = (code >= 0x20 && code <= 0x7e) || code === 0x09;
    if (printable) {
      if (runStart < 0) runStart = i;
      chars.push(String.fromCharCode(code));
    } else if (runStart >= 0) {
      if (flush()) return { strings: out, truncated: true };
    }
  }
  if (runStart >= 0) flush();
  return { strings: out, truncated: out.length >= max };
}

export function makeMeta(capId, format, byteInfo, warnings) {
  return {
    capability: capId,
    format,
    analyzedBytes: byteInfo.analyzedBytes,
    source: byteInfo.source,
    truncated: byteInfo.truncated,
    warnings,
    zeroDependencies: true,
  };
}

/** Build a contract-conformant finding with safe defaults. */
export function makeFinding({
  title,
  severity = 'info',
  description,
  verification = 'observed',
  method,
  cwe = null,
  cvss = null,
  remediation,
  target = null,
  evidence = [],
}) {
  const severities = new Set(['critical', 'high', 'medium', 'low', 'info']);
  const verifications = new Set(['observed', 'corroborated', 'hypothesis', 'unverified']);
  return {
    title: sanitizeText(title, 300),
    severity: severities.has(severity) ? severity : 'info',
    description: sanitizeText(description, 3000),
    verification: verifications.has(verification) ? verification : 'unverified',
    method: sanitizeText(method, 300),
    cwe: typeof cwe === 'string' ? cwe : null,
    cvss: typeof cvss === 'number' && cvss >= 0 && cvss <= 10 ? cvss : null,
    remediation: sanitizeText(remediation, 800),
    target,
    evidence: (Array.isArray(evidence) ? evidence : []).slice(0, 8).map((e) => ({
      title: sanitizeText(e && e.title ? e.title : 'evidence', 200),
      excerpt: excerptOf(e && e.excerpt ? e.excerpt : ''),
      ...(e && e.meta && typeof e.meta === 'object' ? { meta: e.meta } : {}),
    })),
  };
}

export function makeEvidence(title, kind, excerpt, meta) {
  return {
    title: sanitizeText(title, 200),
    kind: sanitizeText(kind, 80),
    excerpt: excerptOf(excerpt),
    ...(meta && typeof meta === 'object' ? { meta } : {}),
  };
}

/** Sanity cap for data payloads: JSON serialized size must stay <= 256 KiB. */
export function enforceDataSize(data, notes) {
  let json;
  try {
    json = JSON.stringify(data);
  } catch {
    return data;
  }
  const cap = 256 * 1024;
  if (json.length <= cap) return data;
  const note = `data 序列化 ${json.length} 字节超过 256 KiB，已截断可变长数组。`;
  if (Array.isArray(notes)) notes.push(note);
  const clone = { ...data };
  for (const key of Object.keys(clone)) {
    if (Array.isArray(clone[key]) && clone[key].length > 20) clone[key] = clone[key].slice(0, 20);
  }
  return clone;
}

export const SEVERITY_ORDER = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });
