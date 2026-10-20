/**
 * ArmorBreak — forensics domain shared helpers.
 * Reuses battle-tested generic helpers from the binary domain (same package, zero deps),
 * adds forensics-specific input handling and timestamp formats.
 */
import * as binaryUtil from '../binary/util.js';
import {
  checkAbort,
  enforceDataSize,
  makeMeta,
  normalizeLimits,
  statTargetFile,
} from '../binary/util.js';

export const {
  sanitizeText,
  excerptOf,
  makeFinding,
  makeEvidence,
  hex,
  readU16,
  readU32,
  readBigU64,
  readU8,
  formatUnixTime,
  formatDosDateTime,
  readAsciiZ,
  entropyOf,
  hashHex,
  truncationInfo,
  byteStats,
  capArray,
  round,
} = binaryUtil;

export { makeMeta, normalizeLimits, checkAbort, enforceDataSize };

/** Resolve analyzable bytes with forensics-specific actionable errors. */
export function prepareInput(input, capId) {
  const buffer = input && Buffer.isBuffer(input.buffer) ? input.buffer : null;
  let source = 'buffer';
  let byteWarnings = [];
  let bytes = buffer;
  if (!bytes || bytes.length === 0) {
    const text = input && typeof input.text === 'string' ? input.text : '';
    if (text.length > 0) {
      bytes = Buffer.from(text, 'utf8');
      source = 'text-reencoded';
      byteWarnings = ['核心未提供 buffer，已把 input.text 按 UTF-8 重新编码（可能丢失原始字节，仅作为降级路径）。'];
    } else if (buffer && buffer.length === 0) {
      throw new Error(`${capId}: 目标文件为 0 字节，取证分析需要非空文件内容。请确认 targetPath 指向非空文件；目录型目标请先指定其中的具体文件。`);
    } else {
      throw new Error(`${capId}: 缺少可分析字节：input.buffer 与 input.text 均为空。请通过 targetPath 指定存在的普通文件，核心会读取并传入 buffer；若路径无效或权限不足请先修复。`);
    }
  }
  const limits = normalizeLimits(input && input.limits);
  checkAbort(input && input.env, capId);
  const env = input && input.env ? input.env : null;
  let fileSize = env && Number.isFinite(env.targetSize) ? env.targetSize : null;
  if (fileSize === null) fileSize = statTargetFile(input).fileSize;
  const truncated = env && env.targetTruncated === true
    ? true
    : (Number.isFinite(fileSize) ? bytes.length < fileSize : null);
  const warnings = [...byteWarnings];
  if (truncated === true) {
    warnings.push(`核心仅提供 ${bytes.length}/${fileSize} 字节（受 limits 上限限制），结果只覆盖已读入部分。`);
  }
  return { buffer: bytes, source, limits, fileSize, truncated, warnings };
}

export function finishResult({ capId, format, prepared, summary, data, findings = [], evidence = [], meta = {} }) {
  const warnings = [...prepared.warnings];
  return {
    summary: binaryUtil.sanitizeText(summary, 4000),
    findings: findings.slice(0, prepared.limits.maxFindings),
    evidence: evidence.slice(0, 8),
    data: enforceDataSize(data, warnings),
    meta: {
      ...makeMeta(capId, format, {
        analyzedBytes: prepared.buffer.length,
        source: prepared.source,
        truncated: prepared.truncated,
      }, warnings),
      fileSize: prepared.fileSize,
      ...meta,
    },
  };
}

/** Compute selected digests; algorithms are validated against an allowlist. */
export function computeDigests(buffer, algorithms) {
  const allowed = ['md5', 'sha1', 'sha256', 'sha512'];
  const requested = Array.isArray(algorithms) && algorithms.length > 0 ? algorithms : ['md5', 'sha1', 'sha256', 'sha512'];
  const digests = {};
  for (const algo of requested) {
    if (!allowed.includes(algo)) {
      throw new Error(`不支持的哈希算法: ${String(algo)}。可用算法: ${allowed.join(', ')}。请修正 options.algorithms。`);
    }
    digests[algo] = binaryUtil.hashHex(buffer, algo);
  }
  return digests;
}

/** Build an ISO-like timestamp for components without a known timezone. */
export function epochFromParts(year, month, day, hour = 0, minute = 0, second = 0) {
  if (![year, month, day, hour, minute, second].every((n) => Number.isFinite(n))) return null;
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  if (!Number.isFinite(ms)) return null;
  const iso = `${String(year).padStart(4, '0')}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}T${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}:${String(second).padStart(2, '0')}`;
  return { iso, epochSeconds: Math.floor(ms / 1000), timezone: 'utc' };
}

/** EXIF date "YYYY:MM:DD HH:MM:SS" -> timestamp (EXIF has no timezone; treated as local-unassigned). */
export function parseExifDate(value) {
  if (typeof value !== 'string') return null;
  const m = /^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/.exec(value.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  const base = epochFromParts(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
  if (!base) return null;
  return { ...base, timezone: 'local-unassigned' };
}

/** PDF date "D:YYYYMMDDHHmmSS..." -> timestamp (with optional timezone offset if present). */
export function parsePdfDate(value) {
  if (typeof value !== 'string') return null;
  const m = /^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([Zz+\-])(\d{2})?'?(\d{2})?)?/.exec(value.trim());
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2] || '1');
  const day = Number(m[3] || '1');
  const hour = Number(m[4] || '0');
  const minute = Number(m[5] || '0');
  const second = Number(m[6] || '0');
  const base = epochFromParts(year, month, day, hour, minute, second);
  if (!base) return null;
  let epochSeconds = base.epochSeconds;
  if (m[7] === '+' || m[7] === '-') {
    const oh = Number(m[8] || '0');
    const om = Number(m[9] || '0');
    const offset = (oh * 60 + om) * 60;
    epochSeconds += m[7] === '+' ? -offset : offset;
  }
  const iso = new Date(epochSeconds * 1000).toISOString().replace('.000Z', 'Z');
  const zoneKnown = m[7] === 'Z' || m[7] === 'z' || m[7] === '+' || m[7] === '-';
  return { iso, epochSeconds, timezone: zoneKnown ? 'utc' : 'local-unassigned' };
}
