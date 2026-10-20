// ArmorBreak - android 域共享小工具（纯 node:*，无依赖）
// 所有输入均视为不可信数据：输出前剥离控制字符、限制长度。
import { createHash } from 'node:crypto';

/** 规范化整数上限参数（核心已校验 JSON Schema，这里再做防御）。 */
export function limitOf(value, def, min, max) {
  const n = Number.isInteger(value) ? value : def;
  return Math.min(max, Math.max(min, n));
}

/** 剥离控制字符（保留 \n \t），压缩空白，截断到 maxLen 字符。 */
export function sanitizeText(value, maxLen = 2000) {
  if (typeof value !== 'string') return '';
  let out = '';
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code === 9 || code === 10) out += ch;
    else if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) out += ' ';
    else out += ch;
  }
  out = out.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  if (out.length > maxLen) out = out.slice(0, maxLen) + '…';
  return out;
}

/** 数组截断并返回是否截断。 */
export function clip(value, max) {
  if (!Array.isArray(value)) return { items: [], truncated: false };
  if (value.length <= max) return { items: value, truncated: false };
  return { items: value.slice(0, max), truncated: true };
}

/** 转为十六进制字符串（最多 maxBytes 字节）。 */
export function hexOf(buf, maxBytes = 32) {
  if (!Buffer.isBuffer(buf)) return '';
  return buf.subarray(0, Math.min(buf.length, maxBytes)).toString('hex');
}

/** 人类可读字节数。 */
export function humanBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '未知';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** 短哈希用于摘要展示。 */
export function shortHash(buf) {
  return sha256Hex(buf).slice(0, 12);
}

/** 校验 params 对象；核心已按 schema 校验，此处仅防御 null/非 object。 */
export function optionsOf(input) {
  const o = input && typeof input === 'object' ? input.options : null;
  return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
}

/** 取读入的 buffer；空则抛出可操作错误。 */
export function requireBuffer(input, capabilityLabel) {
  const buf = input && Buffer.isBuffer(input.buffer) ? input.buffer : null;
  if (!buf || buf.length === 0) {
    throw new Error(
      `缺少可分析字节：capability ${capabilityLabel} 需要 targetPath 指向一个 APK/DEX 文件，且核心已读入 buffer。` +
        '请确认目标是非空文件、不是目录，或提高 limits.maxBytes 后重试。',
    );
  }
  return buf;
}

/** limits 兜底（核心若未传全）。 */
export function limitsOf(input) {
  const l = (input && input.limits) || {};
  return {
    maxBytes: Number.isFinite(l.maxBytes) && l.maxBytes > 0 ? l.maxBytes : 64 * 1024 * 1024,
    maxItems: Number.isFinite(l.maxItems) && l.maxItems > 0 ? l.maxItems : 200,
    maxStrings: Number.isFinite(l.maxStrings) && l.maxStrings > 0 ? l.maxStrings : 500,
    maxFindings: Number.isFinite(l.maxFindings) && l.maxFindings > 0 ? l.maxFindings : 100,
    timeoutMs: Number.isFinite(l.timeoutMs) && l.timeoutMs > 0 ? l.timeoutMs : 30000,
  };
}

/** 协作取消：长循环里调用，超时/中止时抛错。 */
export function checkAbort(input) {
  const signal = input && input.env ? input.env.signal : null;
  if (signal && signal.aborted) {
    const err = new Error('分析已被取消（AbortSignal 已触发）。');
    err.name = 'AbortError';
    throw err;
  }
}

/** 检查 data 体积是否接近契约 256KiB 上限；超限时给出截断提示（由调用方裁剪）。 */
export function dataSize(data) {
  try {
    return Buffer.byteLength(JSON.stringify(data), 'utf8');
  } catch {
    return Infinity;
  }
}

/**
 * 保证 data 序列化体积不超过契约上限（默认 256KiB）：
 * 反复把最大的数组对半裁剪，直到满足预算；裁剪过的 data 会带 dataBudget 标记。
 * 不修改调用方以外无关对象（data 本身会被原地裁剪）。
 */
export function enforceDataBudget(data, maxBytes = 256 * 1024) {
  if (dataSize(data) <= maxBytes) return data;
  const trimmedPaths = [];
  let guard = 0;
  while (guard++ < 200 && dataSize(data) > maxBytes) {
    const candidates = [];
    const walk = (node, path) => {
      if (!node || typeof node !== 'object') return;
      if (Array.isArray(node)) {
        if (node.length > 0) candidates.push({ node, path, size: dataSize(node) });
        return;
      }
      for (const key of Object.keys(node)) walk(node[key], path ? `${path}.${key}` : key);
    };
    walk(data, '');
    if (candidates.length === 0) break;
    candidates.sort((a, b) => b.size - a.size);
    const target = candidates[0];
    target.node.splice(Math.max(0, Math.floor(target.node.length / 2)));
    trimmedPaths.push(target.path || '(root)');
  }
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    data.dataBudget = {
      limitBytes: maxBytes,
      truncated: true,
      trimmedPaths: [...new Set(trimmedPaths)].slice(0, 20),
    };
  }
  return data;
}

/** Result 骨架。 */
export function makeResult({ summary, findings = [], evidence = [], data = {}, meta = {} }) {
  return {
    summary: sanitizeText(summary, 4000),
    findings: findings.slice(0, 100),
    evidence,
    data: enforceDataBudget(data),
    meta,
  };
}

/** 从 buffer 安全读 u16/u32（越界返回 null 而不是抛错，供宽松解析器用）。 */
export function u16(buf, off) {
  if (off < 0 || off + 2 > buf.length) return null;
  return buf.readUInt16LE(off);
}
export function u32(buf, off) {
  if (off < 0 || off + 4 > buf.length) return null;
  return buf.readUInt32LE(off);
}
export function u64(buf, off) {
  if (off < 0 || off + 8 > buf.length) return null;
  return Number(buf.readBigUInt64LE(off));
}

export function isPrintableAsciiByte(b) {
  return b >= 0x20 && b < 0x7f;
}

/** 判断是否像文本 XML（用于 manifest 的文本回退）。 */
export function looksLikeXml(buf) {
  for (let i = 0; i < Math.min(buf.length, 64); i++) {
    const b = buf[i];
    if (b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d || b === 0xef || b === 0xbb || b === 0xbf) continue;
    return b === 0x3c; // '<'
  }
  return false;
}
