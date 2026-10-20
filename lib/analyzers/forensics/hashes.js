/**
 * Forensics — file hashing (md5/sha1/sha256/sha512) with size/type context and truncation honesty.
 */
import { computeDigests } from './util.js';
import { hashHex } from '../binary/util.js';
import { detectFileType } from './filetype.js';

const ALGO_ORDER = ['md5', 'sha1', 'sha256', 'sha512'];

/**
 * @param {Buffer} buffer
 * @param {{algorithms?:string[]}} options
 * @param {{fileSize?:number|null, truncated?:boolean|null}} trunc
 */
export function hashFile(buffer, options = {}, trunc = {}) {
  const requested = Array.isArray(options.algorithms) && options.algorithms.length > 0
    ? options.algorithms
    : ALGO_ORDER;
  for (const algo of requested) {
    if (!ALGO_ORDER.includes(algo)) {
      throw new Error(`不支持的哈希算法: ${String(algo)}。可用算法: ${ALGO_ORDER.join(', ')}。请修正 options.algorithms。`);
    }
  }
  const selected = ALGO_ORDER.filter((a) => requested.includes(a));
  const digests = computeDigests(buffer, selected);
  const typeInfo = detectFileType(buffer);
  return {
    size: buffer.length,
    fileSize: Number.isFinite(trunc.fileSize) ? trunc.fileSize : null,
    truncated: trunc.truncated === true ? true : trunc.truncated === false ? false : null,
    complete: trunc.truncated === true ? false : trunc.truncated === false ? true : null,
    analyzedBytes: buffer.length,
    algorithms: selected,
    digests,
    type: { type: typeInfo.type, category: typeInfo.category, mime: typeInfo.mime, confidence: typeInfo.confidence },
    fileTypeDetails: typeInfo.details,
    magicHex: buffer.subarray(0, 16).toString('hex'),
    note: trunc.truncated === true
      ? '哈希只覆盖已读入的字节（文件被 limits.maxBytes 截断），不是完整文件哈希。'
      : '哈希覆盖核心传入的全部字节。',
  };
}

/** Convenience: single digest without type detection (used by other capabilities for evidence). */
export function quickDigest(buffer, algo = 'sha256') {
  return hashHex(buffer, algo);
}

export function summarizeHash(result) {
  const lines = [`文件大小 ${result.size} 字节${result.truncated === true ? `（完整文件 ${result.fileSize} 字节，已截断）` : ''}。`];
  lines.push(`类型：${result.type.type}（${result.type.category}，${result.type.confidence}）。`);
  for (const algo of result.algorithms) lines.push(`${algo}: ${result.digests[algo]}`);
  return lines.join('\n');
}
