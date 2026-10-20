/**
 * Binary domain — entropy analysis (overall, block map, per-section) and pack/encrypt hints.
 * Bounded: scans at most the provided buffer (core caps it) and caps block count.
 */
import { byteStats, entropyOf } from './util.js';

export function classifyEntropy(entropy) {
  if (!Number.isFinite(entropy)) return 'unknown';
  if (entropy >= 7.2) return 'very-high';
  if (entropy >= 6.5) return 'high';
  if (entropy >= 4.5) return 'normal';
  if (entropy >= 2.0) return 'low';
  return 'mostly-empty';
}

/**
 * @param {Buffer} buffer
 * @param {{blockSize?:number, maxBlocks?:number, sectionSizeCap?:number}} opts
 */
export function analyzeEntropy(buffer, opts = {}) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  const maxBlocks = Math.max(1, Math.min(5000, Math.floor(Number(opts.maxBlocks) || 256)));
  let blockSize = Math.max(256, Math.min(1024 * 1024, Math.floor(Number(opts.blockSize) || 4096)));
  if (buf.length > 0) {
    const needed = Math.ceil(buf.length / maxBlocks);
    if (needed > blockSize) blockSize = needed;
  }
  const overallEntropy = entropyOf(buf);
  const stats = byteStats(buf);
  const blocks = [];
  if (buf.length > 0) {
    for (let offset = 0; offset < buf.length && blocks.length < maxBlocks; offset += blockSize) {
      const slice = buf.subarray(offset, Math.min(buf.length, offset + blockSize));
      const h = entropyOf(slice, 1024 * 1024);
      blocks.push({
        offset,
        size: slice.length,
        entropy: Math.round(h * 1e4) / 1e4,
        classification: classifyEntropy(h),
      });
    }
  }
  const highBlocks = blocks.filter((b) => b.entropy >= 7.2);
  const zeroBlocks = blocks.filter((b) => b.entropy < 0.5);
  const hints = [];
  if (overallEntropy >= 7.2 && stats.printableRatio < 0.25) {
    hints.push({
      id: 'high-overall-entropy',
      severity: 'hypothesis',
      detail: `整体熵 ${overallEntropy.toFixed(4)} bits/byte 且可打印字符比例仅 ${(stats.printableRatio * 100).toFixed(1)}%，疑似压缩/加密数据或加壳节。`,
    });
  }
  if (blocks.length >= 4 && highBlocks.length / blocks.length >= 0.75) {
    hints.push({
      id: 'mostly-high-entropy-blocks',
      severity: 'hypothesis',
      detail: `${highBlocks.length}/${blocks.length} 个块熵 ≥ 7.2，分布均匀，倾向压缩/加密而非普通代码。`,
    });
  }
  if (stats.zeroByteRatio >= 0.5) {
    hints.push({
      id: 'mostly-zero-bytes',
      severity: 'observed',
      detail: `零字节占比 ${(stats.zeroByteRatio * 100).toFixed(1)}%，可能是填充、稀疏数据或未初始化区域。`,
    });
  }
  if (hints.length === 0) {
    hints.push({
      id: 'no-strong-entropy-signal',
      severity: 'observed',
      detail: `整体熵 ${overallEntropy.toFixed(4)} bits/byte（${classifyEntropy(overallEntropy)}），未出现强烈的压缩/加密信号。`,
    });
  }
  return {
    overall: {
      entropy: Math.round(overallEntropy * 1e4) / 1e4,
      classification: classifyEntropy(overallEntropy),
      analyzedBytes: buf.length,
      stats,
    },
    blockSize,
    blockCount: blocks.length,
    blocks,
    highEntropyBlockCount: highBlocks.length,
    zeroBlockCount: zeroBlocks.length,
    hints,
    likelyPackedOrEncrypted: overallEntropy >= 7.2 || (blocks.length >= 4 && highBlocks.length / blocks.length >= 0.75),
  };
}

/**
 * Entropy for a list of raw segments: [{name, offset, size, virtualAddress?, type?}].
 * Sections with no file bytes (offset null / size 0) are reported as no-data.
 */
export function segmentEntropies(buffer, segments, maxEntries = 128, sizeCap = 2 * 1024 * 1024) {
  const out = [];
  const list = Array.isArray(segments) ? segments.slice(0, maxEntries) : [];
  for (const seg of list) {
    const entry = {
      name: seg.name ?? null,
      offset: Number.isFinite(seg.offset) ? seg.offset : null,
      size: Number.isFinite(seg.sizeNumeric) ? seg.sizeNumeric : (Number.isFinite(seg.size) ? seg.size : null),
      virtualAddress: seg.virtualAddress ?? seg.addr ?? null,
      entropy: null,
      classification: 'no-data',
      analyzedBytes: 0,
    };
    if (entry.offset !== null && entry.size !== null && entry.size > 0 && entry.offset < buffer.length) {
      const available = Math.min(entry.size, buffer.length - entry.offset, sizeCap);
      if (available > 0) {
        const h = entropyOf(buffer.subarray(entry.offset, entry.offset + available), sizeCap);
        entry.entropy = Math.round(h * 1e4) / 1e4;
        entry.classification = classifyEntropy(h);
        entry.analyzedBytes = available;
        if (available < entry.size) entry.truncated = true;
      }
    }
    out.push(entry);
  }
  return out;
}

/** Generic per-section extraction helper for PE/ELF/Mach-O models. */
export function sectionsForEntropy(format, parsed) {
  if (!parsed || !parsed.ok) return [];
  if (format === 'pe') {
    return parsed.sections.map((s) => ({
      name: s.name,
      offset: s.rawPointer,
      sizeNumeric: s.rawSize,
      virtualAddress: s.virtualAddress ? `0x${s.virtualAddress.toString(16)}` : null,
      executable: s.executable,
      writable: s.writable,
    }));
  }
  if (format === 'elf') {
    return parsed.sections.map((s) => ({
      name: s.name,
      offset: s.offset,
      sizeNumeric: s.sizeNumeric,
      virtualAddress: s.addr,
      executable: Array.isArray(s.flagNames) && s.flagNames.includes('exec'),
      writable: Array.isArray(s.flagNames) && s.flagNames.includes('write'),
    }));
  }
  if (format === 'macho') {
    const image = parsed.fat ? (parsed.slices.find((s) => s.ok) || {}).image : parsed;
    if (!image || !Array.isArray(image.sections)) return [];
    return image.sections.map((s) => ({
      name: `${s.segment || ''}${s.segment ? '.' : ''}${s.name}`,
      offset: s.offset,
      sizeNumeric: s.sizeNumeric,
      virtualAddress: s.addr,
      executable: (s.flags & 0x80000000) !== 0 || (s.flags & 0x04) !== 0,
      writable: (s.flags & 0x02) !== 0,
    }));
  }
  return [];
}
