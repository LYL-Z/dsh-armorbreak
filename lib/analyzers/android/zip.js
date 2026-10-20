// ArmorBreak - APK/ZIP 容器解析（纯 node:*）
// 手工解析 EOCD / ZIP64 EOCD / 中央目录，支持 store 与 deflate 解压，强制尺寸上限。
// 不落盘、不解压全部条目：只按需读取指定条目。
import { inflateRawSync } from 'node:zlib';

const SIG_EOCD = 0x06054b50; // PK\x05\x06
const SIG_EOCD64 = 0x06064b50; // PK\x06\x06
const SIG_EOCD64_LOCATOR = 0x07064b50; // PK\x06\x07
const SIG_CENTRAL = 0x02014b50; // PK\x01\x02
const SIG_LOCAL = 0x04034b50; // PK\x03\x04

export const METHOD_STORE = 0;
export const METHOD_DEFLATE = 8;

const METHOD_NAMES = new Map([
  [0, 'store'],
  [1, 'shrink'],
  [6, 'implode'],
  [8, 'deflate'],
  [9, 'deflate64'],
  [12, 'bzip2'],
  [14, 'lzma'],
  [93, 'zstd'],
  [99, 'aes'],
]);

// zip64 哨兵值
const U16_MAX = 0xffff;
const U32_MAX = 0xffffffff;

/** ZIP 结构错误（消息面向模型：说明缺什么、为什么、怎么修）。 */
export class ZipError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'ZipError';
    this.detail = detail;
  }
}

/** 错误消息中引用的条目名：剥离控制字符并截断（条目名来自不可信文件）。 */
function safeEntryName(name, max = 200) {
  return String(name ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .slice(0, max);
}

function readU64(buffer, offset) {
  if (offset < 0 || offset + 8 > buffer.length) return null;
  const value = buffer.readBigUInt64LE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(value);
}

function decodeName(raw, flags) {
  if (flags & 0x800) return raw.toString('utf8');
  // 非 UTF-8 名称：APK 中几乎总是 ASCII；先尝试 utf8，失败回退 latin1。
  const utf8 = raw.toString('utf8');
  if (!utf8.includes('\uFFFD')) return utf8;
  return raw.toString('latin1');
}

/** 在文件尾部定位 EOCD。返回 {offset, commentLength} | null。 */
function locateEocd(buffer) {
  const min = Math.max(0, buffer.length - 22 - U16_MAX);
  for (let off = buffer.length - 22; off >= min; off--) {
    if (buffer.readUInt32LE(off) !== SIG_EOCD) continue;
    const commentLength = buffer.readUInt16LE(off + 20);
    if (off + 22 + commentLength !== buffer.length) continue; // 注释长度必须刚好到 EOF
    return { offset: off, commentLength };
  }
  return null;
}

/** 解析 ZIP64 扩展字段（按需读取各 8 字节字段）。 */
function parseZip64Extra(extra, need) {
  const out = {};
  let off = 0;
  while (off + 4 <= extra.length) {
    const id = extra.readUInt16LE(off);
    const len = extra.readUInt16LE(off + 2);
    off += 4;
    if (off + len > extra.length) break;
    if (id === 0x0001) {
      let p = off;
      const order = ['uncompressedSize', 'compressedSize', 'localHeaderOffset', 'diskStart'];
      for (const field of order) {
        if (!need.has(field)) continue;
        if (p + 8 > off + len) break;
        const v = extra.readBigUInt64LE(p);
        p += 8;
        out[field] = v > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(v);
      }
      return out;
    }
    off += len;
  }
  return out;
}

/**
 * 解析 ZIP 中央目录。
 * @param {Buffer} buffer
 * @param {{maxEntries?:number, maxBytes?:number}} opts
 * @returns {{entries:Array, comment:string, eocdOffset:number, centralDirOffset:number, centralDirSize:number, zip64:boolean, truncated:boolean, warnings:string[]}}
 */
export function parseZip(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new ZipError(
      'ZIP 解析失败：输入为空。需要一个非空 APK/ZIP 文件（以 PK\\x03\\x04 或 PK\\x05\\x06 开头）。',
    );
  }
  if (buffer.length < 22) {
    throw new ZipError(
      `ZIP 解析失败：文件仅 ${buffer.length} 字节，小于最小 ZIP 长度 22 字节（EOCD 头），不是有效 ZIP/APK。`,
    );
  }
  const maxEntries = Math.max(1, Math.min(opts.maxEntries ?? 20000, 200000));
  const maxBytes = Number.isFinite(opts.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : buffer.length;

  const eocd = locateEocd(buffer);
  if (!eocd) {
    throw new ZipError(
      'ZIP 解析失败：在文件尾部未找到 EOCD（PK\\x05\\x06）记录。文件可能被截断、不是 ZIP/APK，或被追加了额外数据。' +
        '请确认上传的是完整 .apk/.zip 文件；如经过截断采样，请提供完整文件。',
    );
  }
  const eocdOff = eocd.offset;
  let entryCount = buffer.readUInt16LE(eocdOff + 10);
  let centralDirSize = buffer.readUInt32LE(eocdOff + 12);
  let centralDirOffset = buffer.readUInt32LE(eocdOff + 16);
  const comment = buffer.subarray(eocdOff + 22, eocdOff + 22 + eocd.commentLength).toString('utf8');
  const warnings = [];
  let zip64 = false;

  // ZIP64：定位 locator，解析 EOCD64
  if (entryCount === U16_MAX || centralDirSize === U32_MAX || centralDirOffset === U32_MAX) {
    zip64 = true;
    const locatorOff = eocdOff - 20;
    if (locatorOff < 0 || buffer.readUInt32LE(locatorOff) !== SIG_EOCD64_LOCATOR) {
      throw new ZipError(
        'ZIP64 解析失败：中央目录使用了 ZIP64 哨兵值，但 EOCD 前缺少 ZIP64 EOCD locator（PK\\x06\\x07）。' +
          '文件可能损坏；请用完整 APK 重新上传，或先 `unzip -t` 校验。',
      );
    }
    const eocd64Offset = readU64(buffer, locatorOff + 8);
    if (eocd64Offset === null || eocd64Offset + 56 > buffer.length) {
      throw new ZipError('ZIP64 解析失败：ZIP64 EOCD 偏移越界（文件截断或头部损坏）。');
    }
    if (buffer.readUInt32LE(eocd64Offset) !== SIG_EOCD64) {
      throw new ZipError('ZIP64 解析失败：ZIP64 EOCD 记录签名错误，文件损坏。');
    }
    const entries64 = readU64(buffer, eocd64Offset + 32);
    const cdSize64 = readU64(buffer, eocd64Offset + 40);
    const cdOff64 = readU64(buffer, eocd64Offset + 48);
    if (entries64 === null || cdSize64 === null || cdOff64 === null) {
      throw new ZipError('ZIP64 解析失败：ZIP64 EOCD 字段超出可解析范围。');
    }
    entryCount = entries64;
    centralDirSize = cdSize64;
    centralDirOffset = cdOff64;
  }

  if (centralDirOffset + centralDirSize > buffer.length) {
    throw new ZipError(
      `ZIP 解析失败：中央目录区间 [${centralDirOffset}, ${centralDirOffset + centralDirSize}) 超出文件长度 ${buffer.length}。` +
        '文件被截断或 EOCD 偏移被篡改；请提供完整文件。',
    );
  }

  const effectiveMax = Math.min(entryCount, maxEntries);
  const entries = [];
  let off = centralDirOffset;
  let truncated = false;
  for (let i = 0; i < effectiveMax; i++) {
    if (off + 46 > buffer.length) {
      truncated = true;
      warnings.push(`中央目录在第 ${i} 项处越界，已停止解析。`);
      break;
    }
    if (buffer.readUInt32LE(off) !== SIG_CENTRAL) {
      throw new ZipError(
        `ZIP 解析失败：第 ${i} 个中央目录项签名错误（偏移 ${off}）。中央目录已损坏或被加密工具重写。`,
      );
    }
    const flags = buffer.readUInt16LE(off + 8);
    const method = buffer.readUInt16LE(off + 10);
    const crc = buffer.readUInt32LE(off + 16);
    let compressedSize = buffer.readUInt32LE(off + 20);
    let uncompressedSize = buffer.readUInt32LE(off + 24);
    const nameLen = buffer.readUInt16LE(off + 28);
    const extraLen = buffer.readUInt16LE(off + 30);
    const entryCommentLen = buffer.readUInt16LE(off + 32);
    let localHeaderOffset = buffer.readUInt32LE(off + 42);
    const recordEnd = off + 46 + nameLen + extraLen + entryCommentLen;
    if (recordEnd > buffer.length) {
      throw new ZipError(
        `ZIP 解析失败：第 ${i} 个中央目录项内容越界（偏移 ${off}），文件截断。`,
      );
    }
    const rawName = buffer.subarray(off + 46, off + 46 + nameLen);
    const extra = buffer.subarray(off + 46 + nameLen, off + 46 + nameLen + extraLen);
    const name = decodeName(rawName, flags);

    const need = new Set();
    // 注意 ZIP64 extra 的字段顺序固定；仅当对应普通字段为哨兵值时才存在。
    if (uncompressedSize === U32_MAX) need.add('uncompressedSize');
    if (compressedSize === U32_MAX) need.add('compressedSize');
    if (localHeaderOffset === U32_MAX) need.add('localHeaderOffset');
    if (need.size > 0) {
      const z64 = parseZip64Extra(extra, need);
      if (z64.uncompressedSize !== undefined) uncompressedSize = z64.uncompressedSize;
      if (z64.compressedSize !== undefined) compressedSize = z64.compressedSize;
      if (z64.localHeaderOffset !== undefined) localHeaderOffset = z64.localHeaderOffset;
    }

    entries.push({
      index: i,
      name,
      flags,
      encrypted: (flags & 0x1) !== 0,
      dataDescriptor: (flags & 0x8) !== 0,
      method,
      methodName: METHOD_NAMES.get(method) ?? `method-${method}`,
      crc32: crc,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
    });
    off = recordEnd;
    // 防御：连续解析过多 / 记录尺寸异常时不无限循环
    if (off > buffer.length) {
      truncated = true;
      warnings.push('中央目录记录越界，已停止解析。');
      break;
    }
  }
  if (entryCount > effectiveMax) {
    truncated = true;
    warnings.push(`中央目录声明 ${entryCount} 项，按 maxEntries=${maxEntries} 截断。`);
  }
  if (effectiveMax < entryCount) truncated = true;

  return {
    entries,
    comment,
    eocdOffset: eocdOff,
    centralDirOffset,
    centralDirSize,
    declaredEntryCount: entryCount,
    zip64,
    truncated,
    warnings,
    maxBytes,
  };
}

/**
 * 读取并解压单个条目（受 maxOutputBytes 上限保护）。
 * @param {Buffer} buffer
 * @param {object} entry parseZip 产出的条目
 * @param {{maxBytes?:number, verifyCrc?:boolean}} opts
 * @returns {Buffer}
 */
export function readEntryData(buffer, entry, opts = {}) {
  if (!entry || typeof entry.localHeaderOffset !== 'number') {
    throw new ZipError('ZIP 条目读取失败：缺少中央目录条目信息。');
  }
  const maxOutput = Number.isFinite(opts.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : 32 * 1024 * 1024;
  const local = entry.localHeaderOffset;
  if (local < 0 || local + 30 > buffer.length) {
    throw new ZipError(
      `ZIP 条目读取失败：条目 "${safeEntryName(entry.name)}" 的本地头偏移 ${local} 越界（文件截断或偏移损坏）。`,
    );
  }
  if (buffer.readUInt32LE(local) !== SIG_LOCAL) {
    throw new ZipError(
      `ZIP 条目读取失败：条目 "${safeEntryName(entry.name)}" 本地头签名错误（偏移 ${local}），文件损坏或被加密。`,
    );
  }
  const nameLen = buffer.readUInt16LE(local + 26);
  const extraLen = buffer.readUInt16LE(local + 28);
  const dataStart = local + 30 + nameLen + extraLen;
  const dataEnd = dataStart + entry.compressedSize;
  if (dataStart > buffer.length || dataEnd > buffer.length) {
    throw new ZipError(
      `ZIP 条目读取失败：条目 "${safeEntryName(entry.name)}" 数据区间 [${dataStart}, ${dataEnd}) 超出文件长度 ${buffer.length}。` +
        '文件被截断；请提供完整 APK。',
    );
  }
  const compressed = buffer.subarray(dataStart, dataEnd);
  if (entry.encrypted) {
    throw new ZipError(
      `ZIP 条目 "${safeEntryName(entry.name)}" 被传统加密（flag bit0）。离线解析器不解密；请提供未加密 APK 或先用 apktool/zip 解密。`,
    );
  }
  if (entry.method === METHOD_STORE) {
    if (compressed.length > maxOutput) {
      throw new ZipError(
        `ZIP 条目 "${safeEntryName(entry.name)}" 解压后 ${compressed.length} 字节，超过上限 ${maxOutput} 字节。请提高 maxBytes 或仅分析元数据。`,
      );
    }
    return Buffer.from(compressed);
  }
  if (entry.method === METHOD_DEFLATE) {
    const declared = Number.isFinite(entry.uncompressedSize) ? entry.uncompressedSize : 0;
    const cap = Math.min(
      Math.max(declared, 1) + 1, // 允许声明值为 0 的畸形条目，但输出仍受上限约束
      maxOutput,
    );
    try {
      return inflateRawSync(compressed, { maxOutputLength: cap });
    } catch (err) {
      const code = err && err.code ? String(err.code) : 'UNKNOWN';
      if (code === 'ERR_BUFFER_TOO_LARGE' || /too large/i.test(String(err && err.message))) {
        throw new ZipError(
          `ZIP 条目 "${safeEntryName(entry.name)}" 解压输出超过上限 ${cap} 字节（压缩炸弹防护触发）。` +
            '请仅分析元数据或提高 maxBytes。',
        );
      }
      throw new ZipError(
        `ZIP 条目 "${safeEntryName(entry.name)}" deflate 解压失败（${code}）：压缩数据损坏或被截断。请重新获取完整 APK。`,
      );
    }
  }
  throw new ZipError(
    `ZIP 条目 "${safeEntryName(entry.name)}" 使用了不支持的压缩方法 ${entry.method}（${entry.methodName}）。` +
      '离线解析仅支持 store(0)/deflate(8)；请用 `zip -r` 重新打包为 deflate，或提供标准 Android 构建产物。',
  );
}

/** CRC32（IEEE 802.3，多项式 0xEDB88320），用于校验解压结果。 */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** 解压并校验 CRC；返回 {data, crcOk}。crcOk=false 不应静默通过，由调用方写入 warnings。 */
export function extractEntry(buffer, entry, opts = {}) {
  const data = readEntryData(buffer, entry, opts);
  const actual = crc32(data);
  return { data, crcOk: actual === (entry.crc32 >>> 0), actualCrc32: actual };
}

export function findEntry(zip, name) {
  return zip.entries.find((e) => e.name === name) || null;
}

export function findEntries(zip, predicate) {
  return zip.entries.filter(predicate);
}

/** APK 只按后缀识别；isApk 的判定在 manifest.js（需要 AndroidManifest.xml）。 */
export function topLevelNames(zip) {
  return [...new Set(zip.entries.map((e) => (e.name.includes('/') ? e.name.split('/')[0] : e.name)))].sort();
}
