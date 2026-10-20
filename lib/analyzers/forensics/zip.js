/**
 * Forensics — bounded ZIP central-directory parser (used for filetype/metadata/timeline).
 * Supports EOCD, basic ZIP64, central-directory entries and common extra timestamps.
 * Never decompresses entry data (bounded, no zip bombs).
 */
import { formatDosDateTime, formatUnixTime, readU16, readU32, readBigU64, sanitizeText } from '../binary/util.js';

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;

function decodeEntryName(buffer, start, length, flags) {
  if (start + length > buffer.length) return null;
  const raw = buffer.subarray(start, start + length);
  const utf8 = (flags & 0x0800) !== 0;
  let name;
  try {
    name = raw.toString(utf8 ? 'utf8' : 'latin1');
  } catch {
    name = raw.toString('latin1');
  }
  return sanitizeText(name.replace(/\\/g, '/'), 400);
}

function parseExtraFields(buffer, start, length, out) {
  let off = start;
  const end = Math.min(buffer.length, start + length);
  let guard = 0;
  while (off + 4 <= end && guard < 32) {
    guard += 1;
    const id = readU16(buffer, off, true);
    const size = readU16(buffer, off + 2, true);
    if (id === null || size === null) break;
    const dataOff = off + 4;
    const dataEnd = dataOff + size;
    if (dataEnd > end) break;
    if (id === 0x5455 && size >= 5) {
      // extended timestamp: flags, then mtime/atime/ctime (u32 LE, optional)
      const flags = buffer[dataOff];
      let pos = dataOff + 1;
      const readTs = () => {
        if (pos + 4 > dataEnd) return null;
        const v = readU32(buffer, pos, true);
        pos += 4;
        return v;
      };
      const times = {};
      if (flags & 0x01) { const v = readTs(); if (v !== null) times.mtime = v; }
      if (flags & 0x02) { const v = readTs(); if (v !== null) times.atime = v; }
      if (flags & 0x04) { const v = readTs(); if (v !== null) times.ctime = v; }
      out.extraTimestamps = times;
    } else if (id === 0x0001) {
      // ZIP64 extended info (order: uncompressed, compressed, local header offset, disk start)
      let pos = dataOff;
      const take = () => {
        const v = readBigU64(buffer, pos, true);
        pos += 8;
        return v;
      };
      if (out.__needZip64Uncomp && pos + 8 <= dataEnd) out.uncompressedSize = Number(take());
      if (out.__needZip64Comp && pos + 8 <= dataEnd) out.compressedSize = Number(take());
      if (out.__needZip64Offset && pos + 8 <= dataEnd) out.localHeaderOffset = Number(take());
    } else if (id === 0x000a && size >= 32) {
      // NTFS timestamps: 4 reserved + 3 x FILETIME (100ns since 1601)
      const filetime = (p) => {
        const lo = readU32(buffer, p, true);
        const hi = readU32(buffer, p + 4, true);
        if (lo === null || hi === null) return null;
        const ticks = (BigInt(hi) << 32n) | BigInt(lo);
        const unix = ticks / 10000000n - 11644473600n;
        return unix > 0n && unix < 4102444800n ? Number(unix) : null;
      };
      const m = filetime(dataOff + 4);
      if (m !== null) {
        out.extraTimestamps = { ...(out.extraTimestamps || {}), mtime: m };
      }
    }
    off = dataOff + size;
  }
}

/**
 * Parse a ZIP archive's central directory without extracting entries.
 * @returns {{ok:boolean, warnings:string[], entries:Array, declaredEntryCount:number|null,
 *   parsedEntryCount:number, comment:string|null, eocdOffset:number|null, zip64:boolean, truncated:boolean, scannedLocally:boolean}}
 */
export function parseZip(buffer, opts = {}) {
  const maxEntries = Math.max(1, Math.min(5000, Math.floor(Number(opts.maxEntries) || 200)));
  const result = {
    ok: false,
    warnings: [],
    entries: [],
    declaredEntryCount: null,
    parsedEntryCount: 0,
    comment: null,
    eocdOffset: null,
    zip64: false,
    truncated: false,
    scannedLocally: false,
  };
  if (!Buffer.isBuffer(buffer) || buffer.length < 22) {
    result.warnings.push('文件小于 22 字节，不是有效 ZIP（EOCD 至少 22 字节）。');
    return result;
  }
  const searchStart = Math.max(0, buffer.length - 65557);
  let eocd = -1;
  for (let i = buffer.length - 22; i >= searchStart; i -= 1) {
    if (buffer.readUInt32LE(i) === SIG_EOCD) {
      const commentLen = buffer.readUInt16LE(i + 20);
      if (i + 22 + commentLen <= buffer.length) { eocd = i; break; }
    }
  }
  if (eocd === -1) {
    result.warnings.push('未找到 EOCD（ZIP 目录尾），文件可能被截断；改用本地文件头顺序扫描。');
    return parseLocalHeaders(buffer, result, maxEntries);
  }
  result.eocdOffset = eocd;
  const entriesThisDisk = readU16(buffer, eocd + 8);
  const totalEntries = readU16(buffer, eocd + 10);
  let cdSize = readU32(buffer, eocd + 12);
  let cdOffset = readU32(buffer, eocd + 16);
  const commentLen = readU16(buffer, eocd + 20);
  if (commentLen !== null && commentLen > 0 && eocd + 22 + commentLen <= buffer.length) {
    result.comment = sanitizeText(buffer.subarray(eocd + 22, eocd + 22 + commentLen).toString('latin1'), 500);
  }
  if (totalEntries === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) {
    // ZIP64: locate ZIP64 EOCD via locator immediately before EOCD.
    if (eocd >= 20 && readU32(buffer, eocd - 20) === SIG_ZIP64_LOCATOR) {
      const z64Off = readBigU64(buffer, eocd - 20 + 8);
      if (z64Off !== null && z64Off <= BigInt(buffer.length - 56)) {
        const off = Number(z64Off);
        if (readU32(buffer, off) === SIG_ZIP64_EOCD) {
          result.zip64 = true;
          const total = readBigU64(buffer, off + 32);
          const size = readBigU64(buffer, off + 40);
          const offset = readBigU64(buffer, off + 48);
          if (total !== null && total <= BigInt(Number.MAX_SAFE_INTEGER)) result.declaredEntryCount = Number(total);
          if (size !== null && size <= BigInt(Number.MAX_SAFE_INTEGER)) cdSize = Number(size);
          if (offset !== null && offset <= BigInt(Number.MAX_SAFE_INTEGER)) cdOffset = Number(offset);
        }
      }
    }
    if (!result.zip64) result.warnings.push('ZIP 声明 ZIP64 但未找到有效 ZIP64 EOCD，按 32 位字段尽力解析。');
  }
  if (result.declaredEntryCount === null) result.declaredEntryCount = totalEntries;
  if (entriesThisDisk !== null && totalEntries !== null && entriesThisDisk !== totalEntries && !result.zip64) {
    result.warnings.push(`ZIP 分卷归档（本盘 ${entriesThisDisk}/${totalEntries} 项），仅解析当前可见目录。`);
  }
  if (cdOffset === null || cdSize === null || cdOffset >= buffer.length) {
    result.warnings.push('中央目录偏移超出文件范围（文件可能被截断），改用本地文件头顺序扫描。');
    return parseLocalHeaders(buffer, result, maxEntries);
  }
  const cdEnd = Math.min(buffer.length, cdOffset + cdSize);
  if (cdOffset + cdSize > buffer.length) {
    result.truncated = true;
    result.warnings.push('中央目录被文件末尾截断，仅解析可读取条目。');
  }
  let off = cdOffset;
  const limit = Math.min(result.declaredEntryCount || 0, maxEntries);
  for (let i = 0; i < limit; i += 1) {
    if (off + 46 > cdEnd) { result.truncated = true; break; }
    if (readU32(buffer, off) !== SIG_CENTRAL) {
      result.warnings.push(`中央目录第 ${i} 条签名异常（0x${(readU32(buffer, off) >>> 0).toString(16)}），停止解析。`);
      result.truncated = true;
      break;
    }
    const flags = readU16(buffer, off + 8);
    const method = readU16(buffer, off + 10);
    const dosTime = readU16(buffer, off + 12);
    const dosDate = readU16(buffer, off + 14);
    const crc32 = readU32(buffer, off + 16);
    let compressedSize = readU32(buffer, off + 20);
    let uncompressedSize = readU32(buffer, off + 24);
    const nameLen = readU16(buffer, off + 28);
    const extraLen = readU16(buffer, off + 30);
    const entryCommentLen = readU16(buffer, off + 32);
    let localHeaderOffset = readU32(buffer, off + 42);
    if (nameLen === null || extraLen === null) break;
    const name = decodeEntryName(buffer, off + 46, nameLen, flags || 0);
    const extraStart = off + 46 + nameLen;
    const record = {
      index: i,
      name: name || `<unnamed-${i}>`,
      flags: flags || 0,
      method,
      methodName: method === 0 ? 'stored' : method === 8 ? 'deflate' : method === 12 ? 'bzip2' : method === 14 ? 'lzma' : method === 93 ? 'zstd' : `method-${method}`,
      crc32: crc32 === null ? null : `0x${(crc32 >>> 0).toString(16).padStart(8, '0')}`,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      dosTime,
      dosDate,
      isDirectory: Boolean(name && name.endsWith('/')),
      encrypted: Boolean((flags || 0) & 0x01),
      timestamp: formatDosDateTime(dosDate, dosTime),
      extraTimestamps: null,
    };
    // ZIP64 marker fields inside the 32-bit slots (0xffffffff) are resolved via extra field id 0x0001.
    record.__needZip64Uncomp = uncompressedSize === 0xffffffff;
    record.__needZip64Comp = compressedSize === 0xffffffff;
    record.__needZip64Offset = localHeaderOffset === 0xffffffff;
    if (extraLen > 0) parseExtraFields(buffer, extraStart, extraLen, record);
    delete record.__needZip64Uncomp;
    delete record.__needZip64Comp;
    delete record.__needZip64Offset;
    if (record.extraTimestamps) {
      const ts = record.extraTimestamps;
      record.timestamp = record.timestamp || {};
      if (Number.isFinite(ts.mtime)) {
        const iso = formatUnixTime(ts.mtime);
        if (iso) record.timestamp = { ...(record.timestamp || {}), iso, epochSeconds: ts.mtime, timezone: 'utc', source: 'extended-timestamp' };
      }
      record.extraTimes = {
        mtime: Number.isFinite(ts.mtime) ? formatUnixTime(ts.mtime) : null,
        atime: Number.isFinite(ts.atime) ? formatUnixTime(ts.atime) : null,
        ctime: Number.isFinite(ts.ctime) ? formatUnixTime(ts.ctime) : null,
      };
    }
    result.entries.push(record);
    result.parsedEntryCount += 1;
    off = extraStart + extraLen + (entryCommentLen || 0);
  }
  if ((result.declaredEntryCount || 0) > limit) {
    result.truncated = true;
    result.warnings.push(`中央目录声明 ${result.declaredEntryCount} 项，超过 maxEntries=${maxEntries}，已截断。`);
  }
  result.ok = result.entries.length > 0 || result.declaredEntryCount === 0;
  return result;
}

function parseLocalHeaders(buffer, result, maxEntries) {
  result.scannedLocally = true;
  let off = 0;
  let guard = 0;
  while (off + 30 <= buffer.length && result.entries.length < maxEntries && guard < 10000) {
    guard += 1;
    if (readU32(buffer, off) !== SIG_LOCAL) {
      const next = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), off + 1);
      if (next === -1) break;
      off = next;
      continue;
    }
    const flags = readU16(buffer, off + 6) || 0;
    const method = readU16(buffer, off + 8);
    const dosTime = readU16(buffer, off + 10);
    const dosDate = readU16(buffer, off + 12);
    const compressedSize = readU32(buffer, off + 18);
    const uncompressedSize = readU32(buffer, off + 22);
    const nameLen = readU16(buffer, off + 26);
    const extraLen = readU16(buffer, off + 28);
    if (nameLen === null || extraLen === null) break;
    const name = decodeEntryName(buffer, off + 30, nameLen, flags);
    result.entries.push({
      index: result.entries.length,
      name: name || `<unnamed-${result.entries.length}>`,
      flags,
      method,
      methodName: method === 0 ? 'stored' : method === 8 ? 'deflate' : `method-${method}`,
      crc32: null,
      compressedSize,
      uncompressedSize,
      localHeaderOffset: off,
      isDirectory: Boolean(name && name.endsWith('/')),
      encrypted: Boolean(flags & 0x01),
      timestamp: formatDosDateTime(dosDate, dosTime),
      extraTimestamps: null,
      fromLocalHeader: true,
    });
    result.parsedEntryCount += 1;
    const next = off + 30 + nameLen + extraLen + (compressedSize || 0);
    if (next <= off) break;
    off = next;
  }
  if (result.entries.length > 0) {
    result.ok = true;
    result.truncated = true;
    result.warnings.push(`通过本地文件头恢复 ${result.entries.length} 个条目（无中央目录，时间戳/大小为本地头口径）。`);
  }
  return result;
}

/** Quick entry-name list for filetype heuristics (bounded). */
export function zipEntryNames(buffer, maxEntries = 64) {
  const parsed = parseZip(buffer, { maxEntries });
  return parsed.entries.map((e) => e.name);
}

/** Top-level directory prefixes (helps OOXML/APK/JAR detection). */
export function zipTopLevelPrefixes(entryNames) {
  const set = new Set();
  for (const name of entryNames) {
    const idx = name.indexOf('/');
    set.add(idx === -1 ? name : `${name.slice(0, idx)}/`);
  }
  return [...set].sort();
}

export const SIGNATURES = Object.freeze({
  EOCD: SIG_EOCD,
  CENTRAL: SIG_CENTRAL,
  LOCAL: SIG_LOCAL,
  ZIP64_EOCD: SIG_ZIP64_EOCD,
  ZIP64_LOCATOR: SIG_ZIP64_LOCATOR,
});
