/**
 * Forensics — bounded parsers for non-executable container formats: PNG, JPEG/EXIF,
 * gzip, OLE2/CFB (legacy Office), PDF. No decompression of embedded payloads.
 */
import { parseExifDate, parsePdfDate } from './util.js';
import { readAsciiZ, readU16, readU32, sanitizeText } from '../binary/util.js';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const PNG_COLOR_TYPES = new Map([
  [0, 'grayscale'], [2, 'truecolor'], [3, 'indexed'], [4, 'grayscale-alpha'], [6, 'truecolor-alpha'],
]);

/** Parse PNG chunk structure, IHDR, tEXt/iTXt/zTXt keywords and tIME. */
export function parsePng(buffer, opts = {}) {
  const maxChunks = Math.max(1, Math.min(1024, Number(opts.maxChunks) || 256));
  const result = {
    ok: false,
    width: null,
    height: null,
    bitDepth: null,
    colorType: null,
    colorTypeName: null,
    interlace: null,
    chunks: [],
    text: {},
    time: null,
    notes: ['PNG 数据块 CRC 未逐一校验（只读结构解析）。'],
    truncated: false,
  };
  if (!Buffer.isBuffer(buffer) || buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_SIGNATURE)) {
    result.notes.push('不是 PNG（签名不匹配）。');
    return result;
  }
  result.ok = true;
  let off = 8;
  let guard = 0;
  while (off + 12 <= buffer.length && guard < maxChunks) {
    guard += 1;
    const length = readU32(buffer, off, false);
    if (length === null) break;
    const type = buffer.subarray(off + 4, off + 8).toString('latin1');
    const dataStart = off + 8;
    const dataEnd = dataStart + length;
    const crcEnd = dataEnd + 4;
    if (length > buffer.length || crcEnd > buffer.length) {
      result.truncated = true;
      result.chunks.push({ type, length, offset: off, truncated: true });
      break;
    }
    result.chunks.push({ type, length, offset: off });
    if (type === 'IHDR' && length >= 13) {
      result.width = readU32(buffer, dataStart, false);
      result.height = readU32(buffer, dataStart + 4, false);
      result.bitDepth = buffer[dataStart + 8];
      result.colorType = buffer[dataStart + 9];
      result.colorTypeName = PNG_COLOR_TYPES.get(result.colorType) || `color-${result.colorType}`;
      result.interlace = buffer[dataStart + 12];
    } else if (type === 'tEXt') {
      const chunk = buffer.subarray(dataStart, dataEnd);
      const nul = chunk.indexOf(0);
      if (nul > 0) {
        const key = sanitizeText(chunk.subarray(0, nul).toString('latin1'), 80);
        const value = sanitizeText(chunk.subarray(nul + 1).toString('latin1'), 1000);
        if (Object.keys(result.text).length < 32) result.text[key] = value;
      }
    } else if (type === 'iTXt' && length > 4) {
      const chunk = buffer.subarray(dataStart, dataEnd);
      const nul = chunk.indexOf(0);
      if (nul > 0 && Object.keys(result.text).length < 32) {
        const key = sanitizeText(chunk.subarray(0, nul).toString('latin1'), 80);
        // iTXt: keyword\0 compressionFlag(1) compressionMethod(1) language\0 translated\0 text
        let pos = nul + 3;
        const langNul = chunk.indexOf(0, pos);
        if (langNul !== -1) {
          pos = langNul + 1;
          const translNul = chunk.indexOf(0, pos);
          if (translNul !== -1) {
            pos = translNul + 1;
            result.text[key] = sanitizeText(chunk.subarray(pos).toString('utf8'), 1000);
          }
        }
      }
    } else if (type === 'tIME' && length >= 7) {
      const year = readU16(buffer, dataStart, false);
      const month = buffer[dataStart + 2];
      const day = buffer[dataStart + 3];
      const hour = buffer[dataStart + 4];
      const minute = buffer[dataStart + 5];
      const second = buffer[dataStart + 6];
      if (month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 && second <= 60) {
        const epochSeconds = Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
        result.time = {
          iso: new Date(epochSeconds * 1000).toISOString().replace('.000Z', 'Z'),
          epochSeconds,
          timezone: 'utc',
          raw: { year, month, day, hour, minute, second },
          field: 'tIME',
        };
      }
    }
    if (type === 'IEND') break;
    off = crcEnd;
  }
  if (off < buffer.length && !result.chunks.some((c) => c.type === 'IEND')) {
    result.notes.push('未发现 IEND，文件可能不完整。');
  }
  return result;
}

/**
 * Parse JPEG markers and EXIF (TIFF IFD0 + Exif sub-IFD) for metadata/timeline.
 * Stops at SOS (start of scan) to avoid walking entropy-coded data.
 */
export function parseJpeg(buffer, opts = {}) {
  const maxSegments = Math.max(1, Math.min(512, Number(opts.maxSegments) || 128));
  const result = {
    ok: false,
    width: null,
    height: null,
    components: null,
    exif: null,
    segments: [],
    hasExif: false,
    notes: [],
    truncated: false,
  };
  if (!Buffer.isBuffer(buffer) || buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) {
    result.notes.push('不是 JPEG（缺少 SOI 标记 FFD8）。');
    return result;
  }
  result.ok = true;
  let off = 2;
  let guard = 0;
  while (off + 4 <= buffer.length && guard < maxSegments) {
    guard += 1;
    if (buffer[off] !== 0xff) {
      result.notes.push(`偏移 ${off} 处缺少 JPEG 标记前缀 0xFF，停止解析。`);
      result.truncated = true;
      break;
    }
    let marker = buffer[off + 1];
    let markerOff = off;
    while (marker === 0xff && off + 2 < buffer.length) { off += 1; marker = buffer[off + 1]; markerOff = off; }
    if (marker === 0xd9) { result.segments.push({ marker: 'EOI', offset: markerOff }); break; }
    if (marker === 0xda) { result.segments.push({ marker: 'SOS', offset: markerOff }); break; }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { off += 2; continue; }
    const length = readU16(buffer, markerOff + 2, false);
    if (length === null || length < 2) { result.truncated = true; break; }
    const dataStart = markerOff + 4;
    const dataEnd = markerOff + 2 + length;
    if (dataEnd > buffer.length) {
      result.truncated = true;
      result.notes.push(`JPEG 段 ${segmentName(marker)} 被文件末尾截断。`);
      break;
    }
    result.segments.push({ marker: segmentName(marker), code: `0x${marker.toString(16).padStart(2, '0')}`, offset: markerOff, length });
    if (isSof(marker) && length >= 8) {
      result.height = readU16(buffer, dataStart + 1, false);
      result.width = readU16(buffer, dataStart + 3, false);
      result.components = buffer[dataStart + 5];
    } else if (marker === 0xe1) {
      const app1 = buffer.subarray(dataStart, dataEnd);
      if (app1.length > 6 && app1.subarray(0, 6).equals(Buffer.from('Exif\u0000\u0000', 'latin1'))) {
        const exif = parseExifTiff(buffer, dataStart + 6, dataEnd);
        if (exif) {
          result.exif = exif;
          result.hasExif = true;
        } else {
          result.notes.push('APP1 含 EXIF 标识但 TIFF 结构无法解析。');
        }
      }
    }
    off = dataEnd;
  }
  return result;
}

function isSof(marker) {
  return (marker >= 0xc0 && marker <= 0xc3) || (marker >= 0xc5 && marker <= 0xc7) || (marker >= 0xc9 && marker <= 0xcb) || (marker >= 0xcd && marker <= 0xcf);
}

function segmentName(marker) {
  const map = {
    0xe0: 'APP0', 0xe1: 'APP1', 0xe2: 'APP2', 0xe3: 'APP3', 0xdb: 'DQT', 0xc0: 'SOF0',
    0xc2: 'SOF2', 0xc4: 'DHT', 0xdd: 'DRI', 0xda: 'SOS', 0xd9: 'EOI', 0xfe: 'COM',
  };
  return map[marker] || `0x${marker.toString(16).padStart(2, '0')}`;
}

const EXIF_TAGS = new Map([
  [0x0100, 'ImageWidth'], [0x0101, 'ImageLength'], [0x010f, 'Make'], [0x0110, 'Model'],
  [0x0112, 'Orientation'], [0x011a, 'XResolution'], [0x011b, 'YResolution'],
  [0x0131, 'Software'], [0x0132, 'DateTime'], [0x013b, 'Artist'],
  [0x8298, 'Copyright'], [0x8769, 'ExifIFDPointer'],
  [0x829a, 'ExposureTime'], [0x829d, 'FNumber'], [0x8827, 'ISOSpeedRatings'],
  [0x9003, 'DateTimeOriginal'], [0x9004, 'DateTimeDigitized'], [0x9201, 'ShutterSpeedValue'],
  [0x9202, 'ApertureValue'], [0x9209, 'Flash'], [0x9286, 'UserComment'],
  [0xa002, 'PixelXDimension'], [0xa003, 'PixelYDimension'], [0xa405, 'FocalLengthIn35mmFilm'],
  [0xa434, 'LensModel'],
]);

function parseExifTiff(buffer, tiffStart, limit) {
  if (tiffStart + 8 > limit) return null;
  const order = buffer.subarray(tiffStart, tiffStart + 2).toString('latin1');
  const little = order === 'II';
  if (!little && order !== 'MM') return null;
  const magic = readU16(buffer, tiffStart + 2, little);
  if (magic !== 42) return null;
  const ifd0Offset = readU32(buffer, tiffStart + 4, little);
  if (ifd0Offset === null) return null;
  const ifd0 = readIfd(buffer, tiffStart, tiffStart + ifd0Offset, limit, little);
  if (!ifd0) return null;
  const exifPointer = ifd0.tags.get(0x8769);
  let exifIfd = null;
  if (exifPointer && Number.isFinite(exifPointer.numeric)) {
    exifIfd = readIfd(buffer, tiffStart, tiffStart + exifPointer.numeric, limit, little);
  }
  const fields = {};
  const merged = new Map();
  if (ifd0) for (const [tag, info] of ifd0.tags) merged.set(tag, info.value);
  if (exifIfd) for (const [tag, info] of exifIfd.tags) merged.set(tag, info.value);
  for (const [tag, value] of merged) {
    const name = EXIF_TAGS.get(tag);
    if (name) fields[name] = value;
  }
  return {
    byteOrder: little ? 'little' : 'big',
    ifd0EntryCount: ifd0.count,
    exifIfdEntryCount: exifIfd ? exifIfd.count : 0,
    fields,
  };
}

function readIfd(buffer, tiffStart, ifdOffset, limit, little) {
  if (ifdOffset + 2 > limit || ifdOffset < tiffStart) return null;
  const count = readU16(buffer, ifdOffset, little);
  if (count === null || count > 256) return null;
  const entries = [];
  const tags = new Map();
  for (let i = 0; i < count; i += 1) {
    const entryOff = ifdOffset + 2 + i * 12;
    if (entryOff + 12 > limit) break;
    const tag = readU16(buffer, entryOff, little);
    const type = readU16(buffer, entryOff + 2, little);
    const itemCount = readU32(buffer, entryOff + 4, little);
    if (tag === null || type === null || itemCount === null) break;
    const name = EXIF_TAGS.get(tag) || `0x${tag.toString(16).padStart(4, '0')}`;
    let value = null;
    if (type === 2) {
      // ASCII
      const inline = itemCount <= 4;
      const strOff = inline ? entryOff + 8 : tiffStart + (readU32(buffer, entryOff + 8, little) || 0);
      const maxLen = Math.min(itemCount, 512);
      if (strOff + maxLen <= limit && strOff >= tiffStart) {
        value = sanitizeText(buffer.subarray(strOff, strOff + maxLen).toString('latin1').replace(/\u0000+$/, ''), 512);
      }
    } else if (type === 3 && itemCount === 1) {
      value = readU16(buffer, entryOff + 8, little);
    } else if (type === 4 && itemCount === 1) {
      value = readU32(buffer, entryOff + 8, little);
    } else if (type === 5 && itemCount === 1) {
      const rationalOff = tiffStart + (readU32(buffer, entryOff + 8, little) || 0);
      if (rationalOff + 8 <= limit) {
        const num = readU32(buffer, rationalOff, little);
        const den = readU32(buffer, rationalOff + 4, little);
        value = den ? `(${num}/${den})` : String(num);
      }
    }
    if (value !== null && value !== '') {
      entries.push({ tag, name, type, count: itemCount, value });
      tags.set(tag, { name, type, count: itemCount, value, numeric: typeof value === 'number' ? value : null });
    }
  }
  return { count, entries, tags };
}

/** gzip header: mtime + original filename (no decompression). */
export function parseGzip(buffer) {
  const result = { ok: false, mtime: null, mtimeRaw: null, originalName: null, flags: 0, os: null, notes: [] };
  if (!Buffer.isBuffer(buffer) || buffer.length < 10 || buffer[0] !== 0x1f || buffer[1] !== 0x8b) {
    result.notes.push('不是 gzip（缺少 1F 8B 魔数）。');
    return result;
  }
  if (buffer[2] !== 8) {
    result.notes.push(`gzip 压缩方法 CM=${buffer[2]} 非标准（8=deflate）。`);
    return result;
  }
  result.ok = true;
  result.flags = buffer[3];
  result.mtimeRaw = readU32(buffer, 4, true);
  if (result.mtimeRaw && result.mtimeRaw > 0) {
    const ms = result.mtimeRaw * 1000;
    if (ms >= Date.UTC(1980, 0, 1) && ms <= Date.UTC(2100, 0, 1)) {
      result.mtime = { iso: new Date(ms).toISOString().replace('.000Z', 'Z'), epochSeconds: result.mtimeRaw, timezone: 'utc' };
    }
  }
  result.os = buffer[9];
  let off = 10;
  if (result.flags & 0x04) {
    const xlen = readU16(buffer, off, true);
    if (xlen !== null) off += 2 + xlen;
  }
  if ((result.flags & 0x08) && off < buffer.length) {
    const name = readAsciiZ(buffer, off, 512);
    result.originalName = name;
    off += name ? name.length + 1 : 0;
  }
  if ((result.flags & 0x10) && off < buffer.length) {
    result.comment = readAsciiZ(buffer, off, 512);
  }
  return result;
}

const OLE2_STREAM_HINTS = ['WordDocument', 'Workbook', 'PowerPoint Document', 'EncryptedPackage', 'EncryptionInfo', 'Macros'];

/** OLE2 / Compound File Binary header + stream-name hints (legacy Office). */
export function parseOle2(buffer) {
  const result = { ok: false, majorVersion: null, sectorShift: null, miniSectorShift: null, streamHints: [], notes: [] };
  const sig = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  if (!Buffer.isBuffer(buffer) || buffer.length < 512 || !buffer.subarray(0, 8).equals(sig)) {
    result.notes.push('不是 OLE2/CFB（签名不匹配）。');
    return result;
  }
  result.ok = true;
  result.majorVersion = readU16(buffer, 26, true);
  result.sectorShift = readU16(buffer, 30, true);
  result.miniSectorShift = readU16(buffer, 32, true);
  const scanLimit = Math.min(buffer.length, 2 * 1024 * 1024);
  for (const stream of OLE2_STREAM_HINTS) {
    const wide = Buffer.from(stream, 'utf16le');
    if (buffer.subarray(0, scanLimit).indexOf(wide) !== -1) result.streamHints.push(stream);
  }
  return result;
}

/** PDF: header version + Info dictionary strings from a bounded textual scan. */
export function parsePdf(buffer) {
  const result = { ok: false, version: null, producer: null, creator: null, creationDate: null, modDate: null, notes: [] };
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
    result.notes.push('文件过小，不是 PDF。');
    return result;
  }
  if (!buffer.subarray(0, 5).equals(Buffer.from('%PDF-', 'latin1'))) {
    result.notes.push('不是 PDF（缺少 %PDF- 头）。');
    return result;
  }
  result.ok = true;
  const header = buffer.subarray(0, 16).toString('latin1');
  const vm = /%PDF-(\d+\.\d+)/.exec(header);
  result.version = vm ? vm[1] : null;
  const scan = buffer.subarray(0, Math.min(buffer.length, 2 * 1024 * 1024)).toString('latin1');
  const extract = (key) => {
    const re = new RegExp(`/${key}\\s*\\(([^)]{1,512})\\)`);
    const m = re.exec(scan);
    return m ? sanitizeText(m[1].replace(/\\([()\\])/g, '$1'), 512) : null;
  };
  result.producer = extract('Producer');
  result.creator = extract('Creator');
  const creationRaw = extract('CreationDate');
  const modRaw = extract('ModDate');
  if (creationRaw) result.creationDate = parsePdfDate(creationRaw);
  if (modRaw) result.modDate = parsePdfDate(modRaw);
  result.notes.push('PDF Info 通过有界文本扫描提取（不解析对象流/压缩 xref）。');
  return result;
}

export { EXIF_TAGS, PNG_COLOR_TYPES };
