/**
 * Forensics — magic/content-based file type detection (PE/ELF/Mach-O, archives, documents,
 * images, scripts, captures...) with honest confidence levels.
 */
import { detectElf } from '../binary/elf.js';
import { magicInfo } from '../binary/macho.js';
import { byteStats, readU16, readU32, sanitizeText } from '../binary/util.js';
import { parseGzip, parseJpeg, parseOle2, parsePdf, parsePng } from './formats.js';
import { parseZip, zipTopLevelPrefixes } from './zip.js';

function result(type, category, mime, confidence, extensions, details = {}, notes = []) {
  return { type, category, mime, confidence, extensions, details, notes };
}

const MAGIC_TABLE = [
  { magic: Buffer.from([0x42, 0x5a, 0x68]), type: 'bzip2', category: 'archive', mime: 'application/x-bzip2', ext: ['bz2'] },
  { magic: Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), type: 'xz', category: 'archive', mime: 'application/x-xz', ext: ['xz'] },
  { magic: Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), type: 'zstd', category: 'archive', mime: 'application/zstd', ext: ['zst'] },
  { magic: Buffer.from([0x04, 0x22, 0x4d, 0x18]), type: 'lz4', category: 'archive', mime: 'application/x-lz4', ext: ['lz4'] },
  { magic: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), type: '7z', category: 'archive', mime: 'application/x-7z-compressed', ext: ['7z'] },
  { magic: Buffer.from('Rar!\u001a\u0007\u0000', 'latin1'), type: 'rar', category: 'archive', mime: 'application/vnd.rar', ext: ['rar'] },
  { magic: Buffer.from('Rar!\u001a\u0007\u0001\u0000', 'latin1'), type: 'rar5', category: 'archive', mime: 'application/vnd.rar', ext: ['rar'] },
  { magic: Buffer.from('MSCF', 'latin1'), type: 'cab', category: 'archive', mime: 'application/vnd.ms-cab-compressed', ext: ['cab'] },
  { magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), type: 'png', category: 'image', mime: 'image/png', ext: ['png'] },
  { magic: Buffer.from([0xff, 0xd8, 0xff]), type: 'jpeg', category: 'image', mime: 'image/jpeg', ext: ['jpg', 'jpeg'] },
  { magic: Buffer.from('GIF87a', 'latin1'), type: 'gif', category: 'image', mime: 'image/gif', ext: ['gif'] },
  { magic: Buffer.from('GIF89a', 'latin1'), type: 'gif', category: 'image', mime: 'image/gif', ext: ['gif'] },
  { magic: Buffer.from([0x49, 0x49, 0x2a, 0x00]), type: 'tiff', category: 'image', mime: 'image/tiff', ext: ['tif', 'tiff'] },
  { magic: Buffer.from([0x4d, 0x4d, 0x00, 0x2a]), type: 'tiff', category: 'image', mime: 'image/tiff', ext: ['tif', 'tiff'] },
  { magic: Buffer.from('8BPS', 'latin1'), type: 'photoshop', category: 'image', mime: 'image/vnd.adobe.photoshop', ext: ['psd'] },
  { magic: Buffer.from([0x00, 0x00, 0x01, 0x00]), type: 'ico', category: 'image', mime: 'image/x-icon', ext: ['ico'] },
  { magic: Buffer.from('%PDF-', 'latin1'), type: 'pdf', category: 'document', mime: 'application/pdf', ext: ['pdf'] },
  { magic: Buffer.from('%!PS', 'latin1'), type: 'postscript', category: 'document', mime: 'application/postscript', ext: ['ps'] },
  { magic: Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), type: 'ole2', category: 'document', mime: 'application/x-ole-storage', ext: ['doc', 'xls', 'ppt', 'msi'] },
  { magic: Buffer.from('SQLite format 3\u0000', 'latin1'), type: 'sqlite', category: 'database', mime: 'application/vnd.sqlite3', ext: ['db', 'sqlite', 'sqlite3'] },
  { magic: Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]), type: 'pcap', category: 'network-capture', mime: 'application/vnd.tcpdump.pcap', ext: ['pcap'] },
  { magic: Buffer.from([0xa1, 0xb2, 0xc3, 0xd4]), type: 'pcap', category: 'network-capture', mime: 'application/vnd.tcpdump.pcap', ext: ['pcap'] },
  { magic: Buffer.from([0x4d, 0x3c, 0xb2, 0xa1]), type: 'pcap', category: 'network-capture', mime: 'application/vnd.tcpdump.pcap', ext: ['pcap'] },
  { magic: Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), type: 'pcapng', category: 'network-capture', mime: 'application/x-pcapng', ext: ['pcapng'] },
  { magic: Buffer.from([0x00, 0x61, 0x73, 0x6d]), type: 'wasm', category: 'executable', mime: 'application/wasm', ext: ['wasm'] },
  { magic: Buffer.from([0x00, 0x01, 0x00, 0x00]), type: 'truetype-font', category: 'font', mime: 'font/ttf', ext: ['ttf'] },
  { magic: Buffer.from('OTTO', 'latin1'), type: 'opentype-font', category: 'font', mime: 'font/otf', ext: ['otf'] },
  { magic: Buffer.from('wOFF', 'latin1'), type: 'woff-font', category: 'font', mime: 'font/woff', ext: ['woff'] },
  { magic: Buffer.from('wOF2', 'latin1'), type: 'woff2-font', category: 'font', mime: 'font/woff2', ext: ['woff2'] },
  { magic: Buffer.from('fLaC', 'latin1'), type: 'flac', category: 'audio', mime: 'audio/flac', ext: ['flac'] },
  { magic: Buffer.from('OggS', 'latin1'), type: 'ogg', category: 'audio', mime: 'application/ogg', ext: ['ogg', 'oga', 'ogv'] },
  { magic: Buffer.from([0x1f, 0x8b, 0x08]), type: 'gzip', category: 'archive', mime: 'application/gzip', ext: ['gz', 'tgz'] },
  { magic: Buffer.from([0x1f, 0x9d]), type: 'compress', category: 'archive', mime: 'application/x-compress', ext: ['z'] },
];

/** Validate text-ish content and classify common script/document text formats. */
function classifyText(buffer) {
  let text;
  let encoding = 'utf-8';
  const head = buffer.subarray(0, Math.min(buffer.length, 4));
  if (head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) {
    text = buffer.subarray(3).toString('utf8');
  } else if (head.length >= 2 && head[0] === 0xff && head[1] === 0xfe) {
    encoding = 'utf-16le';
    text = buffer.subarray(2).toString('utf16le');
  } else if (head.length >= 2 && head[0] === 0xfe && head[1] === 0xff) {
    encoding = 'utf-16be';
    // Node has no utf16be decoder; swap bytes in a bounded copy.
    const sample = buffer.subarray(2, Math.min(buffer.length, 2 + 256 * 1024));
    const swapped = Buffer.from(sample);
    for (let i = 0; i + 1 < swapped.length; i += 2) {
      const t = swapped[i];
      swapped[i] = swapped[i + 1];
      swapped[i + 1] = t;
    }
    text = swapped.toString('utf16le');
  } else {
    // Validate UTF-8 on a bounded prefix without throwing.
    const sample = buffer.subarray(0, Math.min(buffer.length, 256 * 1024));
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(sample);
    } catch {
      return null;
    }
    if (buffer.length > sample.length) text += buffer.subarray(sample.length, Math.min(buffer.length, sample.length + 4096)).toString('latin1');
  }
  if (typeof text !== 'string') return null;
  if (buffer.indexOf(0) !== -1 && encoding === 'utf-8') {
    // A NUL in the first bytes of otherwise valid UTF-8 usually means a UTF-16 binary without BOM.
    const nulPos = buffer.indexOf(0);
    if (nulPos >= 0 && nulPos < 256) return null;
  }
  const stats = byteStats(buffer);
  const sampleLen = Math.min(buffer.length, 256 * 1024);
  const sampleText = text.slice(0, sampleLen);
  const printable = sampleText.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').length;
  const ratio = sampleText.length > 0 ? printable / sampleText.length : 0;
  if (ratio < 0.85 && encoding === 'utf-8') return null;
  const trimmed = text.replace(/^\uFEFF/, '').trimStart();
  const details = { encoding, textRatio: Math.round(ratio * 1e4) / 1e4, byteStats: stats };
  if (trimmed.startsWith('#!')) {
    const firstLine = trimmed.split(/\r?\n/, 1)[0].slice(0, 200);
    const interpreter = firstLine.replace(/^#!\s*/, '').split(/\s+/)[0];
    return result('script', 'script', 'text/x-script', 'high', ['sh', 'py', 'pl'], { ...details, shebang: firstLine, interpreter });
  }
  if (/^<!doctype\s+html/i.test(trimmed) || /^<html[\s>]/i.test(trimmed)) {
    return result('html', 'document', 'text/html', 'high', ['html', 'htm'], details);
  }
  if (/^<\?xml[\s>]/i.test(trimmed)) {
    return result('xml', 'document', 'application/xml', 'high', ['xml'], details);
  }
  if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && buffer.length <= 2 * 1024 * 1024) {
    try {
      const parsed = JSON.parse(text);
      if (parsed !== null && typeof parsed === 'object') {
        return result('json', 'document', 'application/json', 'high', ['json'], { ...details, jsonType: Array.isArray(parsed) ? 'array' : 'object' });
      }
    } catch {
      // fall through to generic text
    }
  }
  if (/powershell|Invoke-Expression|cmd\.exe/i.test(sampleText.slice(0, 4096))) {
    return result('powershell-script', 'script', 'text/x-powershell', 'medium', ['ps1'], details);
  }
  return result('text', 'text', 'text/plain', 'high', ['txt'], details);
}

/**
 * Detect file type from magic/content.
 * @returns {{type:string, category:string, mime:string, confidence:string, extensions:string[], details:object, notes:string[]}}
 */
export function detectFileType(buffer) {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.alloc(0);
  if (buf.length === 0) return result('empty', 'unknown', 'application/x-empty', 'certain', [], {}, ['输入为 0 字节。']);
  const notes = [];
  // ELF
  const elf = detectElf(buf);
  if (elf.isElf) {
    if (elf.classBits === null || elf.endianness === null) {
      notes.push(`ELF 标识字段异常（class=${buf[4]}, data=${buf[5]}）。`);
    }
    const eType = readU16(buf, 16, elf.endianness === 'big' ? false : true);
    const typeMap = { 0: 'elf-none', 1: 'elf-relocatable', 2: 'elf-executable', 3: 'elf-shared-object', 4: 'elf-core' };
    const subtype = typeMap[eType] || 'elf';
    const mime = eType === 3 ? 'application/x-sharedlib' : 'application/x-executable';
    return result(subtype, eType === 3 ? 'shared-library' : 'executable', mime, 'certain', ['elf', 'so', 'o'], {
      bits: elf.classBits,
      endianness: elf.endianness,
      osabi: elf.osabi,
      elfType: eType,
    }, notes);
  }
  // PE
  if (buf.length >= 0x40 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOffset = readU32(buf, 0x3c);
    if (peOffset !== null && peOffset >= 0x40 && peOffset + 24 <= buf.length && readU32(buf, peOffset) === 0x00004550) {
      const machine = readU16(buf, peOffset + 4);
      const characteristics = readU16(buf, peOffset + 22);
      const isDll = Boolean((characteristics || 0) & 0x2000);
      const machineMap = { 0x14c: 'x86', 0x8664: 'x86-64', 0xaa64: 'arm64', 0x1c0: 'arm', 0x1c4: 'armnt', 0x200: 'ia64' };
      return result(isDll ? 'pe-dll' : 'pe-executable', 'executable', 'application/vnd.microsoft.portable-executable', 'certain', ['exe', 'dll', 'sys', 'scr'], {
        format: 'PE',
        machine: machineMap[machine] || `machine-0x${(machine || 0).toString(16)}`,
        machineId: machine,
        characteristics,
      }, notes);
    }
    notes.push('存在 MZ 头但未找到有效 PE 签名（可能是 DOS 可执行文件或损坏样本）。');
    return result('mz-dos', 'executable', 'application/x-msdownload', 'high', ['exe'], { format: 'MZ' }, notes);
  }
  // Mach-O / fat Mach-O / Java class
  const mach = magicInfo(buf, 0);
  if (mach) {
    const endsWithJava = mach.kind === 'fat' && buf.length >= 8 && (() => {
      const nfat = readU32(buf, 4, mach.le);
      return !(nfat >= 1 && nfat <= 32);
    })();
    if (!endsWithJava) {
      const le = mach.le;
      const cpu = mach.kind === 'thin' ? readU32(buf, 4, le) : null;
      const filetype = mach.kind === 'thin' ? readU32(buf, 12, le) : null;
      const cpuMap = { 7: 'x86', 0x01000007: 'x86-64', 12: 'arm', 0x0100000c: 'arm64', 18: 'ppc', 0x01000012: 'ppc64' };
      return result(mach.kind === 'fat' ? 'mach-o-universal' : 'mach-o', 'executable', 'application/x-mach-binary', 'certain', ['macho', 'dylib', 'bundle'], {
        format: 'Mach-O',
        bits: mach.bits,
        endianness: mach.endianness,
        arch: cpuMap[cpu] || (cpu === null ? null : `cpu-0x${cpu.toString(16)}`),
        fileType: filetype,
      }, notes);
    }
    notes.push('CAFEBABE 且 nfat_arch 非法，按 Java class 处理。');
  }
  if (buf.length >= 10 && buf.readUInt32BE(0) === 0xcafebabe) {
    const major = buf.readUInt16BE(6);
    if (major >= 45 && major <= 70) {
      return result('java-class', 'executable', 'application/java-vm', 'high', ['class'], { major, minor: buf.readUInt16BE(4) }, notes);
    }
  }
  // ZIP family
  if (buf.length >= 4 && readU32(buf, 0, true) === 0x04034b50) {
    const zip = parseZip(buf, { maxEntries: 64 });
    const names = zip.entries.map((e) => e.name);
    const prefixes = zipTopLevelPrefixes(names);
    const details = {
      entryCount: zip.declaredEntryCount,
      parsedEntries: zip.parsedEntryCount,
      zip64: zip.zip64,
      scannedLocally: zip.scannedLocally,
      topLevel: prefixes.slice(0, 12),
      firstEntries: names.slice(0, 8),
    };
    if (names.includes('[Content_Types].xml')) {
      if (prefixes.some((p) => p.startsWith('word/'))) return result('docx', 'document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'certain', ['docx'], details, notes);
      if (prefixes.some((p) => p.startsWith('xl/'))) return result('xlsx', 'document', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'certain', ['xlsx'], details, notes);
      if (prefixes.some((p) => p.startsWith('ppt/'))) return result('pptx', 'document', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'certain', ['pptx'], details, notes);
      return result('ooxml', 'document', 'application/vnd.openxmlformats-officedocument', 'high', ['docx', 'xlsx', 'pptx'], details, notes);
    }
    if (names.includes('AndroidManifest.xml')) return result('apk', 'package', 'application/vnd.android.package-archive', 'certain', ['apk'], details, notes);
    if (names.includes('META-INF/MANIFEST.MF') || names.some((n) => n.startsWith('META-INF/'))) {
      return result('jar', 'package', 'application/java-archive', 'high', ['jar'], details, notes);
    }
    if (names.includes('mimetype') && names.includes('META-INF/container.xml')) return result('epub', 'document', 'application/epub+zip', 'high', ['epub'], details, notes);
    if (names.some((n) => /^META-INF\/container\.xml$/.test(n))) return result('odf', 'document', 'application/vnd.oasis.opendocument', 'high', ['odt', 'ods', 'odp'], details, notes);
    return result('zip', 'archive', 'application/zip', 'certain', ['zip'], details, notes);
  }
  // OLE2 / legacy Office
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))) {
    const ole = parseOle2(buf);
    const hints = ole.streamHints || [];
    const details = { majorVersion: ole.majorVersion, sectorShift: ole.sectorShift, streamHints: hints };
    if (hints.includes('WordDocument')) return result('doc', 'document', 'application/msword', 'high', ['doc'], details, notes);
    if (hints.includes('Workbook')) return result('xls', 'document', 'application/vnd.ms-excel', 'high', ['xls'], details, notes);
    if (hints.includes('PowerPoint Document')) return result('ppt', 'document', 'application/vnd.ms-powerpoint', 'high', ['ppt'], details, notes);
    if (hints.includes('EncryptedPackage')) return result('msi-or-encrypted-ole2', 'package', 'application/x-ole-storage', 'medium', ['msi'], details, notes);
    return result('ole2', 'document', 'application/x-ole-storage', 'certain', ['doc', 'xls', 'ppt', 'msi'], details, notes);
  }
  // Generic magic table
  for (const entry of MAGIC_TABLE) {
    if (buf.length >= entry.magic.length && buf.subarray(0, entry.magic.length).equals(entry.magic)) {
      const details = {};
      if (entry.type === 'png') {
        const png = parsePng(buf);
        Object.assign(details, { width: png.width, height: png.height, colorType: png.colorTypeName });
      } else if (entry.type === 'jpeg') {
        const jpeg = parseJpeg(buf);
        Object.assign(details, { width: jpeg.width, height: jpeg.height, hasExif: jpeg.hasExif });
      } else if (entry.type === 'gzip') {
        const gz = parseGzip(buf);
        Object.assign(details, { originalName: gz.originalName, mtime: gz.mtime ? gz.mtime.iso : null });
      } else if (entry.type === 'pdf') {
        const pdf = parsePdf(buf);
        Object.assign(details, { version: pdf.version, producer: pdf.producer });
      }
      return result(entry.type, entry.category, entry.mime, 'certain', entry.ext, details, notes);
    }
  }
  // RIFF containers
  if (buf.length >= 12 && buf.subarray(0, 4).toString('latin1') === 'RIFF') {
    const kind = buf.subarray(8, 12).toString('latin1');
    if (kind === 'WEBP') return result('webp', 'image', 'image/webp', 'certain', ['webp'], {}, notes);
    if (kind === 'WAVE') return result('wav', 'audio', 'audio/wav', 'certain', ['wav'], {}, notes);
    if (kind === 'AVI ') return result('avi', 'video', 'video/x-msvideo', 'certain', ['avi'], {}, notes);
    return result('riff', 'unknown', 'application/x-riff', 'high', ['riff'], { kind }, notes);
  }
  // MP4 family
  if (buf.length >= 12 && buf.subarray(4, 8).toString('latin1') === 'ftyp') {
    const brand = sanitizeText(buf.subarray(8, 12).toString('latin1'), 16);
    if (['heic', 'heix', 'mif1', 'msf1'].includes(brand)) return result('heic', 'image', 'image/heic', 'high', ['heic'], { brand }, notes);
    return result('mp4', 'video', 'video/mp4', 'high', ['mp4', 'm4a', 'mov'], { brand }, notes);
  }
  // tar
  if (buf.length >= 265 && buf.subarray(257, 262).toString('latin1') === 'ustar') {
    return result('tar', 'archive', 'application/x-tar', 'certain', ['tar'], {}, notes);
  }
  // Windows shortcut
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]))) {
    return result('lnk', 'executable', 'application/x-ms-shortcut', 'certain', ['lnk'], {}, notes);
  }
  // Android DEX
  if (buf.length >= 8 && buf.subarray(0, 4).toString('latin1') === 'dex\n') {
    return result('dex', 'executable', 'application/x-android-dex', 'certain', ['dex'], { version: buf.subarray(4, 8).toString('latin1').replace(/\u0000/g, '') }, notes);
  }
  // ISO9660 (often ISO at 0x8001)
  if (buf.length > 0x8006 && buf.subarray(0x8001, 0x8006).toString('latin1') === 'CD001') {
    return result('iso9660', 'archive', 'application/x-iso9660-image', 'high', ['iso'], {}, notes);
  }
  // Text / script / structured data
  const textType = classifyText(buf);
  if (textType) {
    textType.notes = notes;
    return textType;
  }
  return result('data', 'unknown', 'application/octet-stream', 'low', ['bin'], {
    magicHex: buf.subarray(0, 16).toString('hex'),
    size: buf.length,
  }, notes);
}

export { MAGIC_TABLE };
