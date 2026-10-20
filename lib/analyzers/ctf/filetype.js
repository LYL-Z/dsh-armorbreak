// ArmorBreak CTF domain — multi-layer artifact classification.
//
// Identifies file magic (PNG/JPEG/PDF/ZIP/APK/GZIP/ELF/PE/PCAP/...), text
// encodings (base64/base32/hex/binary/URL/Morse/ROT13/...), then follows the
// most promising decodable layer with a hard depth/size cap. Every layer preview
// is control-character stripped. Findings are honest: flags are "observed",
// multi-layer/entropy observations are "hypothesis".

import {
  asciiStrings,
  clampInt,
  clip,
  hexDump,
  isPrintableText,
  previewText,
  printableRatio,
  shannonEntropy,
} from './common.js';
import { applyTransform } from './encoding.js';
import { scanFlagsInBuffer, scanFlagsInText } from './flagscan.js';

const MAX_SCAN_BYTES = 4 * 1024 * 1024;

function startsWith(buffer, signature) {
  if (buffer.length < signature.length) return false;
  for (let i = 0; i < signature.length; i += 1) {
    if (buffer[i] !== signature[i]) return false;
  }
  return true;
}

function magic(kind, label, mime, evidence, details = null, confidence = 'high') {
  return { kind, label, mime, confidence, evidence, ...(details ? { details } : {}) };
}

/** Parse central-directory entry names from a ZIP payload (bounded). */
export function listZipEntries(buffer, maxEntries = 100) {
  const entries = [];
  const centralSignature = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
  let cursor = 0;
  while (entries.length < maxEntries) {
    const index = buffer.indexOf(centralSignature, cursor);
    if (index < 0 || index + 46 > buffer.length) break;
    const nameLength = buffer.readUInt16LE(index + 28);
    const extraLength = buffer.readUInt16LE(index + 30);
    const commentLength = buffer.readUInt16LE(index + 32);
    const nameStart = index + 46;
    if (nameLength <= 0 || nameStart + nameLength > buffer.length) break;
    const name = buffer.subarray(nameStart, nameStart + nameLength).toString('utf8');
    if (/^[\x20-\x7e]{1,300}$/.test(name)) entries.push(name);
    cursor = nameStart + nameLength + extraLength + commentLength;
    if (cursor <= index) break;
  }
  if (entries.length) return entries;

  // Fallback: streamed ZIPs may only have local file headers.
  const localSignature = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  cursor = 0;
  while (entries.length < Math.min(maxEntries, 50)) {
    const index = buffer.indexOf(localSignature, cursor);
    if (index < 0 || index + 30 > buffer.length) break;
    const nameLength = buffer.readUInt16LE(index + 26);
    const extraLength = buffer.readUInt16LE(index + 28);
    if (nameLength <= 0 || index + 30 + nameLength > buffer.length) break;
    const name = buffer.subarray(index + 30, index + 30 + nameLength).toString('utf8');
    if (/^[\x20-\x7e]{1,300}$/.test(name)) entries.push(name);
    break; // compressed sizes are unreliable without the data descriptor
  }
  return entries;
}

function refineZip(name, entries, buffer) {
  if (!entries.length) return null;
  const lower = entries.map((entry) => entry.toLowerCase());
  const has = (predicate) => lower.some(predicate);
  if (has((entry) => entry === 'androidmanifest.xml') || has((entry) => entry.endsWith('.dex'))) {
    return magic('apk', 'Android APK（ZIP 容器）', 'application/vnd.android.package-archive', hexDump(buffer, 8), {
      entries: entries.slice(0, 20),
      entryCount: entries.length,
    });
  }
  if (has((entry) => entry === '[content_types].xml')) {
    let kind = 'ooxml';
    let label = 'Office Open XML（ZIP 容器）';
    if (has((entry) => entry.startsWith('word/'))) {
      kind = 'docx';
      label = 'Word DOCX（ZIP 容器）';
    } else if (has((entry) => entry.startsWith('xl/'))) {
      kind = 'xlsx';
      label = 'Excel XLSX（ZIP 容器）';
    } else if (has((entry) => entry.startsWith('ppt/'))) {
      kind = 'pptx';
      label = 'PowerPoint PPTX（ZIP 容器）';
    }
    return magic(kind, label, 'application/zip', hexDump(buffer, 8), { entries: entries.slice(0, 20), entryCount: entries.length });
  }
  if (has((entry) => entry === 'meta-inf/manifest.mf') || has((entry) => entry.endsWith('.class'))) {
    return magic('jar', 'JAR/Java 归档（ZIP 容器）', 'application/java-archive', hexDump(buffer, 8), {
      entries: entries.slice(0, 20),
      entryCount: entries.length,
    });
  }
  if (has((entry) => entry.endsWith('.py')) && has((entry) => entry.endsWith('.pyc'))) {
    return magic('pyz', 'Python 归档（ZIP 容器）', 'application/zip', hexDump(buffer, 8), {
      entries: entries.slice(0, 20),
      entryCount: entries.length,
    });
  }
  return magic('zip', 'ZIP 归档', 'application/zip', hexDump(buffer, 8), {
    entries: entries.slice(0, 20),
    entryCount: entries.length,
  });
}

function elfDetails(buffer) {
  if (buffer.length < 20) return null;
  const is64 = buffer[4] === 2;
  const littleEndian = buffer[5] !== 2;
  const machine = littleEndian ? buffer.readUInt16LE(18) : buffer.readUInt16BE(18);
  const machines = {
    0x03: 'x86',
    0x3e: 'x86-64',
    0x28: 'ARM',
    0xb7: 'AArch64',
    0x08: 'MIPS',
    0x14: 'PowerPC',
    0xf3: 'RISC-V',
  };
  return {
    class: is64 ? '64-bit' : '32-bit',
    endianness: littleEndian ? 'little-endian' : 'big-endian',
    machine: machines[machine] ?? `unknown(0x${machine.toString(16)})`,
  };
}

function peDetails(buffer) {
  if (buffer.length < 0x40 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) return null;
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 6 > buffer.length) return null;
  if (!(buffer[peOffset] === 0x50 && buffer[peOffset + 1] === 0x45 && buffer[peOffset + 2] === 0 && buffer[peOffset + 3] === 0)) {
    return null;
  }
  const machine = buffer.readUInt16LE(peOffset + 4);
  const machines = { 0x014c: 'x86', 0x8664: 'x86-64', 0xaa64: 'ARM64', 0x01c4: 'ARMv7' };
  return { machine: machines[machine] ?? `unknown(0x${machine.toString(16)})`, peOffset };
}

const PCAP_MAGICS = [
  { bytes: [0xd4, 0xc3, 0xb2, 0xa1], label: 'PCAP（小端，微秒）' },
  { bytes: [0xa1, 0xb2, 0xc3, 0xd4], label: 'PCAP（大端，微秒）' },
  { bytes: [0x4d, 0x3c, 0xb2, 0xa1], label: 'PCAP（小端，纳秒）' },
  { bytes: [0xa1, 0xb2, 0x3c, 0x4d], label: 'PCAP（大端，纳秒）' },
];

/**
 * Detect known file formats by magic bytes.
 * @returns {{kind,label,mime,confidence,evidence,details?}[]}
 */
export function detectBufferMagic(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) return [];
  const sample = buffer.subarray(0, Math.min(buffer.length, MAX_SCAN_BYTES));
  const found = [];
  const push = (entry) => {
    if (entry && !found.some((f) => f.kind === entry.kind)) found.push(entry);
  };

  if (startsWith(sample, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    push(magic('png', 'PNG 图片', 'image/png', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0xff, 0xd8, 0xff])) {
    push(magic('jpeg', 'JPEG 图片', 'image/jpeg', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x47, 0x49, 0x46, 0x38])) {
    push(magic('gif', 'GIF 图片', 'image/gif', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x25, 0x50, 0x44, 0x46])) {
    push(magic('pdf', 'PDF 文档', 'application/pdf', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x42, 0x4d])) {
    push(magic('bmp', 'BMP 图片', 'image/bmp', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x52, 0x49, 0x46, 0x46])) {
    const sub = sample.length >= 12 ? sample.subarray(8, 12).toString('latin1') : '';
    if (sub === 'WEBP') push(magic('webp', 'WebP 图片', 'image/webp', hexDump(sample, 12)));
    else if (sub === 'WAVE') push(magic('wav', 'WAV 音频', 'audio/wav', hexDump(sample, 12)));
    else push(magic('riff', 'RIFF 容器', 'application/octet-stream', hexDump(sample, 12)));
  }
  if (startsWith(sample, [0x1f, 0x8b])) {
    push(magic('gzip', 'Gzip 压缩数据', 'application/gzip', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x42, 0x5a, 0x68])) {
    push(magic('bzip2', 'Bzip2 压缩数据（Node 内置不支持解压）', 'application/x-bzip2', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) {
    push(magic('xz', 'XZ 压缩数据（Node 内置不支持解压）', 'application/x-xz', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) {
    push(magic('7z', '7-Zip 归档', 'application/x-7z-compressed', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) {
    push(magic('rar', 'RAR 归档', 'application/vnd.rar', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00])) {
    push(magic('sqlite', 'SQLite 数据库', 'application/vnd.sqlite3', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x00, 0x61, 0x73, 0x6d])) {
    push(magic('wasm', 'WebAssembly 模块', 'application/wasm', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x7f, 0x45, 0x4c, 0x46])) {
    push(magic('elf', 'ELF 可执行文件/目标文件', 'application/x-elf', hexDump(sample, 8), elfDetails(sample)));
  }
  const pe = peDetails(sample);
  if (pe) push(magic('pe', 'Windows PE 可执行文件', 'application/vnd.microsoft.portable-executable', hexDump(sample, 8), pe));
  if (startsWith(sample, [0xfe, 0xed, 0xfa, 0xce]) || startsWith(sample, [0xce, 0xfa, 0xed, 0xfe])) {
    push(magic('macho', 'Mach-O 可执行文件（32/64 位）', 'application/x-mach-binary', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0xca, 0xfe, 0xba, 0xbe])) {
    const version = sample.length >= 8 ? sample.readUInt16BE(6) : 0;
    if (version >= 45 && version <= 80) {
      push(magic('java-class', 'Java Class 字节码', 'application/java-vm', hexDump(sample, 8), { majorVersion: version }));
    } else {
      push(magic('macho-fat', 'Mach-O Fat/Universal 二进制', 'application/x-mach-binary', hexDump(sample, 8)));
    }
  }
  if (startsWith(sample, [0x1a, 0x45, 0xdf, 0xa3])) {
    push(magic('matroska', 'Matroska/WebM 媒体容器', 'video/x-matroska', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x4f, 0x67, 0x67, 0x53])) {
    push(magic('ogg', 'Ogg 媒体容器', 'application/ogg', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x66, 0x4c, 0x61, 0x43])) {
    push(magic('flac', 'FLAC 音频', 'audio/flac', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x49, 0x44, 0x33])) {
    push(magic('mp3', 'MP3 音频（ID3）', 'audio/mpeg', hexDump(sample, 8)));
  }
  for (const pcap of PCAP_MAGICS) {
    if (startsWith(sample, pcap.bytes)) {
      push(magic('pcap', pcap.label, 'application/vnd.tcpdump.pcap', hexDump(sample, 8)));
      break;
    }
  }
  if (startsWith(sample, [0x0a, 0x0d, 0x0d, 0x0a])) {
    push(magic('pcapng', 'PCAPNG 抓包文件', 'application/x-pcapng', hexDump(sample, 8)));
  }
  if (startsWith(sample, [0x50, 0x4b, 0x03, 0x04]) || startsWith(sample, [0x50, 0x4b, 0x05, 0x06])) {
    const entries = listZipEntries(sample, 100);
    const refined = refineZip('zip', entries, sample);
    push(refined ?? magic('zip', 'ZIP 归档', 'application/zip', hexDump(sample, 8)));
  }
  if (sample.length >= 262 && sample.subarray(257, 262).toString('latin1') === 'ustar') {
    push(magic('tar', 'TAR 归档', 'application/x-tar', hexDump(sample.subarray(257, 265), 8)));
  }
  return found;
}

function decodeCandidate(transform, text) {
  try {
    const state = applyTransform(transform, { bytes: Buffer.from(text, 'utf8') });
    const outBytes = state.bytes;
    const outText = outBytes.toString('utf8');
    const validUtf8 = Buffer.from(outText, 'utf8').equals(outBytes);
    const printable = printableRatio(outText);
    const magic = detectBufferMagic(outBytes).slice(0, 3);
    return {
      bytes: outBytes,
      text: outText,
      validUtf8,
      printable,
      magic,
      useful: printable >= 0.8 || magic.length > 0,
    };
  } catch {
    return null;
  }
}

/**
 * Detect likely text encodings. Ordered by specificity (hex/base32 before
 * base64; rot13 is a non-auto-chainable hint only).
 */
export function detectTextEncodings(text) {
  const source = String(text ?? '');
  const trimmed = source.trim();
  if (!trimmed) return [];
  const out = [];
  const add = (encoding, transform, confidence, reason, extra = {}) => {
    if (out.some((entry) => entry.encoding === encoding)) return;
    out.push({ encoding, transform, confidence, reason, ...extra });
  };
  const cleanedNoSpace = trimmed.replace(/\s+/g, '');

  // Hex
  if (cleanedNoSpace.length >= 8 && cleanedNoSpace.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleanedNoSpace) && /^[0-9a-fA-F\s]+$/.test(trimmed)) {
    const decoded = decodeCandidate('hex', trimmed);
    if (decoded?.useful) add('hex', 'hex', 'high', `十六进制串（${cleanedNoSpace.length} 字符）解码后${decoded.magic.length ? '出现文件魔数' : '为可读文本'}`);
  }
  // Base64 (standard, may include internal whitespace)
  if (cleanedNoSpace.length >= 8 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanedNoSpace)) {
    const decoded = decodeCandidate('base64', trimmed);
    if (decoded?.useful) {
      add('base64', 'base64', 'high', `Base64 字符集与长度合法，解码得到 ${decoded.bytes.length} 字节${decoded.magic.length ? '（含文件魔数）' : '可读数据'}`);
    }
  }
  // Base64URL
  if (!out.some((e) => e.encoding === 'base64') && cleanedNoSpace.length >= 8 && /^[A-Za-z0-9_-]+={0,2}$/.test(cleanedNoSpace)) {
    const decoded = decodeCandidate('base64url', trimmed);
    if (decoded?.useful) add('base64url', 'base64url', 'high', `Base64URL 字符集（含 -/_ 或 padding），解码得到可读数据`);
  }
  // Base32
  if (cleanedNoSpace.length >= 8 && /^[A-Z2-7]+=*$/.test(cleanedNoSpace.toUpperCase())) {
    const decoded = decodeCandidate('base32', trimmed);
    if (decoded?.useful && /^[A-Z2-7=\s]+$/i.test(trimmed)) {
      add('base32', 'base32', 'medium', 'Base32 字母表（A-Z2-7）且解码结果可读');
    }
  }
  // Binary bits
  if (cleanedNoSpace.length >= 8 && /^[01]+$/.test(cleanedNoSpace) && cleanedNoSpace.length % 8 === 0 && /^[01\s]+$/.test(trimmed)) {
    const decoded = decodeCandidate('binary', trimmed);
    if (decoded?.useful) add('binary', 'binary', 'high', '0/1 位串且长度为 8 的倍数，解码结果可读');
  }
  // URL-encoded
  if (/%[0-9A-Fa-f]{2}/.test(trimmed)) {
    const decoded = decodeCandidate('url', trimmed);
    if (decoded?.useful && decoded.text !== trimmed) {
      add('url', 'url', 'high', '包含 %XX 转义序列，URL 解码后为可读文本');
    }
  }
  // Morse
  if (trimmed.length >= 8 && /^[.\-\s/|]+$/.test(trimmed) && /[.-]/.test(trimmed) && /[\s/|]/.test(trimmed)) {
    const decoded = decodeCandidate('morse', trimmed);
    if (decoded?.useful) add('morse', 'morse', 'medium', '由 . - / 组成的 Morse 电码，解码结果可读');
  }
  // ROT13 hint (cannot be distinguished from plain English; never auto-chained)
  const letters = (trimmed.match(/[A-Za-z]/g) || []).length;
  if (trimmed.length >= 12 && letters / trimmed.length > 0.6 && !/\d/.test(trimmed)) {
    add('rot13', 'rot13', 'low', '纯字母文本，可能是 ROT13（与普通英文不可区分，仅作提示）', { autoChain: false });
  }
  return out;
}

function flagsFromState(text, bytes) {
  const seen = new Set();
  const merged = [];
  for (const hit of [...scanFlagsInText(text, { maxItems: 20 }), ...scanFlagsInBuffer(bytes, { maxItems: 20 })]) {
    if (seen.has(hit.flag)) continue;
    seen.add(hit.flag);
    merged.push(hit);
  }
  return merged;
}

/**
 * Classify an artifact and follow the most promising decode chain.
 * @param {{bytes:Buffer, text:string}} artifact
 */
export function classifyArtifact(artifact, opts = {}) {
  const maxDepth = clampInt(opts.maxDepth, 5, 1, 10);
  const maxCandidates = clampInt(opts.maxCandidates, 8, 1, 50);
  const initialBytes = artifact.bytes;
  const magicInitial = detectBufferMagic(initialBytes);
  const initialText = initialBytes.toString('utf8');
  const isText = isPrintableText(initialText, 0.85);
  const textEncodings = isText ? detectTextEncodings(initialText) : [];

  // Candidate table for the initial layer.
  const candidates = [];
  for (const candidate of textEncodings) {
    if (candidates.length >= maxCandidates) break;
    const decoded = decodeCandidate(candidate.transform, initialText);
    if (!decoded) {
      candidates.push({ encoding: candidate.encoding, confidence: candidate.confidence, decodable: false, reason: candidate.reason });
      continue;
    }
    candidates.push({
      encoding: candidate.encoding,
      confidence: candidate.confidence,
      decodable: true,
      outputBytes: decoded.bytes.length,
      printable: decoded.printable,
      preview: previewText(decoded.text, 200),
      magic: decoded.magic.map((m) => m.kind),
      reason: candidate.reason,
    });
  }

  // Follow the chain: compression magic first, then the highest-priority
  // auto-chainable text encoding.
  const chain = [];
  const seen = new Set([initialBytes.toString('base64')]);
  let current = initialBytes;
  let depthTruncated = false;
  for (let depth = 1; depth <= maxDepth; depth += 1) {
    if (opts.signal?.aborted) break;
    const currentMagic = detectBufferMagic(current);
    const compression = currentMagic.find((entry) => entry.kind === 'gzip' || entry.kind === 'zlib');
    let advanced = false;
    if (compression) {
      try {
        const out = applyTransform(compression.kind, { bytes: current });
        const key = out.bytes.toString('base64');
        if (out.bytes.length && !seen.has(key)) {
          seen.add(key);
          const outText = out.bytes.toString('utf8');
          chain.push({
            depth,
            encoding: compression.kind,
            source: 'magic-bytes',
            outputBytes: out.bytes.length,
            printable: isPrintableText(outText, 0.8),
            entropy: Number(shannonEntropy(out.bytes).toFixed(3)),
            preview: previewText(outText, 300),
            flags: scanFlagsInText(outText, { maxItems: 5 }).map((f) => f.flag),
          });
          current = out.bytes;
          advanced = true;
        }
      } catch {
        // Magic said compression but data is corrupt; fall through to text layer.
      }
    }
    if (advanced) continue;
    const text = current.toString('utf8');
    const encodings = isPrintableText(text, 0.6) ? detectTextEncodings(text) : [];
    const chosen = encodings.find((entry) => entry.autoChain !== false && entry.confidence !== 'low');
    if (!chosen) break;
    try {
      const out = applyTransform(chosen.transform, { bytes: current });
      const key = out.bytes.toString('base64');
      if (!out.bytes.length || seen.has(key)) break;
      seen.add(key);
      const outText = out.bytes.toString('utf8');
      chain.push({
        depth,
        encoding: chosen.encoding,
        source: 'text-encoding',
        outputBytes: out.bytes.length,
        printable: isPrintableText(outText, 0.8),
        entropy: Number(shannonEntropy(out.bytes).toFixed(3)),
        preview: previewText(outText, 300),
        flags: scanFlagsInText(outText, { maxItems: 5 }).map((f) => f.flag),
      });
      current = out.bytes;
    } catch {
      break;
    }
    if (depth === maxDepth) {
      const more = isPrintableText(current.toString('utf8'), 0.6) ? detectTextEncodings(current.toString('utf8')) : [];
      depthTruncated = more.some((entry) => entry.autoChain !== false && entry.confidence !== 'low');
    }
  }

  const finalText = current.toString('utf8');
  const finalMagic = detectBufferMagic(current);
  const flags = flagsFromState(finalText, current);
  const finalPrintable = isPrintableText(finalText, 0.8);
  const entropy = Number(shannonEntropy(current).toFixed(3));

  return {
    magic: magicInitial,
    textEncodings,
    candidates,
    chain,
    final: {
      byteLength: current.length,
      printable: finalPrintable,
      entropy,
      preview: previewText(finalText, 300),
      magic: finalMagic,
    },
    flags,
    isText,
    initial: {
      byteLength: initialBytes.length,
      entropy: Number(shannonEntropy(initialBytes).toFixed(3)),
      hexPreview: hexDump(initialBytes, 16),
      asciiStrings: asciiStrings(initialBytes, { minLength: 6, maxItems: 5 }).map((item) => ({ offset: item.offset, text: clip(item.text, 80) })),
    },
    truncated: { depth: depthTruncated, candidates: textEncodings.length > maxCandidates },
    maxDepth,
  };
}
