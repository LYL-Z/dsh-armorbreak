// ArmorBreak - DEX 文件解析（纯 node:*）
// 解析 DEX 头、string_ids / type_ids / *_ids 计数、类描述符与类定义摘要。
// 字符串数据为 MUTF-8（NUL 结尾），带长度上限；截断标记而非崩溃。
import { sanitizeText } from './util.js';

export const DEX_HEADER_SIZE = 0x70;
export const DEX_ENDIAN_CONSTANT = 0x12345678;
export const DEX_REVERSE_ENDIAN = 0x78563412;

export class DexError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'DexError';
    this.detail = detail;
  }
}

const ACCESS_FLAGS = new Map([
  [0x1, 'public'],
  [0x2, 'private'],
  [0x4, 'protected'],
  [0x8, 'static'],
  [0x10, 'final'],
  [0x200, 'interface'],
  [0x400, 'abstract'],
  [0x1000, 'synthetic'],
  [0x2000, 'annotation'],
  [0x4000, 'enum'],
]);

const LIB_HINTS = [
  {
    category: 'http-client',
    label: 'HTTP 客户端库',
    patterns: [/Lokhttp3\//, /Lretrofit2\//, /Lokio\//, /Lorg\/apache\/http\//, /Lcom\/android\/volley\//],
  },
  {
    category: 'tls',
    label: 'TLS / 证书校验相关',
    patterns: [/CertificatePinner/, /X509TrustManager/, /TrustManagerFactory/, /Ljavax\/net\/ssl\//, /SSLContext/, /HostnameVerifier/, /TrustAllCerts/],
  },
  {
    category: 'crypto',
    label: '加解密 API',
    patterns: [/Ljavax\/crypto\//, /Ljava\/security\//, /Ljavax\/crypto\/spec\//, /Landroid\/security\/crypto\//],
  },
  {
    category: 'dynamic-loading',
    label: '动态加载 / 反射',
    patterns: [/DexClassLoader/, /PathClassLoader/, /InMemoryDexClassLoader/, /Ljava\/lang\/reflect\//, /System\.load/],
  },
  {
    category: 'root-detection',
    label: 'Root / 反调试检测特征',
    patterns: [/frida/i, /xposed/i, /magisk/i, /supersu/i, /RootBeer/, /isRooted/i, /\/su\b/, /getprop/i],
  },
  {
    category: 'native',
    label: 'Native 交互',
    patterns: [/Landroid\/app\/NativeActivity/, /System\.loadLibrary/, /Ljava\/lang\/System/],
  },
];

function readU32Safe(buffer, off) {
  return off + 4 <= buffer.length ? buffer.readUInt32LE(off) : null;
}

function readUleb128(buffer, start, end) {
  let result = 0;
  let shift = 0;
  let pos = start;
  for (let i = 0; i < 5 && pos < end; i++) {
    const b = buffer[pos++];
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) return { value: result >>> 0, next: pos };
    shift += 7;
  }
  return { value: null, next: pos };
}

/** 解码 MUTF-8（CESU-8）字符串，止于 NUL 或 end。 */
export function decodeMutf8(buffer, start, end) {
  const units = [];
  let pos = start;
  while (pos < end) {
    const b = buffer[pos];
    if (b === 0x00) break;
    if (b < 0x80) {
      units.push(b);
      pos += 1;
    } else if ((b & 0xe0) === 0xc0 && pos + 1 < end) {
      const b1 = buffer[pos + 1];
      units.push(((b & 0x1f) << 6) | (b1 & 0x3f));
      pos += 2;
    } else if ((b & 0xf0) === 0xe0 && pos + 2 < end) {
      const b1 = buffer[pos + 1];
      const b2 = buffer[pos + 2];
      units.push(((b & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f));
      pos += 3;
    } else if ((b & 0xf8) === 0xf0 && pos + 3 < end) {
      // 非标准 4 字节 MUTF-8（部分工具会写）：合成为代理对
      const b1 = buffer[pos + 1];
      const b2 = buffer[pos + 2];
      const b3 = buffer[pos + 3];
      const cp =
        ((b & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
      const v = cp - 0x10000;
      units.push(0xd800 | (v >> 10), 0xdc00 | (v & 0x3ff));
      pos += 4;
    } else {
      units.push(0xfffd); // 无效字节 -> U+FFFD
      pos += 1;
    }
  }
  let out = '';
  for (let i = 0; i < units.length; i += 4096) {
    out += String.fromCharCode(...units.slice(i, i + 4096));
  }
  return out;
}

function formatAccessFlags(flags) {
  const names = [];
  for (const [bit, name] of ACCESS_FLAGS) if (flags & bit) names.push(name);
  return names;
}

/**
 * 解析 DEX。
 * @param {Buffer} buffer
 * @param {{maxStrings?:number, maxClassDefs?:number, maxScan?:number}} opts
 */
export function parseDex(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
    throw new DexError('DEX 解析失败：输入不足 8 字节，无法读取 DEX magic。');
  }
  const magic = buffer.subarray(0, 4).toString('latin1');
  if (magic !== 'dex\n') {
    throw new DexError(
      `不是 DEX 文件：magic 为 ${JSON.stringify(buffer.subarray(0, 8).toString('latin1'))}，期望 "dex\\n"。` +
        '请确认目标为 classes*.dex；APK 内 DEX 需先从 ZIP 容器中读取。',
    );
  }
  if (buffer.length < DEX_HEADER_SIZE) {
    throw new DexError(
      `DEX 解析失败：文件仅 ${buffer.length} 字节，小于 DEX 头长度 ${DEX_HEADER_SIZE} 字节（文件被截断）。`,
    );
  }
  const versionRaw = buffer.subarray(4, 8);
  const versionText = versionRaw.subarray(0, 3).toString('latin1');
  const version = /^\d{3}$/.test(versionText) ? versionText : 'unknown';
  const warnings = [];
  if (versionRaw[3] !== 0x00) warnings.push('DEX magic 第 8 字节不是 NUL，文件头可能有误。');
  if (version === 'unknown' || Number(version) < 35 || Number(version) > 41) {
    warnings.push(`DEX 版本 ${JSON.stringify(sanitizeText(versionText, 8))} 不在已知范围 035-041，按 039 规则尽力解析。`);
  }
  const endianTag = buffer.readUInt32LE(32 + 8); // header 偏移 0x28 = 40
  if (endianTag === DEX_REVERSE_ENDIAN) {
    throw new DexError(
      'DEX 为大端字节序（endian_tag=0x78563412），离线解析器仅支持小端 DEX。请用标准 Android 构建产物。',
    );
  }
  if (endianTag !== DEX_ENDIAN_CONSTANT) {
    warnings.push(`DEX endian_tag=0x${endianTag.toString(16)} 非标准值，可能不是有效 DEX。`);
  }
  const fileSize = buffer.readUInt32LE(32);
  const headerSize = buffer.readUInt32LE(36);
  const stringIdsSize = buffer.readUInt32LE(56);
  const stringIdsOff = buffer.readUInt32LE(60);
  const typeIdsSize = buffer.readUInt32LE(64);
  const typeIdsOff = buffer.readUInt32LE(68);
  const protoIdsSize = buffer.readUInt32LE(72);
  const fieldIdsSize = buffer.readUInt32LE(80);
  const methodIdsSize = buffer.readUInt32LE(88);
  const classDefsSize = buffer.readUInt32LE(96);
  const classDefsOff = buffer.readUInt32LE(100);
  const dataSize = buffer.readUInt32LE(104);
  const dataOff = buffer.readUInt32LE(108);

  if (headerSize !== DEX_HEADER_SIZE) {
    warnings.push(`DEX header_size=${headerSize}（标准为 ${DEX_HEADER_SIZE}），按标准布局解析。`);
  }
  const len = buffer.length;
  let truncated = false;
  if (fileSize > len) {
    truncated = true;
    warnings.push(`DEX 声明 file_size=${fileSize}，实际仅 ${len} 字节，已按实际边界解析（截断）。`);
  }
  if (fileSize > 512 * 1024 * 1024) {
    throw new DexError(`DEX 声明 file_size=${fileSize} 超过 512MiB 上限，疑似恶意文件。`);
  }
  const limitStrings = Math.max(1, Math.min(opts.maxStrings ?? 500, 20000));
  const limitClassDefs = Math.max(1, Math.min(opts.maxClassDefs ?? 200, 5000));
  const maxScan = Math.max(limitStrings, Math.min(opts.maxScan ?? 4000, 200000));
  const end = Math.min(fileSize || len, len);

  const rangeOk = (off, count, itemSize) => {
    if (!Number.isFinite(off) || !Number.isFinite(count)) return false;
    const bytes = count * itemSize;
    return off >= 0 && off + bytes <= end && bytes >= 0;
  };

  // string_ids
  const strings = [];
  let stringScanLimit = Math.min(stringIdsSize, maxScan);
  if (stringIdsSize > 0 && !rangeOk(stringIdsOff, stringScanLimit, 4)) {
    truncated = true;
    warnings.push('DEX string_ids 区间越界，字符串解析已跳过。');
    stringScanLimit = 0;
  }
  const stringDataEnd = end;
  for (let i = 0; i < stringScanLimit; i++) {
    const dataOff2 = buffer.readUInt32LE(stringIdsOff + i * 4);
    if (dataOff2 < 0 || dataOff2 >= stringDataEnd) {
      strings.push('');
      continue;
    }
    const lenRes = readUleb128(buffer, dataOff2, stringDataEnd);
    if (lenRes.value === null) {
      strings.push('');
      continue;
    }
    strings.push(decodeMutf8(buffer, lenRes.next, stringDataEnd));
  }
  if (stringIdsSize > stringScanLimit) truncated = true;

  // type_ids -> 类描述符
  const typeCount = Math.min(typeIdsSize, maxScan);
  let typeRangeOk = typeIdsSize === 0 || rangeOk(typeIdsOff, typeCount, 4);
  if (!typeRangeOk) {
    truncated = true;
    warnings.push('DEX type_ids 区间越界，描述符解析已跳过。');
  }
  const typeDescriptors = [];
  if (typeRangeOk) {
    for (let i = 0; i < typeCount; i++) {
      const strIdx = buffer.readUInt32LE(typeIdsOff + i * 4);
      const s = strIdx < strings.length ? strings[strIdx] : null;
      typeDescriptors.push(s);
    }
  }
  const classDescriptorList = typeDescriptors.filter((s) => typeof s === 'string' && s.startsWith('L'));
  const descriptorSample = classDescriptorList.slice(0, Math.min(limitStrings, 300)).map((s) => sanitizeText(s, 300));
  const singleLetterClasses = classDescriptorList.filter((s) => /^L[^/;]{1,2};$/.test(s)).length;
  const obfuscationRatio = classDescriptorList.length > 0 ? singleLetterClasses / classDescriptorList.length : 0;

  // class_defs
  const classDefLimit = Math.min(classDefsSize, limitClassDefs);
  const classDefs = [];
  if (classDefsSize > 0 && !rangeOk(classDefsOff, classDefLimit, 32)) {
    truncated = true;
    warnings.push('DEX class_defs 区间越界，类定义解析已跳过。');
  } else {
    for (let i = 0; i < classDefLimit; i++) {
      const p = classDefsOff + i * 32;
      const classIdx = buffer.readUInt32LE(p);
      const accessFlags = buffer.readUInt32LE(p + 4);
      const superclassIdx = buffer.readUInt32LE(p + 8);
      const sourceFileIdx = buffer.readUInt32LE(p + 16);
      classDefs.push({
        name: classIdx < typeDescriptors.length ? typeDescriptors[classIdx] : null,
        superclass: superclassIdx !== 0xffffffff && superclassIdx < typeDescriptors.length ? typeDescriptors[superclassIdx] : null,
        sourceFile: sourceFileIdx !== 0xffffffff && sourceFileIdx < strings.length ? sanitizeText(strings[sourceFileIdx], 120) : null,
        accessFlags,
        accessFlagsNames: formatAccessFlags(accessFlags),
      });
    }
  }
  if (classDefsSize > classDefLimit) truncated = true;

  // 库特征扫描（仅在已解析的字符串样本内，属于 observed 而非漏洞判定）
  const hintMatches = [];
  for (const hint of LIB_HINTS) {
    const samples = new Set();
    let count = 0;
    for (const s of strings) {
      if (typeof s !== 'string' || s.length === 0) continue;
      if (hint.patterns.some((re) => re.test(s))) {
        count++;
        if (samples.size < 5) samples.add(sanitizeText(s, 160));
      }
    }
    if (count > 0) hintMatches.push({ category: hint.category, label: hint.label, matchCount: count, samples: [...samples] });
  }
  const scanTruncated = stringIdsSize > strings.length;

  return {
    version,
    fileSize,
    headerSize,
    endianTag,
    checksum: buffer.readUInt32LE(8),
    signatureSha1: buffer.subarray(12, 32).toString('hex'),
    counts: {
      stringIds: stringIdsSize,
      typeIds: typeIdsSize,
      protoIds: protoIdsSize,
      fieldIds: fieldIdsSize,
      methodIds: methodIdsSize,
      classDefs: classDefsSize,
      dataSize,
      dataOffset: dataOff,
    },
    strings: strings.slice(0, limitStrings).map((s) => sanitizeText(s, 300)),
    stringCountScanned: strings.length,
    classDescriptors: descriptorSample,
    classDescriptorCount: classDescriptorList.length,
    classDefs: classDefs.map((c) => ({
      ...c,
      name: c.name ? sanitizeText(c.name, 300) : null,
      superclass: c.superclass ? sanitizeText(c.superclass, 300) : null,
    })),
    libraryHints: hintMatches,
    obfuscation: {
      singleLetterClassRatio: Number(obfuscationRatio.toFixed(3)),
      sampleClasses: singleLetterClasses,
      totalClasses: classDescriptorList.length,
    },
    truncated,
    warnings,
    scanTruncated,
  };
}
