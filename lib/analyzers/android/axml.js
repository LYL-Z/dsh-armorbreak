// ArmorBreak - Android 二进制 XML（AXML）解析（纯 node:*）
// 实现分块遍历：文件头 0x0003、字符串池 0x0001、资源映射 0x0180、命名空间/元素起止 0x0100-0x0104。
// 不追求兼容所有厂商怪癖：遇到未知块给出可操作 Error；截断给出 warnings + truncated 标记。
import { sanitizeText } from './util.js';

export const AXML_FILE = 0x0003;
export const RES_STRING_POOL = 0x0001;
export const RES_XML_START_NAMESPACE = 0x0100;
export const RES_XML_END_NAMESPACE = 0x0101;
export const RES_XML_START_ELEMENT = 0x0102;
export const RES_XML_END_ELEMENT = 0x0103;
export const RES_XML_CDATA = 0x0104;
export const RES_XML_RESOURCE_MAP = 0x0180;

// Res_value dataType（frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h）
export const TYPE_NULL = 0x00;
export const TYPE_REFERENCE = 0x01;
export const TYPE_ATTRIBUTE = 0x02;
export const TYPE_STRING = 0x03;
export const TYPE_FLOAT = 0x04;
export const TYPE_DIMENSION = 0x05;
export const TYPE_FRACTION = 0x06;
export const TYPE_DYNAMIC_REFERENCE = 0x07;
export const TYPE_DYNAMIC_ATTRIBUTE = 0x08;
export const TYPE_INT_DEC = 0x10;
export const TYPE_INT_HEX = 0x11;
export const TYPE_INT_BOOLEAN = 0x12;
export const TYPE_INT_COLOR_ARGB8 = 0x1c;
export const TYPE_INT_COLOR_RGB8 = 0x1d;
export const TYPE_INT_COLOR_ARGB4 = 0x1e;
export const TYPE_INT_COLOR_RGB4 = 0x1f;

const KNOWN_CHUNKS = new Set([
  RES_STRING_POOL,
  RES_XML_START_NAMESPACE,
  RES_XML_END_NAMESPACE,
  RES_XML_START_ELEMENT,
  RES_XML_END_ELEMENT,
  RES_XML_CDATA,
  RES_XML_RESOURCE_MAP,
]);

export class AxmlError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'AxmlError';
    this.detail = detail;
  }
}

function chunkTypeName(type) {
  switch (type) {
    case RES_STRING_POOL: return 'STRING_POOL';
    case RES_XML_START_NAMESPACE: return 'START_NAMESPACE';
    case RES_XML_END_NAMESPACE: return 'END_NAMESPACE';
    case RES_XML_START_ELEMENT: return 'START_ELEMENT';
    case RES_XML_END_ELEMENT: return 'END_ELEMENT';
    case RES_XML_CDATA: return 'CDATA';
    case RES_XML_RESOURCE_MAP: return 'RESOURCE_MAP';
    default: return `0x${type.toString(16).padStart(4, '0')}`;
  }
}

/** 解析字符串池块；返回 {strings, count, utf8, truncated}。 */
function parseStringPool(buffer, chunk, warnings) {
  const { start, headerSize, size } = chunk;
  if (headerSize < 28) {
    throw new AxmlError(`AXML 字符串池头长度异常（${headerSize} < 28），文件损坏。`);
  }
  const end = start + size;
  if (end > buffer.length) {
    throw new AxmlError(
      `AXML 字符串池越界：块 [${start}, ${end}) 超出文件长度 ${buffer.length}，文件被截断。`,
    );
  }
  const stringCount = buffer.readUInt32LE(start + 8);
  const styleCount = buffer.readUInt32LE(start + 12);
  const flags = buffer.readUInt32LE(start + 16);
  const stringsStart = buffer.readUInt32LE(start + 20);
  const utf8 = (flags & 0x100) !== 0;
  if (stringCount > 200000) {
    throw new AxmlError(`AXML 字符串池声明 ${stringCount} 条字符串，超出合理上限 200000，疑似恶意文件。`);
  }
  if (styleCount !== 0) warnings.push(`字符串池含 ${styleCount} 个 style span（已忽略样式，仅解析文本）。`);
  const offsetsBase = start + headerSize;
  if (offsetsBase + stringCount * 4 > end) {
    throw new AxmlError('AXML 字符串池偏移数组越界，文件损坏或被截断。');
  }
  const dataBase = start + stringsStart;
  if (stringsStart < headerSize || dataBase > end) {
    throw new AxmlError(`AXML 字符串池数据区偏移非法（stringsStart=${stringsStart}）。`);
  }
  let badOffsets = 0;
  const strings = new Array(stringCount);
  for (let i = 0; i < stringCount; i++) {
    const rel = buffer.readUInt32LE(offsetsBase + i * 4);
    const abs = dataBase + rel;
    if (abs < dataBase || abs >= end) {
      strings[i] = '';
      badOffsets++;
      continue;
    }
    strings[i] = decodePoolString(buffer, abs, end, utf8);
  }
  if (badOffsets > 0) warnings.push(`${badOffsets} 个字符串偏移越界，已置空。`);
  return { strings, count: stringCount, utf8, end };
}

function decodeLength8(buffer, pos, end) {
  if (pos >= end) return { length: 0, next: pos };
  const b0 = buffer[pos];
  if (b0 & 0x80) {
    if (pos + 1 >= end) return { length: 0, next: end };
    return { length: ((b0 & 0x7f) << 8) | buffer[pos + 1], next: pos + 2 };
  }
  return { length: b0, next: pos + 1 };
}

function decodeLength16(buffer, pos, end) {
  if (pos + 2 > end) return { length: 0, next: end };
  const b0 = buffer.readUInt16LE(pos);
  if (b0 & 0x8000) {
    if (pos + 4 > end) return { length: 0, next: end };
    const b1 = buffer.readUInt16LE(pos + 2);
    return { length: ((b0 & 0x7fff) << 16) | b1, next: pos + 4 };
  }
  return { length: b0, next: pos + 2 };
}

/** 解码单条池字符串；对 UTF-8 池兼容 "u16len+u8len" 双长度写法。 */
function decodePoolString(buffer, start, end, utf8) {
  try {
    if (utf8) {
      const first = decodeLength8(buffer, start, end);
      const afterFirst = first.next;
      // AAPT2 UTF-8 池为 [UTF-16 长度][UTF-8 字节长度][数据][NUL]；部分工具只写一个长度。
      const second = decodeLength8(buffer, afterFirst, end);
      const dataStart = second.next;
      if (dataStart + second.length <= end && buffer[dataStart + second.length] === 0x00) {
        return buffer.subarray(dataStart, dataStart + second.length).toString('utf8');
      }
      // 回退：单长度写法，数据紧跟第一个长度，扫描到 NUL（受池块边界限制）
      let q = afterFirst;
      while (q < end && buffer[q] !== 0x00) q++;
      return buffer.subarray(afterFirst, q).toString('utf8');
    }
    const first = decodeLength16(buffer, start, end);
    const charLen = first.length;
    const sliceStart = first.next;
    const byteLen = Math.min(charLen * 2, end - sliceStart);
    return buffer.subarray(sliceStart, sliceStart + byteLen).toString('utf16le');
  } catch {
    return '';
  }
}

/** 解析 ResXMLTree 节点公共头（lineNumber + comment），返回 body 起始偏移。 */
function nodeBodyOffset(chunk) {
  return chunk.start + chunk.headerSize;
}

function readTypedValue(buffer, pos) {
  // Res_value: size u16, res0 u8, dataType u8, data u32
  const valueSize = buffer.readUInt16LE(pos);
  const dataType = buffer.readUInt8(pos + 3);
  const data = buffer.readUInt32LE(pos + 4);
  return { valueSize, dataType, data };
}

function decodeAttrValue(buffer, attr, strings, resourceMap) {
  const { dataType, data, rawValue } = attr;
  const strAt = (idx) =>
    Number.isInteger(idx) && idx >= 0 && idx < strings.length ? strings[idx] : null;
  let value = null;
  let kind = 'raw';
  switch (dataType) {
    case TYPE_STRING:
      value = strAt(data);
      kind = 'string';
      break;
    case TYPE_INT_BOOLEAN:
      value = data !== 0;
      kind = 'boolean';
      break;
    case TYPE_INT_DEC:
      value = data | 0;
      kind = 'int';
      break;
    case TYPE_INT_HEX:
      value = data >>> 0;
      kind = 'hex';
      break;
    case TYPE_FLOAT:
      value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(data, 0);
      value = value.readFloatLE(0);
      kind = 'float';
      break;
    case TYPE_REFERENCE:
    case TYPE_DYNAMIC_REFERENCE:
      value = `@0x${data.toString(16).padStart(8, '0')}`;
      kind = 'reference';
      break;
    case TYPE_ATTRIBUTE:
    case TYPE_DYNAMIC_ATTRIBUTE:
      value = `?0x${data.toString(16).padStart(8, '0')}`;
      kind = 'attribute';
      break;
    case TYPE_INT_COLOR_ARGB8:
    case TYPE_INT_COLOR_RGB8:
    case TYPE_INT_COLOR_ARGB4:
    case TYPE_INT_COLOR_RGB4:
      value = `#${data.toString(16).padStart(8, '0')}`;
      kind = 'color';
      break;
    case TYPE_DIMENSION:
    case TYPE_FRACTION:
      value = data >>> 0;
      kind = dataType === TYPE_DIMENSION ? 'dimension-raw' : 'fraction-raw';
      break;
    case TYPE_NULL:
      value = null;
      kind = 'null';
      break;
    default:
      value = data >>> 0;
      kind = 'raw-int';
      break;
  }
  // 原始字符串引用优先用于展示（如 android:name 的原始值）
  const raw = rawValue !== 0xffffffff ? strAt(rawValue) : null;
  const mappedResource = Number.isInteger(attr.nameIndex) && attr.nameIndex < resourceMap.length
    ? resourceMap[attr.nameIndex]
    : 0;
  const resourceId = mappedResource ? mappedResource >>> 0 : null;
  return { kind, value, raw, resourceId };
}

/**
 * 解析二进制 AndroidManifest.xml。
 * @param {Buffer} buffer
 * @param {{maxElements?:number, maxStrings?:number, maxDepth?:number}} opts
 * @returns {{root:object|null, elementCount:number, namespaceCount:number, stringCount:number, utf8:boolean, resourceMapSize:number, truncated:boolean, warnings:string[]}}
 */
export function parseAxml(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
    throw new AxmlError(
      `AXML 解析失败：输入仅 ${buffer ? buffer.length : 0} 字节，小于 8 字节 AXML 文件头。` +
        '请确认目标包含二进制 AndroidManifest.xml。',
    );
  }
  const maxElements = Math.max(1, Math.min(opts.maxElements ?? 5000, 200000));
  const maxDepth = Math.max(1, Math.min(opts.maxDepth ?? 128, 1000));
  const warnings = [];
  let truncated = false;

  const fileType = buffer.readUInt16LE(0);
  const fileHeaderSize = buffer.readUInt16LE(2);
  const fileSize = buffer.readUInt32LE(4);
  if (fileType !== AXML_FILE) {
    throw new AxmlError(
      `不是 Android 二进制 XML（AXML）：文件头 chunkType=0x${fileType.toString(16)}，期望 0x0003。` +
        '如果这是纯文本 XML，请将文件改为 .xml 文本格式；APK 内的 AndroidManifest.xml 应为 AXML。',
    );
  }
  if (fileHeaderSize < 8) throw new AxmlError(`AXML 文件头长度非法（${fileHeaderSize} < 8）。`);
  if (fileSize > buffer.length) {
    truncated = true;
    warnings.push(`AXML 声明大小 ${fileSize} 字节，实际仅 ${buffer.length} 字节，已按实际边界解析。`);
  }
  const end = Math.min(fileSize, buffer.length);
  if (end <= fileHeaderSize) throw new AxmlError('AXML 文件没有子块（只有文件头），文件损坏。');

  let offset = fileHeaderSize;
  let strings = [];
  let poolUtf8 = false;
  let resourceMap = [];
  let elementCount = 0;
  const namespaceStack = [];
  const namespaces = [];
  const stack = [];
  let root = null;

  while (offset + 8 <= end) {
    const type = buffer.readUInt16LE(offset);
    const headerSize = buffer.readUInt16LE(offset + 2);
    const size = buffer.readUInt32LE(offset + 4);
    if (size < 8 || headerSize < 8 || headerSize > size) {
      throw new AxmlError(
        `AXML 块头非法（偏移 ${offset}，type=0x${type.toString(16)}，headerSize=${headerSize}，size=${size}）。` +
          '文件损坏或不是标准 AXML。',
      );
    }
    if (offset + size > end) {
      truncated = true;
      warnings.push(`AXML 块 0x${type.toString(16)} 声明大小越界，已停止解析（截断）。`);
      break;
    }
    const chunk = { type, start: offset, headerSize, size };

    if (!KNOWN_CHUNKS.has(type)) {
      throw new AxmlError(
        `AXML 含不支持的块类型 ${chunkTypeName(type)}（偏移 ${offset}）。` +
          '离线解析器仅支持标准 XML 块；请用 aapt2 dump xmltree 导出文本后分析，或提供标准 APK。',
      );
    }

    switch (type) {
      case RES_STRING_POOL: {
        if (strings.length > 0) warnings.push('AXML 含多个字符串池，已使用最后一个覆盖名称解析。');
        const pool = parseStringPool(buffer, chunk, warnings);
        strings = pool.strings;
        poolUtf8 = pool.utf8;
        break;
      }
      case RES_XML_RESOURCE_MAP: {
        const count = Math.floor((size - headerSize) / 4);
        resourceMap = new Array(count);
        for (let i = 0; i < count; i++) resourceMap[i] = buffer.readUInt32LE(offset + headerSize + i * 4);
        break;
      }
      case RES_XML_START_NAMESPACE: {
        if (headerSize < 16) throw new AxmlError('AXML START_NAMESPACE 节点头长度非法。');
        const prefixIdx = buffer.readUInt32LE(offset + headerSize);
        const uriIdx = buffer.readUInt32LE(offset + headerSize + 4);
        const prefix = prefixIdx < strings.length ? strings[prefixIdx] : '';
        const uri = uriIdx < strings.length ? strings[uriIdx] : '';
        namespaceStack.push({ prefix, uri });
        namespaces.push({ prefix, uri });
        break;
      }
      case RES_XML_END_NAMESPACE: {
        namespaceStack.pop();
        break;
      }
      case RES_XML_START_ELEMENT: {
        elementCount++;
        if (elementCount > maxElements) {
          truncated = true;
          warnings.push(`元素数量超过 maxElements=${maxElements}，已停止解析。`);
          offset = end;
          break;
        }
        if (headerSize < 16) throw new AxmlError('AXML START_ELEMENT 节点头长度非法。');
        const body = nodeBodyOffset(chunk);
        if (body + 20 > offset + size) throw new AxmlError('AXML START_ELEMENT 结构越界，文件截断。');
        const nsIdx = buffer.readUInt32LE(body);
        const nameIdx = buffer.readUInt32LE(body + 4);
        const attributeStart = buffer.readUInt16LE(body + 8);
        const attributeSize = buffer.readUInt16LE(body + 10);
        const attributeCount = buffer.readUInt16LE(body + 12);
        if (attributeSize !== 0 && attributeSize < 20) {
          throw new AxmlError(`AXML 属性步长非法（${attributeSize} < 20），文件损坏。`);
        }
        const stride = attributeSize || 20;
        const attrBase = body + attributeStart;
        if (attributeCount > 0 && attrBase + attributeCount * stride > offset + size) {
          truncated = true;
          warnings.push('AXML 属性数组越界，已按可用部分解析。');
        }
        const attributes = [];
        const attrLimit = Math.min(attributeCount, Math.floor((offset + size - attrBase) / stride));
        for (let i = 0; i < attrLimit; i++) {
          const p = attrBase + i * stride;
          const attrNsIdx = buffer.readUInt32LE(p);
          const attrNameIdx = buffer.readUInt32LE(p + 4);
          const rawValue = buffer.readUInt32LE(p + 8);
          const typed = readTypedValue(buffer, p + 12);
          const attrNs = attrNsIdx !== 0xffffffff && attrNsIdx < strings.length ? strings[attrNsIdx] : null;
          const attrName = attrNameIdx < strings.length ? strings[attrNameIdx] : null;
          const decoded = decodeAttrValue(
            buffer,
            { rawValue, ...typed, nameIndex: attrNameIdx },
            strings,
            resourceMap,
          );
          attributes.push({
            ns: attrNs,
            name: attrName,
            rawValue: decoded.raw,
            type: typed.dataType,
            data: typed.data,
            value: decoded.value,
            kind: decoded.kind,
            resourceId: decoded.resourceId,
          });
        }
        const node = {
          type: 'element',
          name: nameIdx < strings.length ? strings[nameIdx] : null,
          ns: nsIdx !== 0xffffffff && nsIdx < strings.length ? strings[nsIdx] : null,
          attributes,
          children: [],
          lineNumber: buffer.readUInt32LE(offset + 8),
        };
        if (stack.length > 0) {
          stack[stack.length - 1].children.push(node);
        } else if (root === null) {
          root = node;
        } else {
          warnings.push('AXML 存在多个根元素，仅保留第一个。');
        }
        stack.push(node);
        if (stack.length > maxDepth) {
          throw new AxmlError(`AXML 元素嵌套深度超过 ${maxDepth}，疑似恶意/损坏文件。`);
        }
        break;
      }
      case RES_XML_END_ELEMENT: {
        if (stack.length === 0) {
          warnings.push('AXML 出现多余的 END_ELEMENT，已忽略。');
        } else {
          stack.pop();
        }
        break;
      }
      case RES_XML_CDATA: {
        if (headerSize >= 16 && offset + headerSize + 8 <= end) {
          const dataIdx = buffer.readUInt32LE(offset + headerSize);
          const text = dataIdx < strings.length ? strings[dataIdx] : '';
          if (stack.length > 0) stack[stack.length - 1].children.push({ type: 'cdata', text });
        }
        break;
      }
      default:
        break;
    }
    offset += size;
  }
  if (stack.length > 0) {
    truncated = true;
    warnings.push(`AXML 结束时仍有 ${stack.length} 个未闭合元素。`);
  }
  if (offset < end && end - offset > 0) {
    // 尾部不足 8 字节视为对齐填充
    if (end - offset >= 8) warnings.push(`AXML 尾部有 ${end - offset} 字节未解析数据。`);
  }
  return {
    root,
    elementCount,
    namespaceCount: namespaces.length,
    namespaces,
    stringCount: strings.length,
    utf8: poolUtf8,
    resourceMapSize: resourceMap.length,
    truncated,
    warnings,
  };
}

/** 深度优先查找元素。 */
export function findElements(root, predicate) {
  const out = [];
  const visit = (node) => {
    if (node.type === 'element' && predicate(node)) out.push(node);
    for (const child of node.children || []) visit(child);
  };
  if (root) visit(root);
  return out;
}

/** 取元素属性（按本地名，忽略命名空间；Android 属性均在此列）。 */
export function attr(node, name) {
  if (!node || !Array.isArray(node.attributes)) return undefined;
  return node.attributes.find((a) => a.name === name);
}

/** 取属性原始字符串值（字符串引用优先）；无则返回 null。 */
export function attrString(node, name) {
  const a = attr(node, name);
  if (!a) return null;
  if (typeof a.value === 'string') return sanitizeText(a.value, 300);
  if (typeof a.raw === 'string') return sanitizeText(a.raw, 300);
  return null;
}

/** 取属性布尔值；无则 null。 */
export function attrBool(node, name) {
  const a = attr(node, name);
  if (!a) return null;
  if (typeof a.value === 'boolean') return a.value;
  if (a.raw === 'true') return true;
  if (a.raw === 'false') return false;
  if (typeof a.raw === 'string') return a.raw === 'true';
  return null;
}

/** 取属性整数；无则 null。 */
export function attrInt(node, name) {
  const a = attr(node, name);
  if (!a) return null;
  if (typeof a.value === 'number') return a.value | 0;
  if (typeof a.raw === 'string' && /^-?\d+$/.test(a.raw)) return parseInt(a.raw, 10);
  return null;
}

export { chunkTypeName };
