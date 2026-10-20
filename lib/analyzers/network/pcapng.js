// ArmorBreak - pcapng 解析（纯 node:*）
// 支持多 Section、多 Interface（IDB）、EPB 与 SPB；按 Section 字节序解析。
// 截断/畸形块返回 truncated + warnings，不抛异常（除文件头完全非法）。
import { sanitizeText } from './util.js';

export class PcapngError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'PcapngError';
    this.detail = detail;
  }
}

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_EPB = 0x00000006;
const BLOCK_SPB = 0x00000003;
const BLOCK_NRB = 0x00000004;
const BLOCK_ISB = 0x00000005;
const BLOCK_DSB = 0x0000000a;
const BYTE_ORDER_MAGIC = 0x1a2b3c4d;

export function looksLikePcapng(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return false;
  return (
    buffer[0] === 0x0a &&
    buffer[1] === 0x0d &&
    buffer[2] === 0x0d &&
    buffer[3] === 0x0a &&
    (buffer.readUInt32LE(8) === BYTE_ORDER_MAGIC || buffer.readUInt32BE(8) === BYTE_ORDER_MAGIC)
  );
}

function optionLabel(code) {
  const map = {
    1: 'opt_comment',
    2: 'if_name',
    3: 'if_description',
    4: 'if_IPv4addr',
    5: 'if_IPv6addr',
    6: 'if_MACaddr',
    7: 'if_EUIaddr',
    8: 'if_speed',
    9: 'if_tsresol',
    10: 'if_tzone',
    11: 'if_filter',
    12: 'if_os',
    13: 'if_fcslen',
    14: 'if_tsoffset',
  };
  return map[code] ?? `opt_${code}`;
}

function parseOptions(buffer, start, end, le) {
  const options = [];
  let p = start;
  const readU16 = (off) => (le ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off));
  let guard = 0;
  while (p + 4 <= end && guard++ < 256) {
    const code = readU16(p);
    const len = readU16(p + 2);
    if (code === 0 && len === 0) break;
    const valueStart = p + 4;
    const valueEnd = valueStart + len;
    if (valueEnd > end) break;
    options.push({ code, name: optionLabel(code), value: buffer.subarray(valueStart, valueEnd) });
    p = valueStart + len + ((4 - (len % 4)) % 4);
  }
  return options;
}

function findOption(options, code) {
  return options.find((o) => o.code === code)?.value ?? null;
}

/**
 * 解析 pcapng。
 * @param {Buffer} buffer
 * @param {{maxPackets?:number}} opts
 * @returns {{format:'pcapng', sections:Array, interfaces:Array, packets:Array, truncated:boolean, warnings:string[], totalBytes:number}}
 */
export function parsePcapng(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    throw new PcapngError(`pcapng 解析失败：文件仅 ${buffer ? buffer.length : 0} 字节，小于最小块长度 12 字节。`);
  }
  if (buffer.readUInt32LE(0) !== BLOCK_SHB) {
    throw new PcapngError(
      `不是 pcapng 文件：首个块类型=0x${buffer.readUInt32LE(0).toString(16)}，期望 Section Header Block 0x0a0d0d0a。`,
    );
  }
  const maxPackets = Math.max(1, Math.min(opts.maxPackets ?? 50000, 500000));
  const warnings = [];
  const sections = [];
  const interfaces = [];
  const packets = [];
  let current = null;
  let offset = 0;
  let truncated = false;
  let packetIndex = 0;

  while (offset + 12 <= buffer.length) {
    if (packets.length >= maxPackets) {
      truncated = true;
      warnings.push(`报文数超过 maxPackets=${maxPackets}，已停止解析。`);
      break;
    }
    let le;
    const blockTypeLe = buffer.readUInt32LE(offset);
    // SHB 的块类型字节序列与大端/小端无关（0x0A0D0D0A 对称）
    if (blockTypeLe === BLOCK_SHB) {
      if (offset + 12 > buffer.length) break;
      const bom = buffer.readUInt32LE(offset + 8);
      if (bom === BYTE_ORDER_MAGIC) le = true;
      else if (buffer.readUInt32BE(offset + 8) === BYTE_ORDER_MAGIC) le = false;
      else {
        throw new PcapngError(
          `pcapng SHB 字节序魔数错误（偏移 ${offset + 8} 处为 0x${bom.toString(16)}），文件损坏或不是 pcapng。`,
        );
      }
      const readU32 = (off) => (le ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off));
      const totalLength = readU32(offset + 4);
      if (totalLength < 28 || totalLength % 4 !== 0) {
        throw new PcapngError(`pcapng SHB 块长度非法（${totalLength}），文件损坏。`);
      }
      if (offset + totalLength > buffer.length) {
        truncated = true;
        warnings.push('pcapng SHB 块越界，文件被截断。');
        break;
      }
      const trailer = readU32(offset + totalLength - 4);
      if (trailer !== totalLength) {
        truncated = true;
        warnings.push(`pcapng SHB 尾部长度 ${trailer} 与头部 ${totalLength} 不一致，文件损坏/截断。`);
        break;
      }
      const readU16 = (off) => (le ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off));
      const major = readU16(offset + 12);
      const minor = readU16(offset + 14);
      const sectionLengthBig = le ? buffer.readBigInt64LE(offset + 16) : buffer.readBigInt64BE(offset + 16);
      current = {
        index: sections.length,
        endianness: le ? 'little' : 'big',
        version: `${major}.${minor}`,
        sectionLength: sectionLengthBig === -1n ? -1 : Number(sectionLengthBig),
        interfaces: [],
        packetCount: 0,
      };
      // SHB options
      const shbOptions = parseOptions(buffer, offset + 24, offset + totalLength - 4, le);
      current.options = shbOptions.map((o) => ({ code: o.code, name: o.name, size: o.value.length }));
      sections.push(current);
      offset += totalLength;
      continue;
    }
    if (!current) {
      throw new PcapngError(
        `pcapng 首个块不是 Section Header Block（0x${blockTypeLe.toString(16)}），无法确定字节序。` +
          '文件可能损坏或不是 pcapng。',
      );
    }
    const le2 = current.endianness === 'little';
    const readU32 = (off) => (le2 ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off));
    const blockType = readU32(offset);
    const totalLength = readU32(offset + 4);
    if (totalLength < 12 || totalLength % 4 !== 0) {
      truncated = true;
      warnings.push(`pcapng 块长度非法（${totalLength}，偏移 ${offset}），已停止解析。`);
      break;
    }
    if (offset + totalLength > buffer.length) {
      truncated = true;
      warnings.push(`pcapng 块越界（偏移 ${offset}，长度 ${totalLength}），文件被截断。`);
      break;
    }
    const trailer = readU32(offset + totalLength - 4);
    if (trailer !== totalLength) {
      truncated = true;
      warnings.push(`pcapng 块尾部长度不一致（${trailer} != ${totalLength}，偏移 ${offset}）。`);
      break;
    }
    const bodyStart = offset + 8;
    const bodyEnd = offset + totalLength - 4;
    const readU16 = (off) => (le2 ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off));

    if (blockType === BLOCK_IDB) {
      if (bodyEnd - bodyStart < 8) {
        warnings.push('IDB 块过短，已跳过。');
        offset += totalLength;
        continue;
      }
      const linkType = readU16(bodyStart);
      const snaplen = readU32(bodyStart + 4);
      const idbOptions = parseOptions(buffer, bodyStart + 8, bodyEnd, le2);
      let tsResolution = 1e6; // 默认微秒
      let tsOffset = 0;
      const tsresolRaw = findOption(idbOptions, 9);
      if (tsresolRaw && tsresolRaw.length >= 1) {
        const v = tsresolRaw[0];
        tsResolution = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v;
      }
      const tsoffsetRaw = findOption(idbOptions, 14);
      if (tsoffsetRaw && tsoffsetRaw.length >= 8) {
        try {
          tsOffset = le2 ? Number(tsoffsetRaw.readBigInt64LE(0)) : Number(tsoffsetRaw.readBigInt64BE(0));
        } catch {
          tsOffset = 0;
        }
      }
      const iface = {
        sectionIndex: current.index,
        id: current.interfaces.length,
        linkType,
        snaplen,
        tsResolution,
        tsOffsetSeconds: tsOffset,
        name: findOption(idbOptions, 2) ? sanitizeText(findOption(idbOptions, 2).toString('utf8'), 200) : null,
        description: findOption(idbOptions, 3) ? sanitizeText(findOption(idbOptions, 3).toString('utf8'), 300) : null,
        options: idbOptions.map((o) => ({ code: o.code, name: o.name, size: o.value.length })),
      };
      current.interfaces.push(iface);
      interfaces.push(iface);
      offset += totalLength;
      continue;
    }

    if (blockType === BLOCK_EPB) {
      if (bodyEnd - bodyStart < 20) {
        warnings.push('EPB 块过短，已跳过。');
        offset += totalLength;
        continue;
      }
      const interfaceId = readU32(bodyStart);
      const tsHigh = readU32(bodyStart + 4);
      const tsLow = readU32(bodyStart + 8);
      const caplen = readU32(bodyStart + 12);
      const origlen = readU32(bodyStart + 16);
      const dataStart = bodyStart + 20;
      if (dataStart + caplen > bodyEnd) {
        truncated = true;
        warnings.push(`EPB 报文声明 ${caplen} 字节超出块边界，已停止解析。`);
        break;
      }
      const iface = current.interfaces[interfaceId];
      if (!iface) {
        warnings.push(`EPB 引用未知接口 ${interfaceId}（section ${current.index}），已跳过。`);
        offset += totalLength;
        continue;
      }
      const ticks = tsHigh * 4294967296 + tsLow;
      const tsSeconds = ticks / iface.tsResolution + iface.tsOffsetSeconds;
      packets.push({
        index: packetIndex++,
        sectionIndex: current.index,
        interfaceId,
        linkType: iface.linkType,
        tsSeconds,
        caplen,
        origlen,
        data: buffer.subarray(dataStart, dataStart + caplen),
      });
      current.packetCount++;
      offset += totalLength;
      continue;
    }

    if (blockType === BLOCK_SPB) {
      if (bodyEnd - bodyStart < 4) {
        offset += totalLength;
        continue;
      }
      const origlen = readU32(bodyStart);
      const iface = current.interfaces[0];
      if (!iface) {
        warnings.push('SPB 出现但 section 无接口，已跳过。');
        offset += totalLength;
        continue;
      }
      const dataStart = bodyStart + 4;
      const caplen = Math.min(origlen, bodyEnd - dataStart);
      packets.push({
        index: packetIndex++,
        sectionIndex: current.index,
        interfaceId: 0,
        linkType: iface.linkType,
        tsSeconds: null,
        caplen,
        origlen,
        data: buffer.subarray(dataStart, dataStart + caplen),
      });
      current.packetCount++;
      offset += totalLength;
      continue;
    }

    // NRB / ISB / DSB / 自定义块：跳过（保留计数）
    if (blockType === BLOCK_NRB) current.nameResolutionBlocks = (current.nameResolutionBlocks || 0) + 1;
    if (blockType === BLOCK_ISB) current.statisticsBlocks = (current.statisticsBlocks || 0) + 1;
    if (blockType === BLOCK_DSB) current.decryptionSecretsBlocks = (current.decryptionSecretsBlocks || 0) + 1;
    offset += totalLength;
  }
  if (offset < buffer.length && buffer.length - offset > 0) {
    truncated = true;
    warnings.push(`pcapng 尾部有 ${buffer.length - offset} 字节未解析（不完整块）。`);
  }
  return {
    format: 'pcapng',
    sections,
    interfaces,
    packets,
    truncated,
    warnings,
    totalBytes: buffer.length,
  };
}
