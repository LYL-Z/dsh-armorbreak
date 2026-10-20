// ArmorBreak - 经典 pcap 解析（纯 node:*）
// 支持大/小端、微秒/纳秒时间戳魔数；有界读取，截断抓包返回 truncated 标记而非抛错。
export class PcapError extends Error {
  constructor(message, detail = null) {
    super(message);
    this.name = 'PcapError';
    this.detail = detail;
  }
}

/**
 * 通过 magic 字节判断文件字节序与时间戳精度。
 * 标准约定：文件头 4 字节按文件自身字节序写成 0xa1b2c3d4。
 * 因此内存中字节 a1 b2 c3 d4 表示大端文件；d4 c3 b2 a1 表示小端文件。
 */
function detectMagic(buffer) {
  const b0 = buffer[0];
  const b1 = buffer[1];
  const b2 = buffer[2];
  const b3 = buffer[3];
  if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0xc3 && b3 === 0xd4) return { endianness: 'big', nano: false };
  if (b0 === 0xd4 && b1 === 0xc3 && b2 === 0xb2 && b3 === 0xa1) return { endianness: 'little', nano: false };
  if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0x3c && b3 === 0x4d) return { endianness: 'big', nano: true };
  if (b0 === 0x4d && b1 === 0x3c && b2 === 0xb2 && b3 === 0xa1) return { endianness: 'little', nano: true };
  return null;
}

export function looksLikePcap(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 4 && detectMagic(buffer) !== null;
}

/**
 * 解析经典 pcap。
 * @param {Buffer} buffer
 * @param {{maxPackets?:number}} opts
 * @returns {{format:'pcap', endianness:'big'|'little', nanosecond:boolean, version:{major:number,minor:number}, snaplen:number, linkType:number, packets:Array<{index,tsSeconds,tsFraction,denominator,caplen,origlen,data}>, truncated:boolean, warnings:string[], totalBytes:number}}
 */
export function parseClassicPcap(buffer, opts = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 24) {
    throw new PcapError(
      `pcap 解析失败：文件仅 ${buffer ? buffer.length : 0} 字节，小于经典 pcap 最小头长度 24 字节。`,
    );
  }
  const magic = detectMagic(buffer);
  if (!magic) {
    throw new PcapError(
      `不是经典 pcap 文件：magic=${buffer.subarray(0, 4).toString('hex')}，期望 a1b2c3d4/d4c3b2a1（微秒）或 a1b23c4d/4d3cb2a1（纳秒）。` +
        '请确认抓包格式；pcapng 以 0a0d0d0a 开头。',
    );
  }
  const le = magic.endianness === 'little';
  const u16 = (off) => (le ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off));
  const u32 = (off) => (le ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off));
  const version = { major: u16(4), minor: u16(6) };
  const thiszone = le ? buffer.readInt32LE(8) : buffer.readInt32BE(8);
  const sigfigs = u32(12);
  const snaplen = u32(16);
  let linkType = u32(20);
  // 高 16 位可能携带 FCS 等标志位（pcap 扩展），低 28 位是链路类型
  const linkTypeRaw = linkType;
  linkType = linkType & 0x0fffffff;
  const warnings = [];
  if (version.major !== 2 || version.minor !== 4) warnings.push(`pcap 版本 ${version.major}.${version.minor} 非标准 2.4，按 2.4 解析。`);
  if (snaplen > 1024 * 1024 * 256) warnings.push(`snaplen=${snaplen} 异常大，可能存在损坏。`);
  const maxPackets = Math.max(1, Math.min(opts.maxPackets ?? 50000, 500000));
  const denominator = magic.nano ? 1e9 : 1e6;
  const packets = [];
  let offset = 24;
  let truncated = false;
  let index = 0;
  while (offset + 16 <= buffer.length) {
    if (packets.length >= maxPackets) {
      truncated = true;
      warnings.push(`报文数超过 maxPackets=${maxPackets}，已停止解析。`);
      break;
    }
    const tsSec = u32(offset);
    const tsFrac = u32(offset + 4);
    const caplen = u32(offset + 8);
    const origlen = u32(offset + 12);
    const dataStart = offset + 16;
    if (caplen > snaplen && snaplen > 0) {
      warnings.push(`第 ${index} 个报文 caplen=${caplen} 超过 snaplen=${snaplen}（已按实际数据解析）。`);
    }
    if (dataStart + caplen > buffer.length) {
      truncated = true;
      warnings.push(`第 ${index} 个报文声明 ${caplen} 字节但仅剩 ${buffer.length - dataStart} 字节，抓包被截断。`);
      break;
    }
    packets.push({
      index: index++,
      tsSeconds: tsSec + tsFrac / denominator,
      tsSec,
      tsFraction: tsFrac,
      denominator,
      caplen,
      origlen,
      data: buffer.subarray(dataStart, dataStart + caplen),
    });
    offset = dataStart + caplen;
  }
  if (offset < buffer.length && buffer.length - offset > 0) {
    // 尾部不足 16 字节：可能是截断的记录头
    if (buffer.length - offset > 0) {
      truncated = true;
      warnings.push(`抓包尾部有 ${buffer.length - offset} 字节不完整记录头。`);
    }
  }
  return {
    format: 'pcap',
    endianness: magic.endianness,
    nanosecond: magic.nano,
    version,
    thiszone,
    sigfigs,
    snaplen,
    linkType,
    linkTypeRaw,
    packets,
    truncated,
    warnings,
    totalBytes: buffer.length,
  };
}
