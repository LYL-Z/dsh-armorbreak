// ArmorBreak - 抓包统一加载与解码（classic pcap + pcapng -> 统一报文模型）
import { parseClassicPcap, looksLikePcap } from './pcap.js';
import { parsePcapng, looksLikePcapng } from './pcapng.js';
import { decodePacket, linkTypeName } from './packets.js';
import { isoTime, limitOf, requireBuffer } from './util.js';

export const SUPPORTED_CAPTURE_FORMATS = ['pcap', 'pcapng'];

export function detectCaptureFormat(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) return null;
  if (looksLikePcap(buffer)) return 'pcap';
  if (looksLikePcapng(buffer)) return 'pcapng';
  return null;
}

/**
 * 加载并解码抓包。
 * @param {object} input run(input)
 * @param {{maxPackets?:number}} options
 * @param {{maxItems:number, maxBytes:number}} limits
 */
export function loadCapture(input, options, limits) {
  const buffer = requireBuffer(input, 'network.pcap');
  const format = detectCaptureFormat(buffer);
  if (!format) {
    const head = buffer.subarray(0, Math.min(buffer.length, 8)).toString('hex');
    throw new Error(
      `无法识别的抓包格式：文件头 ${head} 既不是经典 pcap（a1b2c3d4 / d4c3b2a1 / a1b23c4d），也不是 pcapng（0a0d0d0a）。` +
        '请提供 tcpdump/Wireshark 导出的 .pcap 或 .pcapng；如果是文本日志，请先用文本类 capability 分析。',
    );
  }
  const maxPackets = limitOf(options.maxPackets, Math.min(limits.maxItems * 100, 50000), 1, 500000);
  const decoded = [];
  const decodeErrors = [];
  const unsupportedLinkTypes = new Map();
  let parsed;
  if (format === 'pcap') {
    parsed = parseClassicPcap(buffer, { maxPackets });
    for (const raw of parsed.packets) {
      const packet = decodePacket(parsed.linkType, raw.data);
      if (!packet.ok) {
        if (packet.unsupportedLinkType) unsupportedLinkTypes.set(parsed.linkType, (unsupportedLinkTypes.get(parsed.linkType) || 0) + 1);
        if (decodeErrors.length < 10) decodeErrors.push({ index: raw.index, reason: packet.reason });
        continue;
      }
      decoded.push({ ...packet, index: raw.index, tsSeconds: raw.tsSeconds, caplen: raw.caplen, origlen: raw.origlen });
    }
  } else {
    parsed = parsePcapng(buffer, { maxPackets });
    for (const raw of parsed.packets) {
      const packet = decodePacket(raw.linkType, raw.data);
      if (!packet.ok) {
        if (packet.unsupportedLinkType) unsupportedLinkTypes.set(raw.linkType, (unsupportedLinkTypes.get(raw.linkType) || 0) + 1);
        if (decodeErrors.length < 10) decodeErrors.push({ index: raw.index, reason: packet.reason });
        continue;
      }
      decoded.push({ ...packet, index: raw.index, tsSeconds: raw.tsSeconds, caplen: raw.caplen, origlen: raw.origlen });
    }
  }

  const linkTypeCounts = new Map();
  for (const packet of decoded) linkTypeCounts.set(packet.linkType, (linkTypeCounts.get(packet.linkType) || 0) + 1);
  for (const [linkType, count] of unsupportedLinkTypes) linkTypeCounts.set(linkType, (linkTypeCounts.get(linkType) || 0) + count);
  const linkTypes = [...linkTypeCounts.entries()]
    .map(([linkType, count]) => ({ linkType, name: linkTypeName(linkType), packetCount: count }))
    .sort((a, b) => a.linkType - b.linkType);

  let firstTs = null;
  let lastTs = null;
  let capturedBytes = 0;
  let originalBytes = 0;
  for (const packet of decoded) {
    if (Number.isFinite(packet.tsSeconds)) {
      if (firstTs === null || packet.tsSeconds < firstTs) firstTs = packet.tsSeconds;
      if (lastTs === null || packet.tsSeconds > lastTs) lastTs = packet.tsSeconds;
    }
    capturedBytes += packet.caplen ?? 0;
    originalBytes += packet.origlen ?? 0;
  }
  const duration = firstTs !== null && lastTs !== null ? Number((lastTs - firstTs).toFixed(6)) : null;
  return {
    format,
    packets: decoded,
    rawPacketCount: parsed.packets.length,
    decodedCount: decoded.length,
    decodeErrors,
    unsupportedLinkTypes: [...unsupportedLinkTypes.entries()].map(([linkType, count]) => ({ linkType, name: linkTypeName(linkType), count })),
    linkTypes,
    interfaces: parsed.interfaces ?? (parsed.linkType !== undefined ? [{ linkType: parsed.linkType, name: linkTypeName(parsed.linkType) }] : []),
    sections: parsed.sections ?? null,
    endianness: parsed.endianness ?? null,
    nanosecond: parsed.nanosecond ?? false,
    snaplen: parsed.snaplen ?? null,
    firstTs,
    lastTs,
    firstPacketIso: isoTime(firstTs),
    lastPacketIso: isoTime(lastTs),
    durationSeconds: duration,
    capturedBytes,
    originalBytes,
    truncated: Boolean(parsed.truncated),
    warnings: parsed.warnings.slice(0, 30),
    totalBytes: buffer.length,
    maxPackets,
  };
}

/** 协议直方图（tcp/udp/icmp/...）。 */
export function protocolHistogram(packets) {
  const counts = new Map();
  for (const packet of packets) counts.set(packet.proto, (counts.get(packet.proto) || 0) + 1);
  return [...counts.entries()]
    .map(([proto, count]) => ({ proto, count }))
    .sort((a, b) => b.count - a.count || a.proto.localeCompare(b.proto));
}

/** IP 版本分布。 */
export function ipVersionHistogram(packets) {
  const counts = new Map();
  for (const packet of packets) {
    const key = packet.ipVersion === null || packet.ipVersion === undefined ? 'unknown' : `IPv${packet.ipVersion}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].map(([version, count]) => ({ version, count })).sort((a, b) => a.version.localeCompare(b.version));
}

/** 顶层交谈方统计（按字节数降序）。 */
export function topTalkers(packets, limit = 10) {
  const map = new Map();
  for (const packet of packets) {
    if (!packet.src) continue;
    for (const key of [packet.src, packet.dst]) {
      if (!key) continue;
      const entry = map.get(key) || { ip: key, packets: 0, bytes: 0 };
      entry.packets += 1;
      entry.bytes += packet.payloadLength || 0;
      map.set(key, entry);
    }
  }
  return [...map.values()].sort((a, b) => b.bytes - a.bytes || b.packets - a.packets || a.ip.localeCompare(b.ip)).slice(0, limit);
}

/** 传输层端口统计（serverSide=true 统计目的端口，否则统计源端口）。 */
export function portHistogram(packets, { serverSide = true, limit = 15 } = {}) {
  const map = new Map();
  for (const packet of packets) {
    if (packet.proto !== 'tcp' && packet.proto !== 'udp') continue;
    const port = serverSide ? packet.dstPort : packet.srcPort;
    if (!Number.isInteger(port)) continue;
    map.set(port, (map.get(port) || 0) + 1);
  }
  return [...map.entries()]
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count || a.port - b.port)
    .slice(0, limit);
}
