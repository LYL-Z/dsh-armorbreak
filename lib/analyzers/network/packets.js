// ArmorBreak - 链路层/网络层/传输层报文解码（纯 node:*）
// 支持链路类型：Ethernet(1)、raw IP(101/12/228/229)、Linux SLL(113)、NULL/LOOP(0/108)。
// 单包解析失败返回 {ok:false}，由上层计数；不因畸形单包抛异常。
import { formatIpv4, formatIpv6 } from './util.js';

export const LINKTYPE_NULL = 0;
export const LINKTYPE_ETHERNET = 1;
export const LINKTYPE_RAW = 101;
export const LINKTYPE_LOOP = 108;
export const LINKTYPE_LINUX_SLL = 113;
export const LINKTYPE_RAW_BSD = 12;
export const LINKTYPE_IPV4 = 228;
export const LINKTYPE_IPV6 = 229;
export const LINKTYPE_LINUX_SLL2 = 276;

const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;
const ETHERTYPE_ARP = 0x0806;
const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_QINQ = 0x88a8;
const ETHERTYPE_VLAN_9100 = 0x9100;

const LINKTYPE_NAMES = new Map([
  [0, 'NULL'],
  [1, 'Ethernet'],
  [12, 'RAW(BSD)'],
  [101, 'RAW'],
  [105, '802.11'],
  [108, 'LOOP'],
  [113, 'Linux SLL'],
  [228, 'IPv4'],
  [229, 'IPv6'],
  [276, 'Linux SLL2'],
]);

export function linkTypeName(linkType) {
  return LINKTYPE_NAMES.get(linkType) ?? `linktype-${linkType}`;
}

export function isSupportedLinkType(linkType) {
  return (
    linkType === LINKTYPE_NULL ||
    linkType === LINKTYPE_ETHERNET ||
    linkType === LINKTYPE_RAW ||
    linkType === LINKTYPE_LOOP ||
    linkType === LINKTYPE_LINUX_SLL ||
    linkType === LINKTYPE_RAW_BSD ||
    linkType === LINKTYPE_IPV4 ||
    linkType === LINKTYPE_IPV6
  );
}

// ---------------------------------------------------------------------------
// 传输层
// ---------------------------------------------------------------------------

export function parseTcp(buf, ctx = {}) {
  if (buf.length < 20) return { ok: false, reason: 'TCP 头不足 20 字节' };
  const dataOffset = (buf[12] >> 4) * 4;
  if (dataOffset < 20) return { ok: false, reason: `TCP dataOffset=${dataOffset} < 20` };
  const flagsByte = buf[13];
  const flags = {
    fin: (flagsByte & 0x01) !== 0,
    syn: (flagsByte & 0x02) !== 0,
    rst: (flagsByte & 0x04) !== 0,
    psh: (flagsByte & 0x08) !== 0,
    ack: (flagsByte & 0x10) !== 0,
    urg: (flagsByte & 0x20) !== 0,
    ece: (flagsByte & 0x40) !== 0,
    cwr: (flagsByte & 0x80) !== 0,
  };
  const payloadStart = Math.min(dataOffset, buf.length);
  return {
    ok: true,
    srcPort: buf.readUInt16BE(0),
    dstPort: buf.readUInt16BE(2),
    seq: buf.readUInt32BE(4),
    ack: buf.readUInt32BE(8),
    dataOffset,
    flags,
    flagNames: Object.entries(flags).filter(([, v]) => v).map(([k]) => k),
    payload: buf.subarray(payloadStart),
    l4Truncated: dataOffset > buf.length,
    window: buf.readUInt16BE(14),
    ...ctx,
  };
}

export function parseUdp(buf) {
  if (buf.length < 8) return { ok: false, reason: 'UDP 头不足 8 字节' };
  const declaredLength = buf.readUInt16BE(4);
  const available = buf.length - 8;
  const payloadLength = declaredLength >= 8 ? Math.min(declaredLength - 8, available) : available;
  return {
    ok: true,
    srcPort: buf.readUInt16BE(0),
    dstPort: buf.readUInt16BE(2),
    length: declaredLength,
    payload: buf.subarray(8, 8 + payloadLength),
    l4Truncated: declaredLength > buf.length,
  };
}

export function parseIcmp(buf) {
  if (buf.length < 4) return { ok: false, reason: 'ICMP 头不足 4 字节' };
  return { ok: true, icmpType: buf[0], icmpCode: buf[1], payload: buf.subarray(4) };
}

function parseIcmp6(buf) {
  if (buf.length < 4) return { ok: false, reason: 'ICMPv6 头不足 4 字节' };
  return { ok: true, icmpType: buf[0], icmpCode: buf[1], payload: buf.subarray(4) };
}

// ---------------------------------------------------------------------------
// 网络层
// ---------------------------------------------------------------------------

/** @returns {object} {ok, version, src, dst, protocol, payload, ...} */
export function parseIp(buf) {
  if (buf.length < 1) return { ok: false, reason: 'IP 包为空' };
  const version = buf[0] >> 4;
  if (version === 4) return parseIpv4(buf);
  if (version === 6) return parseIpv6(buf);
  return { ok: false, reason: `未知 IP 版本 ${version}` };
}

export function parseIpv4(buf) {
  if (buf.length < 20) return { ok: false, reason: 'IPv4 头不足 20 字节' };
  if ((buf[0] >> 4) !== 4) return { ok: false, reason: 'IPv4 版本字段非 4' };
  const ihl = (buf[0] & 0x0f) * 4;
  if (ihl < 20) return { ok: false, reason: `IPv4 IHL=${ihl} < 20` };
  const totalLength = buf.readUInt16BE(2);
  const available = buf.length;
  const declared = totalLength === 0 ? available : totalLength;
  const truncated = ihl > available || declared > available;
  const effectiveLength = Math.min(available, Math.max(ihl, declared));
  const flagsAndOffset = buf.readUInt16BE(6);
  const flags = flagsAndOffset >> 13;
  const fragmentOffset = (flagsAndOffset & 0x1fff) * 8;
  const moreFragments = (flags & 0x1) !== 0;
  const protocol = buf[9];
  const header = {
    ok: true,
    version: 4,
    headerLength: ihl,
    totalLength: declared,
    effectiveLength,
    truncated,
    fragmented: moreFragments || fragmentOffset > 0,
    moreFragments,
    fragmentOffset,
    ttl: buf[8],
    protocol,
    src: formatIpv4(buf.subarray(12, 16)),
    dst: formatIpv4(buf.subarray(16, 20)),
  };
  let l4 = null;
  const l4Buf = buf.subarray(Math.min(ihl, available), effectiveLength);
  if (fragmentOffset > 0) {
    return { ...header, l4: null, payload: l4Buf, fragmentOnly: true };
  }
  switch (protocol) {
    case 6:
      l4 = parseTcp(l4Buf);
      break;
    case 17:
      l4 = parseUdp(l4Buf);
      break;
    case 1:
      l4 = parseIcmp(l4Buf);
      break;
    default:
      l4 = { ok: true, payload: l4Buf, unknownProtocol: protocol };
      break;
  }
  return { ...header, l4, payload: l4 && l4.ok && l4.payload ? l4.payload : l4Buf };
}

const IPV6_EXT_HEADERS = new Set([0, 43, 60, 51]);
const IPV6_FRAGMENT = 44;
const IPV6_AH = 51;
const IPV6_ESP = 50;

export function parseIpv6(buf) {
  if (buf.length < 40) return { ok: false, reason: 'IPv6 头不足 40 字节' };
  if ((buf[0] >> 4) !== 6) return { ok: false, reason: 'IPv6 版本字段非 6' };
  const payloadLength = buf.readUInt16BE(4);
  const available = buf.length;
  const declared = 40 + payloadLength;
  const truncated = declared > available;
  const effectiveLength = Math.min(available, payloadLength === 0 ? available : declared);
  let nextHeader = buf[6];
  const hopLimit = buf[7];
  const src = formatIpv6(buf.subarray(8, 24));
  const dst = formatIpv6(buf.subarray(24, 40));
  let offset = 40;
  let fragmented = false;
  let fragmentOffset = 0;
  let moreFragments = false;
  let extHeaders = 0;
  let endedOnFragment = false;
  while (IPV6_EXT_HEADERS.has(nextHeader) && extHeaders < 8) {
    if (offset + 2 > effectiveLength) {
      return { ok: true, version: 6, src, dst, hopLimit, nextHeader, truncated: true, l4: null, fragmented: true, fragmentOffset, moreFragments, payload: Buffer.alloc(0), headerLength: offset, totalLength: declared, effectiveLength };
    }
    const hdrLen = nextHeader === IPV6_AH ? (buf[offset + 1] + 2) * 4 : (buf[offset + 1] + 1) * 8;
    nextHeader = buf[offset];
    offset += hdrLen;
    extHeaders++;
  }
  if (nextHeader === IPV6_FRAGMENT) {
    if (offset + 8 > effectiveLength) {
      return { ok: true, version: 6, src, dst, hopLimit, nextHeader, truncated: true, l4: null, fragmented: true, fragmentOffset: 0, moreFragments: false, payload: Buffer.alloc(0), headerLength: offset, totalLength: declared, effectiveLength };
    }
    const fragField = buf.readUInt16BE(offset + 2);
    fragmentOffset = (fragField & 0xfff8);
    moreFragments = (fragField & 0x1) !== 0;
    fragmented = true;
    endedOnFragment = fragmentOffset > 0;
    nextHeader = buf[offset];
    offset += 8;
    extHeaders++;
  }
  if (nextHeader === IPV6_ESP) {
    return { ok: true, version: 6, src, dst, hopLimit, nextHeader, encrypted: true, truncated, fragmented, fragmentOffset, moreFragments, l4: null, payload: buf.subarray(Math.min(offset, effectiveLength), effectiveLength), headerLength: offset, totalLength: declared, effectiveLength };
  }
  const header = {
    ok: true,
    version: 6,
    src,
    dst,
    hopLimit,
    nextHeader,
    truncated,
    fragmented,
    fragmentOffset,
    moreFragments,
    headerLength: offset,
    totalLength: declared,
    effectiveLength,
    l4: null,
  };
  if (endedOnFragment || offset > effectiveLength) return { ...header, payload: buf.subarray(Math.min(offset, available), effectiveLength) };
  const l4Buf = buf.subarray(Math.min(offset, available), effectiveLength);
  switch (nextHeader) {
    case 6:
      header.l4 = parseTcp(l4Buf);
      break;
    case 17:
      header.l4 = parseUdp(l4Buf);
      break;
    case 58:
      header.l4 = parseIcmp6(l4Buf);
      break;
    default:
      header.l4 = { ok: true, payload: l4Buf, unknownProtocol: nextHeader };
      break;
  }
  header.payload = header.l4 && header.l4.ok && header.l4.payload ? header.l4.payload : l4Buf;
  return header;
}

// ---------------------------------------------------------------------------
// 链路层
// ---------------------------------------------------------------------------

/** 返回 {ok, etherType, payload, srcMac, dstMac, vlanIds} */
export function parseEthernet(buf) {
  if (buf.length < 14) return { ok: false, reason: 'Ethernet 帧不足 14 字节' };
  let offset = 12;
  let etherType = buf.readUInt16BE(offset);
  offset += 2;
  const vlanIds = [];
  let guard = 0;
  while (
    (etherType === ETHERTYPE_VLAN || etherType === ETHERTYPE_QINQ || etherType === ETHERTYPE_VLAN_9100) &&
    offset + 4 <= buf.length &&
    guard++ < 4
  ) {
    vlanIds.push(buf.readUInt16BE(offset) & 0x0fff);
    etherType = buf.readUInt16BE(offset + 2);
    offset += 4;
  }
  return {
    ok: true,
    etherType,
    payload: buf.subarray(offset),
    srcMac: buf.subarray(6, 12).toString('hex').replace(/(..)(?=.)/g, '$1:'),
    dstMac: buf.subarray(0, 6).toString('hex').replace(/(..)(?=.)/g, '$1:'),
    vlanIds,
  };
}

export function parseLinuxSll(buf) {
  if (buf.length < 16) return { ok: false, reason: 'Linux SLL 头不足 16 字节' };
  return {
    ok: true,
    etherType: buf.readUInt16BE(14),
    payload: buf.subarray(16),
    packetType: buf.readUInt16BE(0),
    arpHRD: buf.readUInt16BE(2),
    srcMac: buf.subarray(6, 12).toString('hex').replace(/(..)(?=.)/g, '$1:'),
  };
}

export function parseNullLoopback(buf) {
  if (buf.length < 4) return { ok: false, reason: 'NULL/LOOP 头不足 4 字节' };
  // 家庭地址字段可能是 LE（BSD）或 BE（部分实现）
  const familyLe = buf.readUInt32LE(0);
  const familyBe = buf.readUInt32BE(0);
  const family = familyLe <= 255 ? familyLe : familyBe;
  let etherType = null;
  if (family === 2) etherType = ETHERTYPE_IPV4;
  else if (family === 10 || family === 24 || family === 28 || family === 30) etherType = ETHERTYPE_IPV6;
  return { ok: true, etherType, family, payload: buf.subarray(4) };
}

function decodeEtherPayload(link) {
  if (!link.ok) return { ok: false, reason: link.reason };
  if (link.etherType === ETHERTYPE_ARP) return { ok: true, protoLabel: 'arp', arp: true, payload: link.payload };
  if (link.etherType === ETHERTYPE_IPV4) {
    const ip = parseIp(link.payload);
    return { ...ip, linkInfo: { srcMac: link.srcMac, dstMac: link.dstMac, vlanIds: link.vlanIds } };
  }
  if (link.etherType === ETHERTYPE_IPV6) {
    const ip = parseIp(link.payload);
    return { ...ip, linkInfo: { srcMac: link.srcMac, dstMac: link.dstMac, vlanIds: link.vlanIds } };
  }
  return { ok: true, protoLabel: `ethertype-0x${(link.etherType ?? 0).toString(16).padStart(4, '0')}`, raw: true, payload: link.payload };
}

/**
 * 解码一个抓包记录为统一报文模型。
 * @param {number} linkType
 * @param {Buffer} data
 * @returns {object} 统一报文对象；ok=false 表示无法解码（计数用，不抛错）
 */
export function decodePacket(linkType, data) {
  if (!Buffer.isBuffer(data) || data.length === 0) return { ok: false, reason: '报文数据为空' };
  let net = null;
  try {
    switch (linkType) {
      case LINKTYPE_ETHERNET: {
        const eth = parseEthernet(data);
        net = decodeEtherPayload(eth);
        break;
      }
      case LINKTYPE_LINUX_SLL: {
        const sll = parseLinuxSll(data);
        net = decodeEtherPayload(sll);
        break;
      }
      case LINKTYPE_NULL:
      case LINKTYPE_LOOP: {
        const nl = parseNullLoopback(data);
        net = decodeEtherPayload(nl);
        break;
      }
      case LINKTYPE_RAW:
      case LINKTYPE_RAW_BSD: {
        net = parseIp(data);
        break;
      }
      case LINKTYPE_IPV4: {
        net = parseIpv4(data);
        break;
      }
      case LINKTYPE_IPV6: {
        net = parseIpv6(data);
        break;
      }
      default:
        return { ok: false, reason: `不支持的链路类型 ${linkType}（${linkTypeName(linkType)}）`, unsupportedLinkType: true };
    }
  } catch (err) {
    return { ok: false, reason: `报文解码异常：${err && err.message ? err.message : String(err)}` };
  }
  if (!net || net.ok === false) {
    return { ok: false, reason: (net && net.reason) || '网络层解析失败' };
  }
  const base = {
    ok: true,
    linkType,
    linkTypeName: linkTypeName(linkType),
    etherType: net.etherType ?? null,
    src: net.src ?? null,
    dst: net.dst ?? null,
    ipVersion: net.version ?? null,
    ipHeaderLength: net.headerLength ?? null,
    ipLength: net.totalLength ?? null,
    ipTruncated: Boolean(net.truncated),
    fragmented: Boolean(net.fragmented),
    ttl: net.ttl ?? net.hopLimit ?? null,
    srcPort: null,
    dstPort: null,
    transport: null,
    payload: Buffer.alloc(0),
    payloadLength: 0,
    tcpFlags: null,
    tcpSeq: null,
    tcpAck: null,
    icmpType: null,
    icmpCode: null,
    arp: Boolean(net.arp),
    encrypted: Boolean(net.encrypted),
    unknownProtocol: net.unknownProtocol ?? null,
    linkInfo: net.linkInfo ?? null,
  };
  if (net.arp) return { ...base, transport: 'arp', proto: 'arp' };
  if (net.raw) return { ...base, transport: 'raw', proto: 'other' };
  const ipProto = net.nextHeader ?? net.protocol;
  let proto = 'other';
  if (net.version === 4) {
    if (ipProto === 6) proto = 'tcp';
    else if (ipProto === 17) proto = 'udp';
    else if (ipProto === 1) proto = 'icmp';
    else proto = numberProtocolName(ipProto);
  } else if (net.version === 6) {
    if (ipProto === 6) proto = 'tcp';
    else if (ipProto === 17) proto = 'udp';
    else if (ipProto === 58) proto = 'icmp6';
    else proto = numberProtocolName(ipProto);
  }
  const l4 = net.l4;
  if (l4 && l4.ok) {
    if (proto === 'tcp') {
      return {
        ...base,
        transport: 'tcp',
        proto,
        srcPort: l4.srcPort,
        dstPort: l4.dstPort,
        tcpSeq: l4.seq,
        tcpAck: l4.ack,
        tcpFlags: l4.flags,
        tcpFlagNames: l4.flagNames,
        tcpWindow: l4.window,
        l4Truncated: Boolean(l4.l4Truncated),
        payload: l4.payload,
        payloadLength: l4.payload.length,
      };
    }
    if (proto === 'udp') {
      return {
        ...base,
        transport: 'udp',
        proto,
        srcPort: l4.srcPort,
        dstPort: l4.dstPort,
        udpLength: l4.length,
        l4Truncated: Boolean(l4.l4Truncated),
        payload: l4.payload,
        payloadLength: l4.payload.length,
      };
    }
    if (proto === 'icmp' || proto === 'icmp6') {
      return {
        ...base,
        transport: proto,
        proto,
        icmpType: l4.icmpType,
        icmpCode: l4.icmpCode,
        payload: l4.payload,
        payloadLength: l4.payload.length,
      };
    }
    return { ...base, transport: 'other', proto, payload: l4.payload ?? Buffer.alloc(0), payloadLength: (l4.payload ?? Buffer.alloc(0)).length };
  }
  return {
    ...base,
    transport: 'other',
    proto,
    payload: Buffer.alloc(0),
    payloadLength: 0,
    fragmentedOrShort: true,
    reason: l4 ? l4.reason : '无传输层解析结果',
  };
}

function numberProtocolName(n) {
  const map = { 1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 41: 'ipv6', 47: 'gre', 50: 'esp', 51: 'ah', 58: 'icmp6', 89: 'ospf', 132: 'sctp' };
  return map[n] ?? `proto-${n}`;
}
