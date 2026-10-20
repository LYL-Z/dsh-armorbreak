// ArmorBreak - network 域测试（node:test，零依赖，fixture 全部程序化构造）
// 覆盖：classic pcap（LE/BE/纳秒）、pcapng（多 Section/多接口/时间精度）、TCP/UDP 流、
// DNS、TLS ClientHello/ServerHello、明文 HTTP、IOC、异常启发式、畸形/截断/确定性。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import networkManifest from '../lib/analyzers/network/manifest.js';
import { parseDnsMessage } from '../lib/analyzers/network/dns.js';
import { parseTlsRecords, parseClientHello, parseServerHello } from '../lib/analyzers/network/tls.js';
import { parseHttpStream } from '../lib/analyzers/network/http.js';
import { reassembleTcpStream } from '../lib/analyzers/network/flows.js';
import { detectAnomalies } from '../lib/analyzers/network/anomalies.js';
import { enforceDataBudget, classifyIp } from '../lib/analyzers/network/util.js';

// ---------------------------------------------------------------------------
// 测试输入
// ---------------------------------------------------------------------------

function cap(id) {
  const found = networkManifest.capabilities.find((c) => c.id === id);
  assert.ok(found, `capability ${id} 必须存在`);
  return found;
}

function makeInput(buffer, options = {}, limits = {}) {
  return {
    targetPath: 'D:\\fixtures\\capture.pcap',
    buffer,
    text: null,
    options,
    limits: { maxBytes: 16 * 1024 * 1024, maxItems: 200, maxStrings: 500, maxFindings: 100, timeoutMs: 30000, ...limits },
    env: {
      signal: new AbortController().signal,
      workspaceRoot: 'D:\\fixtures',
      nowIso: '2026-01-01T00:00:00Z',
      log: () => {},
    },
  };
}

function u16buf(value) {
  const buf = Buffer.alloc(2);
  buf.writeUInt16BE(value, 0);
  return buf;
}
function u32buf(value) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(value, 0);
  return buf;
}
function u24buf(value) {
  return Buffer.from([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}
function ipv4Bytes(text) {
  return Buffer.from(text.split('.').map((n) => Number(n)));
}
function ipv6Bytes(text) {
  let groups;
  if (text.includes('::')) {
    const [head, tail] = text.split('::');
    const h = head ? head.split(':') : [];
    const t = tail ? tail.split(':') : [];
    const zeros = new Array(Math.max(0, 8 - h.length - t.length)).fill('0');
    groups = [...h, ...zeros, ...t];
  } else {
    groups = text.split(':');
  }
  assert.equal(groups.length, 8, `IPv6 地址格式错误: ${text}`);
  const buf = Buffer.alloc(16);
  groups.forEach((group, index) => buf.writeUInt16BE(parseInt(group || '0', 16), index * 2));
  return buf;
}

// ---------------------------------------------------------------------------
// 报文构造
// ---------------------------------------------------------------------------

function ipv4Packet({ src, dst, protocol, payload, ttl = 64, id = 1, fragOffset = 0, moreFragments = false }) {
  const header = Buffer.alloc(20);
  header[0] = 0x45;
  header.writeUInt16BE(20 + payload.length, 2);
  header.writeUInt16BE(id, 4);
  const flagsFrag = (moreFragments ? 0x2000 : 0) | ((fragOffset / 8) & 0x1fff);
  header.writeUInt16BE(flagsFrag, 6);
  header[8] = ttl;
  header[9] = protocol;
  header.writeUInt16BE(0, 10); // checksum（离线分析不校验）
  ipv4Bytes(src).copy(header, 12);
  ipv4Bytes(dst).copy(header, 16);
  return Buffer.concat([header, payload]);
}

function ipv6Packet({ src, dst, nextHeader, payload, hopLimit = 64 }) {
  const header = Buffer.alloc(40);
  header[0] = 0x60;
  header.writeUInt16BE(payload.length, 4);
  header[6] = nextHeader;
  header[7] = hopLimit;
  ipv6Bytes(src).copy(header, 8);
  ipv6Bytes(dst).copy(header, 24);
  return Buffer.concat([header, payload]);
}

function ethFrame(payload, etherType = 0x0800) {
  const header = Buffer.alloc(14);
  Buffer.alloc(6, 0xaa).copy(header, 0); // dst MAC
  Buffer.alloc(6, 0xbb).copy(header, 6); // src MAC
  header.writeUInt16BE(etherType, 12);
  return Buffer.concat([header, payload]);
}

function tcpSegment({ srcPort, dstPort, seq = 1000, ack = 0, flags = {}, payload = Buffer.alloc(0), window = 65535 }) {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt32BE(seq >>> 0, 4);
  header.writeUInt32BE(ack >>> 0, 8);
  header[12] = 5 << 4;
  let flagByte = 0;
  if (flags.fin) flagByte |= 0x01;
  if (flags.syn) flagByte |= 0x02;
  if (flags.rst) flagByte |= 0x04;
  if (flags.psh) flagByte |= 0x08;
  if (flags.ack) flagByte |= 0x10;
  if (flags.urg) flagByte |= 0x20;
  header[13] = flagByte;
  header.writeUInt16BE(window, 14);
  header.writeUInt16BE(0, 16);
  header.writeUInt16BE(0, 18);
  return Buffer.concat([header, payload]);
}

function udpDatagram({ srcPort, dstPort, payload }) {
  const header = Buffer.alloc(8);
  header.writeUInt16BE(srcPort, 0);
  header.writeUInt16BE(dstPort, 2);
  header.writeUInt16BE(8 + payload.length, 4);
  header.writeUInt16BE(0, 6);
  return Buffer.concat([header, payload]);
}

function tcpPacket({ srcIp, dstIp, srcPort, dstPort, seq = 1000, ack = 0, flags = {}, payload = Buffer.alloc(0) }) {
  return ethFrame(ipv4Packet({ src: srcIp, dst: dstIp, protocol: 6, payload: tcpSegment({ srcPort, dstPort, seq, ack, flags, payload }) }));
}

function udpPacket({ srcIp, dstIp, srcPort, dstPort, payload }) {
  return ethFrame(ipv4Packet({ src: srcIp, dst: dstIp, protocol: 17, payload: udpDatagram({ srcPort, dstPort, payload }) }));
}

function icmpEcho({ srcIp, dstIp }) {
  const icmp = Buffer.from([8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]);
  return ethFrame(ipv4Packet({ src: srcIp, dst: dstIp, protocol: 1, payload: icmp }));
}

// ---------------------------------------------------------------------------
// pcap / pcapng 容器构造
// ---------------------------------------------------------------------------

const PCAP_MAGIC = {
  'little-micro': [0xd4, 0xc3, 0xb2, 0xa1],
  'little-nano': [0x4d, 0x3c, 0xb2, 0xa1],
  'big-micro': [0xa1, 0xb2, 0xc3, 0xd4],
  'big-nano': [0xa1, 0xb2, 0x3c, 0x4d],
};

function buildPcap(records, opts = {}) {
  const endian = opts.endian ?? 'little';
  const nano = opts.nano === true;
  const linkType = opts.linkType ?? 1;
  const snaplen = opts.snaplen ?? 65535;
  const le = endian === 'little';
  const w16 = (buf, value, off) => (le ? buf.writeUInt16LE(value, off) : buf.writeUInt16BE(value, off));
  const w32 = (buf, value, off) => (le ? buf.writeUInt32LE(value, off) : buf.writeUInt32BE(value, off));
  const header = Buffer.alloc(24);
  Buffer.from(PCAP_MAGIC[`${endian}-${nano ? 'nano' : 'micro'}`]).copy(header, 0);
  w16(header, 2, 4);
  w16(header, 4, 6);
  w32(header, 0, 8); // thiszone
  w32(header, 0, 12); // sigfigs
  w32(header, snaplen, 16);
  w32(header, linkType, 20);
  const parts = [header];
  for (const record of records) {
    const data = record.data;
    const ts = record.ts ?? 1700000000;
    const tsSec = Math.floor(ts);
    const fraction = Math.round((ts - tsSec) * (nano ? 1e9 : 1e6));
    const row = Buffer.alloc(16);
    w32(row, tsSec, 0);
    w32(row, fraction, 4);
    w32(row, record.inclLen ?? data.length, 8);
    w32(row, record.origLen ?? data.length, 12);
    parts.push(row, data);
  }
  return Buffer.concat(parts);
}

function pcapngWrite(endian) {
  const le = endian === 'little';
  return {
    u16: (value) => {
      const b = Buffer.alloc(2);
      le ? b.writeUInt16LE(value, 0) : b.writeUInt16BE(value, 0);
      return b;
    },
    u32: (value) => {
      const b = Buffer.alloc(4);
      le ? b.writeUInt32LE(value, 0) : b.writeUInt32BE(value, 0);
      return b;
    },
    i64minus1: () => Buffer.alloc(8, 0xff),
  };
}

function pcapngBlock(endian, type, body) {
  const w = pcapngWrite(endian).u32;
  assert.equal(body.length % 4, 0, 'pcapng block body 必须 4 字节对齐');
  const total = 12 + body.length;
  return Buffer.concat([w(type), w(total), body, w(total)]);
}

function shbBlock(endian) {
  const w = pcapngWrite(endian);
  const body = Buffer.concat([
    w.u32(0x1a2b3c4d), // byte-order magic
    w.u16(1),
    w.u16(0),
    w.i64minus1(), // section length: 未知
    w.u16(0),
    w.u16(0), // opt_endofopt
  ]);
  return pcapngBlock(endian, 0x0a0d0d0a, body);
}

function idbBlock(endian, { linkType, snaplen = 65535, tsresol }) {
  const w = pcapngWrite(endian);
  const options = [];
  if (tsresol !== undefined && tsresol !== 6) {
    options.push(w.u16(9), w.u16(1), Buffer.from([tsresol, 0, 0, 0])); // if_tsresol
  }
  options.push(w.u16(0), w.u16(0));
  const optionsBuf = Buffer.concat(options);
  const body = Buffer.concat([w.u16(linkType), w.u16(0), w.u32(snaplen), optionsBuf]);
  return pcapngBlock(endian, 0x00000001, body);
}

function epbBlock(endian, { interfaceId, ts = 1700000000, data, tsresol = 6 }) {
  const w = pcapngWrite(endian);
  const ticks = BigInt(Math.round(ts * 10 ** tsresol));
  const high = Number(ticks >> 32n);
  const low = Number(ticks & 0xffffffffn);
  const padding = (4 - (data.length % 4)) % 4;
  const body = Buffer.concat([
    w.u32(interfaceId),
    w.u32(high),
    w.u32(low),
    w.u32(data.length),
    w.u32(data.length),
    data,
    Buffer.alloc(padding),
  ]);
  return pcapngBlock(endian, 0x00000006, body);
}

// ---------------------------------------------------------------------------
// DNS / TLS / HTTP 构造
// ---------------------------------------------------------------------------

function dnsName(text) {
  const labels = text.split('.').filter((label) => label.length > 0);
  return Buffer.concat([...labels.map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label, 'ascii')])), Buffer.from([0])]);
}

function dnsHeader({ id = 0x1234, flags = 0x0100, qdcount = 1, ancount = 0 }) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(qdcount, 4);
  header.writeUInt16BE(ancount, 6);
  return header;
}

function dnsQuery({ id = 0x1234, name = 'example.com', qtype = 1 }) {
  return Buffer.concat([dnsHeader({ id, flags: 0x0100 }), dnsName(name), u16buf(qtype), u16buf(1)]);
}

function dnsResponse({ id = 0x1234, name = 'example.com', qtype = 1, rcode = 0, answers = [] }) {
  const flags = 0x8180 | rcode;
  const parts = [dnsHeader({ id, flags, qdcount: 1, ancount: answers.length }), dnsName(name), u16buf(qtype), u16buf(1)];
  for (const answer of answers) {
    const type = answer.type ?? 1;
    let rdata;
    if (type === 1) rdata = ipv4Bytes(answer.value);
    else if (type === 28) rdata = ipv6Bytes(answer.value);
    else if (type === 5) rdata = dnsName(answer.value);
    else rdata = Buffer.from(answer.value ?? '');
    parts.push(
      Buffer.from([0xc0, 0x0c]), // name 压缩指针
      u16buf(type),
      u16buf(1),
      u32buf(answer.ttl ?? 300),
      u16buf(rdata.length),
      rdata,
    );
  }
  return Buffer.concat(parts);
}

function tlsExtension(type, data) {
  return Buffer.concat([u16buf(type), u16buf(data.length), data]);
}

function tlsRecord(type, version, body) {
  return Buffer.concat([Buffer.from([type]), u16buf(version), u16buf(body.length), body]);
}

function buildClientHello({ sni = 'example.com', alpn = ['h2', 'http/1.1'], versions = [0x0304, 0x0303], cipherSuites = [0x1301, 0x1302, 0x002f] } = {}) {
  const extensions = [];
  if (sni) {
    const host = Buffer.from(sni, 'ascii');
    const entry = Buffer.concat([Buffer.from([0]), u16buf(host.length), host]);
    extensions.push(tlsExtension(0, Buffer.concat([u16buf(entry.length), entry])));
  }
  if (alpn && alpn.length > 0) {
    const protocols = alpn.map((protocol) => {
      const bytes = Buffer.from(protocol, 'latin1');
      return Buffer.concat([Buffer.from([bytes.length]), bytes]);
    });
    extensions.push(tlsExtension(16, Buffer.concat([u16buf(protocols.reduce((n, b) => n + b.length, 0)), ...protocols])));
  }
  const versionsData = Buffer.concat([Buffer.from([versions.length * 2]), ...versions.map((v) => u16buf(v))]);
  extensions.push(tlsExtension(43, versionsData));
  const extensionBlock = Buffer.concat(extensions);
  const body = Buffer.concat([
    u16buf(0x0303), // legacy_version
    Buffer.alloc(32, 0x42), // random
    Buffer.from([0]), // session_id 长度
    u16buf(cipherSuites.length * 2),
    ...cipherSuites.map((id) => u16buf(id)),
    Buffer.from([1, 0]), // compression: null
    u16buf(extensionBlock.length),
    extensionBlock,
  ]);
  return tlsRecord(22, 0x0301, Buffer.concat([Buffer.from([1]), u24buf(body.length), body]));
}

function buildServerHello({ version = 0x0304, cipherSuite = 0x1301 } = {}) {
  const extensions = Buffer.concat([tlsExtension(43, u16buf(version))]);
  const body = Buffer.concat([
    u16buf(0x0303),
    Buffer.alloc(32, 0x43),
    Buffer.from([0]),
    u16buf(cipherSuite),
    Buffer.from([0]),
    u16buf(extensions.length),
    extensions,
  ]);
  return tlsRecord(22, 0x0303, Buffer.concat([Buffer.from([2]), u24buf(body.length), body]));
}

function httpRequest({ method = 'GET', uri = '/', headers = {}, body = null }) {
  const lines = [`${method} ${uri} HTTP/1.1`];
  const allHeaders = { Host: 'example.com', ...headers };
  if (body !== null) allHeaders['Content-Length'] = String(body.length);
  for (const [name, value] of Object.entries(allHeaders)) lines.push(`${name}: ${value}`);
  return Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1'), body ?? Buffer.alloc(0)]);
}

function httpResponse({ status = 200, reason = 'OK', headers = {}, body = null, chunked = false }) {
  const lines = [`HTTP/1.1 ${status} ${reason}`];
  const allHeaders = { 'Content-Type': 'text/html', ...headers };
  if (chunked) allHeaders['Transfer-Encoding'] = 'chunked';
  else if (body !== null) allHeaders['Content-Length'] = String(body.length);
  for (const [name, value] of Object.entries(allHeaders)) lines.push(`${name}: ${value}`);
  let bodyPart = Buffer.alloc(0);
  if (chunked && body !== null) {
    bodyPart = Buffer.concat([Buffer.from(`${body.length.toString(16)}\r\n`, 'latin1'), body, Buffer.from('\r\n0\r\n\r\n', 'latin1')]);
  } else if (body !== null) {
    bodyPart = body;
  }
  return Buffer.concat([Buffer.from(lines.join('\r\n') + '\r\n\r\n', 'latin1'), bodyPart]);
}

// ---------------------------------------------------------------------------
// 会话构造辅助
// ---------------------------------------------------------------------------

function tcpConversation({ clientIp, clientPort, serverIp, serverPort, clientPayloads = [], serverPayloads = [], startTs = 1700000000, handshake = true }) {
  const records = [];
  let ts = startTs;
  let clientSeq = 1000;
  let serverSeq = 5000;
  const push = (data) => {
    records.push({ ts, data });
    ts = Number((ts + 0.1).toFixed(6));
  };
  if (handshake) {
    push(tcpPacket({ srcIp: clientIp, dstIp: serverIp, srcPort: clientPort, dstPort: serverPort, seq: clientSeq, flags: { syn: true } }));
    push(tcpPacket({ srcIp: serverIp, dstIp: clientIp, srcPort: serverPort, dstPort: clientPort, seq: serverSeq, ack: clientSeq + 1, flags: { syn: true, ack: true } }));
    clientSeq += 1;
    serverSeq += 1;
    push(tcpPacket({ srcIp: clientIp, dstIp: serverIp, srcPort: clientPort, dstPort: serverPort, seq: clientSeq, ack: serverSeq, flags: { ack: true } }));
  }
  for (const payload of clientPayloads) {
    push(tcpPacket({ srcIp: clientIp, dstIp: serverIp, srcPort: clientPort, dstPort: serverPort, seq: clientSeq, ack: serverSeq, flags: { psh: true, ack: true }, payload }));
    clientSeq += payload.length;
  }
  for (const payload of serverPayloads) {
    push(tcpPacket({ srcIp: serverIp, dstIp: clientIp, srcPort: serverPort, dstPort: clientPort, seq: serverSeq, ack: clientSeq, flags: { psh: true, ack: true }, payload }));
    serverSeq += payload.length;
  }
  return records;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

test('network: capability 清单符合契约', () => {
  assert.equal(networkManifest.domain, 'network');
  assert.deepEqual(
    networkManifest.capabilities.map((c) => c.id),
    [
      'network.pcap_overview',
      'network.flows',
      'network.dns',
      'network.tls',
      'network.http',
      'network.iocs',
      'network.anomalies',
      'network.tshark',
    ],
  );
  for (const capability of networkManifest.capabilities) {
    if (capability.id === 'network.tshark') continue; // external tool + capture; covered by external-adapters-v2.test.mjs / Gate B
    assert.equal(capability.riskLevel, 'L0');
    assert.equal(capability.params.type, 'object');
    assert.equal(capability.params.additionalProperties, false);
    assert.ok(capability.params.properties.maxPackets, `${capability.id} 必须声明 maxPackets 上限`);
  }
});

test('network.pcap_overview: 经典 pcap（LE 微秒）协议直方图/时间范围/统计', async () => {
  const records = [
    { ts: 1700000000.25, data: tcpPacket({ srcIp: '10.0.0.5', dstIp: '93.184.216.34', srcPort: 34567, dstPort: 80, flags: { syn: true } }) },
    { ts: 1700000001.0, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '8.8.8.8', srcPort: 40000, dstPort: 53, payload: dnsQuery({ name: 'example.com' }) }) },
    { ts: 1700000002.75, data: icmpEcho({ srcIp: '10.0.0.5', dstIp: '1.1.1.1' }) },
  ];
  const pcap = buildPcap(records, { linkType: 1 });
  const result = await cap('network.pcap_overview').run(makeInput(pcap));
  assert.equal(result.data.format, 'pcap');
  assert.equal(result.data.packetCount, 3);
  assert.equal(result.data.rawPacketCount, 3);
  assert.deepEqual(result.data.protocols, [
    { proto: 'icmp', count: 1 },
    { proto: 'tcp', count: 1 },
    { proto: 'udp', count: 1 },
  ]);
  assert.equal(result.data.linkTypes[0].linkType, 1);
  assert.equal(result.data.linkTypes[0].name, 'Ethernet');
  assert.deepEqual(result.data.ipVersions, [{ version: 'IPv4', count: 3 }]);
  assert.equal(result.data.tcp.synCount, 1);
  assert.equal(result.data.firstPacketIso, '2023-11-14T22:13:20.250Z');
  assert.equal(result.data.lastPacketIso, '2023-11-14T22:13:22.750Z');
  assert.equal(result.data.durationSeconds, 2.5);
  assert.ok(result.data.capturedBytes > 0);
  assert.ok(result.data.topTalkers.some((t) => t.ip === '10.0.0.5'));
  assert.equal(result.data.decodeErrors.length, 0);
  assert.equal(result.data.truncated, false);
  assert.match(result.summary, /3 个报文/);
  const again = await cap('network.pcap_overview').run(makeInput(pcap));
  assert.deepEqual(again.data, result.data);
});

test('network.pcap_overview: 大端/纳秒 pcap，以及截断抓包只标记不抛错', async () => {
  const bigNano = buildPcap(
    [{ ts: 1700000000.125, data: tcpPacket({ srcIp: '192.168.1.10', dstIp: '10.0.0.1', srcPort: 50000, dstPort: 443, flags: { syn: true } }) }],
    { endian: 'big', nano: true },
  );
  const result = await cap('network.pcap_overview').run(makeInput(bigNano));
  assert.equal(result.data.endianness, 'big');
  assert.equal(result.data.nanosecondTimestamps, true);
  assert.equal(result.data.packetCount, 1);
  assert.equal(result.data.firstPacketIso, '2023-11-14T22:13:20.125Z');
  assert.equal(result.data.packets, undefined); // overview 不应返回全部报文
  // 截断：保留头 + 一条记录的部分数据
  const truncated = bigNano.subarray(0, bigNano.length - 6);
  const truncatedResult = await cap('network.pcap_overview').run(makeInput(truncated));
  assert.equal(truncatedResult.data.truncated, true);
  assert.ok(truncatedResult.meta.warnings.some((w) => /截断|不完整/.test(w)));
  assert.equal(truncatedResult.data.packetCount, 0);
  // 非法 pcap
  await assert.rejects(
    () => cap('network.pcap_overview').run(makeInput(Buffer.alloc(8))),
    (err) => {
      assert.match(err.message, /无法识别|pcap/);
      return true;
    },
  );
});

test('network.pcap_overview: pcapng 多 Section/多接口/多时间精度', async () => {
  const tcpData = tcpPacket({ srcIp: '172.16.0.5', dstIp: '203.0.113.10', srcPort: 44444, dstPort: 443, flags: { syn: true } });
  const dnsData = ipv4Packet({
    src: '172.16.0.5',
    dst: '8.8.8.8',
    protocol: 17,
    payload: udpDatagram({ srcPort: 33333, dstPort: 53, payload: dnsQuery({ name: 'pcapng.example' }) }),
  });
  const section1 = Buffer.concat([
    shbBlock('little'),
    idbBlock('little', { linkType: 1 }),
    idbBlock('little', { linkType: 101, snaplen: 262144, tsresol: 9 }),
    epbBlock('little', { interfaceId: 0, ts: 1700000000.5, data: tcpData, tsresol: 6 }),
    epbBlock('little', { interfaceId: 1, ts: 1700000001.25, data: dnsData, tsresol: 9 }),
  ]);
  const section2 = Buffer.concat([
    shbBlock('big'),
    idbBlock('big', { linkType: 1 }),
    epbBlock('big', { interfaceId: 0, ts: 1700000002, data: tcpData, tsresol: 6 }),
  ]);
  const pcapng = Buffer.concat([section1, section2]);
  const result = await cap('network.pcap_overview').run(makeInput(pcapng));
  assert.equal(result.data.format, 'pcapng');
  assert.equal(result.data.packetCount, 3);
  assert.equal(result.data.sections.length, 2);
  assert.equal(result.data.sections[0].interfaceCount, 2);
  assert.equal(result.data.sections[1].endianness, 'big');
  assert.equal(result.data.interfaces.length, 3);
  assert.deepEqual(
    result.data.linkTypes.map((entry) => `${entry.linkType}:${entry.packetCount}`),
    ['1:2', '101:1'],
  );
  assert.deepEqual(result.data.ipVersions, [{ version: 'IPv4', count: 3 }]);
  assert.equal(result.data.firstPacketIso, '2023-11-14T22:13:20.500Z');
  assert.equal(result.data.lastPacketIso, '2023-11-14T22:13:22.000Z');
  assert.equal(result.data.durationSeconds, 1.5);
  assert.equal(result.data.decodeErrors.length, 0);
  // pcapng 首块非法
  await assert.rejects(
    () => cap('network.pcap_overview').run(makeInput(Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.alloc(20, 0)]))),
    (err) => {
      assert.match(err.message, /pcapng|SHB/);
      return true;
    },
  );
});

test('network.flows: TCP 状态启发式 + UDP 会话聚合 + 截断', async () => {
  const http = Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', 'latin1');
  const response = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK', 'latin1');
  const conversation = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 34567,
    serverIp: '93.184.216.34',
    serverPort: 80,
    clientPayloads: [http],
    serverPayloads: [response],
  });
  const dnsRecords = [
    { ts: 1700000100, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '8.8.8.8', srcPort: 40001, dstPort: 53, payload: dnsQuery({ id: 1 }) }) },
    { ts: 1700000100.1, data: udpPacket({ srcIp: '8.8.8.8', dstIp: '10.0.0.5', srcPort: 53, dstPort: 40001, payload: dnsResponse({ id: 1, answers: [{ type: 1, value: '93.184.216.34' }] }) }) },
  ];
  const pcap = buildPcap([...conversation, ...dnsRecords]);
  const result = await cap('network.flows').run(makeInput(pcap));
  assert.equal(result.data.flowCount, 2);
  assert.equal(result.data.totalFlowCount, 2);
  const tcpFlow = result.data.flows.find((flow) => flow.proto === 'tcp');
  assert.ok(tcpFlow);
  assert.equal(tcpFlow.state, 'established');
  assert.equal(tcpFlow.server.port, 80);
  assert.equal(tcpFlow.service, 'http');
  assert.equal(tcpFlow.client.port, 34567);
  assert.equal(tcpFlow.packets, 3 + 2);
  assert.equal(tcpFlow.firstSeen, '2023-11-14T22:13:20.000Z');
  assert.ok(tcpFlow.bytesByDirection.ab > 0);
  assert.ok(tcpFlow.bytesByDirection.ba > 0);
  assert.ok(tcpFlow.tcpFlags.includes('syn'));
  const udpFlow = result.data.flows.find((flow) => flow.proto === 'udp');
  assert.ok(udpFlow);
  assert.equal(udpFlow.state, 'datagram');
  assert.equal(udpFlow.server.port, 53);
  assert.equal(udpFlow.service, 'dns');
  assert.deepEqual(result.data.stateCounts, [
    { state: 'datagram', count: 1 },
    { state: 'established', count: 1 },
  ]);
  const limited = await cap('network.flows').run(makeInput(pcap, { maxFlows: 1 }));
  assert.equal(limited.data.flowCount, 1);
  assert.equal(limited.data.truncated, true);
});

test('network.dns: 查询/响应/A 记录/NXDOMAIN/解析器配对', async () => {
  const ts = 1700000000;
  const records = [
    { ts, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '8.8.8.8', srcPort: 40000, dstPort: 53, payload: dnsQuery({ id: 0x1111, name: 'example.com' }) }) },
    {
      ts: ts + 0.05,
      data: udpPacket({
        srcIp: '8.8.8.8',
        dstIp: '10.0.0.5',
        srcPort: 53,
        dstPort: 40000,
        payload: dnsResponse({
          id: 0x1111,
          name: 'example.com',
          answers: [
            { type: 1, value: '93.184.216.34', ttl: 120 },
            { type: 5, value: 'cdn.example.com', ttl: 60 },
          ],
        }),
      }),
    },
    // NXDOMAIN 响应
    {
      ts: ts + 0.2,
      data: udpPacket({
        srcIp: '8.8.8.8',
        dstIp: '10.0.0.5',
        srcPort: 53,
        dstPort: 40000,
        payload: dnsResponse({ id: 0x2222, name: 'nxdomain.invalid', rcode: 3, answers: [] }),
      }),
    },
    // 畸形 DNS（太短）
    { ts: ts + 0.3, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '8.8.8.8', srcPort: 40000, dstPort: 53, payload: Buffer.from([1, 2, 3, 4]) }) },
    // 非 DNS 端口（不应计入）
    { ts: ts + 0.4, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '10.0.0.9', srcPort: 40000, dstPort: 123, payload: Buffer.alloc(32) }) },
  ];
  const pcap = buildPcap(records);
  const result = await cap('network.dns').run(makeInput(pcap));
  assert.equal(result.data.messageCount, 4); // 前 4 条是 DNS（含畸形）
  assert.equal(result.data.queryCount, 1);
  assert.equal(result.data.responseCount, 2);
  assert.equal(result.data.nxdomainCount, 1);
  assert.equal(result.data.parseErrors, 1);
  assert.equal(result.data.qtypeCounts[0].type, 'A');
  assert.equal(result.data.qtypeCounts[0].count, 1);
  const noerror = result.data.rcodeCounts.find((entry) => entry.rcode === 'NOERROR');
  assert.equal(noerror.count, 1);
  assert.equal(result.data.rcodeCounts.find((entry) => entry.rcode === 'NXDOMAIN').count, 1);
  assert.equal(result.data.resolverPairs.length, 1);
  assert.deepEqual(result.data.resolverPairs[0], { client: '10.0.0.5', resolver: '8.8.8.8', queries: 1 });
  assert.ok(result.data.names.some((entry) => entry.name === 'example.com'));
  assert.ok(result.data.answers.some((entry) => entry.type === 'A' && entry.value === '93.184.216.34' && entry.ttl === 120));
  assert.ok(result.data.answers.some((entry) => entry.type === 'CNAME' && entry.value === 'cdn.example.com'));
  assert.match(result.summary, /NXDOMAIN 1/);
  // 直接调用解析器校验字段
  const direct = parseDnsMessage(dnsResponse({ id: 7, answers: [{ type: 1, value: '1.2.3.4' }] }));
  assert.equal(direct.ok, true);
  assert.equal(direct.isResponse, true);
  assert.equal(direct.rcode, 0);
  assert.equal(direct.questions[0].name, 'example.com');
  assert.equal(direct.answers[0].value, '1.2.3.4');
});

test('network.tls: ClientHello 分段重组/SNI/ALPN/版本 + ServerHello 协商', async () => {
  const hello = buildClientHello();
  const splitPoint = Math.floor(hello.length / 2);
  const conversation1 = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 35000,
    serverIp: '93.184.216.34',
    serverPort: 443,
    clientPayloads: [hello.subarray(0, splitPoint), hello.subarray(splitPoint)],
    serverPayloads: [buildServerHello()],
  });
  const noSni = buildClientHello({ sni: null, alpn: [] });
  const conversation2 = tcpConversation({
    clientIp: '10.0.0.6',
    clientPort: 35001,
    serverIp: '203.0.113.20',
    serverPort: 443,
    clientPayloads: [noSni],
    serverPayloads: [buildServerHello({ version: 0x0303, cipherSuite: 0xc02f })],
  });
  const truncatedConversation = tcpConversation({
    clientIp: '10.0.0.7',
    clientPort: 35002,
    serverIp: '203.0.113.21',
    serverPort: 443,
    clientPayloads: [buildClientHello({ sni: 'trunc.example.com' }), Buffer.from([0x16, 0x03, 0x03, 0x40])], // 尾部不完整 record
  });
  const pcap = buildPcap([...conversation1, ...conversation2, ...truncatedConversation]);
  const result = await cap('network.tls').run(makeInput(pcap));
  assert.equal(result.data.sessionCount, 3);
  const first = result.data.sessions.find((session) => session.sni === 'example.com');
  assert.ok(first, '应提取 SNI=example.com');
  assert.equal(first.serverPort, 443);
  assert.equal(first.service, 'https');
  assert.deepEqual(first.alpn, ['h2', 'http/1.1']);
  assert.ok(first.clientSupportedVersions.includes('TLS 1.3'));
  assert.ok(first.clientSupportedVersions.includes('TLS 1.2'));
  assert.equal(first.clientLegacyVersion, 'TLS 1.2');
  assert.equal(first.selectedVersion, 'TLS 1.3');
  assert.equal(first.negotiatedCipherSuite, 'TLS_AES_128_GCM_SHA256');
  assert.equal(first.ja3LikeSha256.length, 64);
  assert.equal(first.streamGaps.clientToServer, 0, '分段但 seq 连续不应产生 gap');
  assert.match(first.ja3Like, /771,4865-4866-47,0-16-43/);
  const noSniSession = result.data.sessions.find((session) => session.server.includes('203.0.113.20'));
  assert.ok(noSniSession);
  assert.equal(noSniSession.sni, null);
  assert.equal(noSniSession.selectedVersion, 'TLS 1.2');
  assert.equal(noSniSession.negotiatedCipherSuite, 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256');
  const truncatedSession = result.data.sessions.find((session) => session.server.includes('203.0.113.21'));
  assert.ok(truncatedSession);
  assert.equal(truncatedSession.clientTruncated, true);
  assert.deepEqual(result.data.sniValues.find((entry) => entry.sni === 'example.com'), { sni: 'example.com', count: 1 });
  assert.deepEqual(result.data.versionCounts, [{ version: 'TLS 1.3', count: 1 }, { version: 'TLS 1.2', count: 2 }].sort((a, b) => b.count - a.count || a.version.localeCompare(b.version)));
  // 直接调用 TLS 解析
  const records = parseTlsRecords(hello);
  assert.equal(records.records.length, 1);
  assert.equal(records.truncated, false);
  const clientHello = parseClientHello(records.messages[0].body);
  assert.equal(clientHello.ok, true);
  assert.equal(clientHello.sni, 'example.com');
  assert.deepEqual(clientHello.alpn, ['h2', 'http/1.1']);
  const serverHello = parseServerHello(parseTlsRecords(buildServerHello()).messages[0].body);
  assert.equal(serverHello.selectedVersionName, 'TLS 1.3');
  assert.equal(serverHello.cipherSuiteName, 'TLS_AES_128_GCM_SHA256');
  // handshake 消息跨两个 TLS record 时应重组为一条完整消息
  const helloBytes = buildClientHello().subarray(5); // 去掉 record 头，仅 handshake 消息
  const splitRecords = Buffer.concat([tlsRecord(22, 0x0301, helloBytes.subarray(0, 11)), tlsRecord(22, 0x0301, helloBytes.subarray(11))]);
  const splitParsed = parseTlsRecords(splitRecords);
  assert.equal(splitParsed.records.length, 2);
  assert.equal(splitParsed.messages.length, 1);
  assert.equal(splitParsed.truncated, false);
  assert.equal(parseClientHello(splitParsed.messages[0].body).sni, 'example.com');
});

test('network.http: 明文请求/响应、状态码、chunked 与敏感信息脱敏', async () => {
  const request1 = httpRequest({
    method: 'GET',
    uri: '/index.html?token=abc123&x=1',
    headers: { 'User-Agent': 'agent/1.0', Authorization: 'Bearer supersecret-token' },
  });
  const response1 = httpResponse({ status: 200, headers: { Server: 'nginx/1.2.3' }, body: Buffer.from('<html>hello</html>') });
  const request2 = httpRequest({
    method: 'POST',
    uri: '/api/login?password=hunter2',
    headers: { 'Content-Type': 'application/json', Cookie: 'session=deadbeef' },
    body: Buffer.from('{"user":"alice"}'),
  });
  const response2 = httpResponse({ status: 201, reason: 'Created', headers: { 'Content-Type': 'text/plain' }, body: Buffer.from('OK!'), chunked: true });
  const conversation = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 34567,
    serverIp: '93.184.216.34',
    serverPort: 80,
    clientPayloads: [request1, request2],
    serverPayloads: [response1, response2],
  });
  const pcap = buildPcap(conversation);
  const result = await cap('network.http').run(makeInput(pcap));
  assert.equal(result.data.streamCount, 1);
  assert.equal(result.data.requestCount, 2);
  assert.equal(result.data.responseCount, 2);
  assert.equal(result.data.requests[0].method, 'GET');
  assert.equal(result.data.requests[0].host, 'example.com');
  assert.equal(result.data.requests[0].userAgent, 'agent/1.0');
  assert.equal(result.data.requests[0].hasAuthorization, true);
  assert.equal(result.data.requests[1].method, 'POST');
  assert.equal(result.data.requests[1].hasCookie, true);
  assert.deepEqual(result.data.statusCodes, [
    { status: 200, count: 1 },
    { status: 201, count: 1 },
  ]);
  assert.equal(result.data.responses[0].server, 'nginx/1.2.3');
  assert.ok(result.data.responses[0].bodySample.includes('hello'));
  assert.ok(result.data.responses[1].bodySample.includes('OK!'));
  assert.equal(result.data.servers[0].server, 'nginx/1.2.3');
  assert.deepEqual(result.data.userAgents[0], { userAgent: 'agent/1.0', count: 1 });
  // 脱敏：原始敏感值不得出现在输出 JSON 中
  const serialized = JSON.stringify(result.data);
  assert.ok(!serialized.includes('supersecret-token'), 'Authorization 值必须脱敏');
  assert.ok(!serialized.includes('abc123'), 'token 查询参数值必须脱敏');
  assert.ok(!serialized.includes('hunter2'), 'password 查询参数值必须脱敏');
  assert.ok(!serialized.includes('deadbeef'), 'Cookie 值必须脱敏');
  assert.match(result.data.requests[0].uri, /\[redacted:6\]/);
  assert.equal(result.data.parseErrors, 0);
  // 直接解析 + 脱敏函数
  const direct = parseHttpStream(Buffer.concat([request1, response1]));
  assert.equal(direct.requests.length, 1);
  assert.equal(direct.requests[0].method, 'GET');
  assert.equal(direct.responses[0].status, 200);
});

test('network.iocs: 公网/私有 IP 分类、域名来源、URI 汇总', async () => {
  const dnsRecords = [
    { ts: 1700000000, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '8.8.8.8', srcPort: 40000, dstPort: 53, payload: dnsQuery({ name: 'api.example.com' }) }) },
    {
      ts: 1700000000.1,
      data: udpPacket({
        srcIp: '8.8.8.8',
        dstIp: '10.0.0.5',
        srcPort: 53,
        dstPort: 40000,
        payload: dnsResponse({ id: 0x1234, name: 'api.example.com', answers: [{ type: 1, value: '93.184.216.34' }] }),
      }),
    },
  ];
  const httpConversation = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 34567,
    serverIp: '93.184.216.34',
    serverPort: 80,
    clientPayloads: [httpRequest({ method: 'GET', uri: '/v1/items', headers: { Host: 'api.example.com' } })],
    serverPayloads: [httpResponse({ status: 200, body: Buffer.from('[]') })],
  });
  const tlsConversation = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 34568,
    serverIp: '203.0.113.20',
    serverPort: 443,
    clientPayloads: [buildClientHello({ sni: 'secure.example.com' })],
    serverPayloads: [buildServerHello()],
  });
  const pcap = buildPcap([...dnsRecords, ...httpConversation, ...tlsConversation]);
  const result = await cap('network.iocs').run(makeInput(pcap));
  assert.ok(result.data.publicIps.some((entry) => entry.ip === '93.184.216.34'));
  // 文档地址段 203.0.113.0/24 不计入 public，但应出现在 serverIps/分类统计里
  assert.ok(!result.data.publicIps.some((entry) => entry.ip === '203.0.113.20'));
  assert.ok(result.data.ipClassification.some((entry) => entry.category === 'documentation'));
  assert.ok(!result.data.publicIps.some((entry) => entry.ip === '10.0.0.5'), '私有地址不得出现在公网 IP 列表');
  const publicIpEntry = result.data.publicIps.find((entry) => entry.ip === '93.184.216.34');
  assert.equal(publicIpEntry.firstSeen, '2023-11-14T22:13:20.000Z');
  assert.equal(publicIpEntry.lastSeen, '2023-11-14T22:13:20.400Z');
  assert.ok(publicIpEntry.packets >= 2);
  assert.ok(result.data.privateIps.some((entry) => entry.ip === '10.0.0.5'));
  const privateCategory = result.data.ipClassification.find((entry) => entry.category === 'private');
  assert.ok(privateCategory && privateCategory.distinctCount >= 1);
  const apiDomain = result.data.domains.find((entry) => entry.domain === 'api.example.com');
  assert.ok(apiDomain, 'DNS 域名应进入 IOC');
  assert.ok(apiDomain.sources.includes('dns'));
  assert.equal(apiDomain.firstSeen, '2023-11-14T22:13:20.000Z');
  assert.ok(result.data.domains.some((entry) => entry.domain === 'secure.example.com' && entry.sources.includes('tls-sni')));
  assert.ok(result.data.domains.some((entry) => entry.domain === 'api.example.com' && entry.sources.includes('http-host')));
  assert.ok(result.data.uris.some((entry) => entry.uri === 'http://api.example.com/v1/items'));
  assert.equal(result.data.uris.find((entry) => entry.uri === 'http://api.example.com/v1/items').firstSeen, '2023-11-14T22:13:20.000Z');
  assert.ok(result.data.serverIps.some((entry) => entry.ip === '93.184.216.34'));
  assert.ok(result.data.counts.distinctIps >= 3);
  assert.match(result.data.note, /不代表已确认的恶意/);
  // 确定性
  const again = await cap('network.iocs').run(makeInput(pcap));
  assert.deepEqual(again.data, result.data);
});

test('network.anomalies: 扫描扇出/信标/大上传/罕见端口/明文 HTTP（全部标注验证等级）', async () => {
  const records = [];
  let ts = 1700000000;
  // 1) 端口扫描：10.0.0.66 -> 10.0.0.1 的 20 个不同目的端口
  for (let i = 0; i < 20; i++) {
    records.push({ ts: Number((ts + i * 0.01).toFixed(6)), data: tcpPacket({ srcIp: '10.0.0.66', dstIp: '10.0.0.1', srcPort: 50000, dstPort: 1 + i, flags: { syn: true } }) });
  }
  ts += 1;
  // 2) 周期性信标：每 10 秒一个 10 字节包
  let seq = 7000;
  for (let i = 0; i < 6; i++) {
    records.push({
      ts: ts + i * 10,
      data: tcpPacket({
        srcIp: '10.0.0.66',
        dstIp: '203.0.113.5',
        srcPort: 40000,
        dstPort: 443,
        seq,
        flags: { psh: true, ack: true },
        payload: Buffer.alloc(10, 0x5a),
      }),
    });
    seq += 10;
  }
  ts += 60;
  // 3) 大上传：20 个 ~60KB 分片，总计 ~1.2MB（单 IP 包不能超过 65535 字节）
  const uploadChunkSize = 60000;
  let uploadSeq = 9000;
  for (let i = 0; i < 20; i++) {
    records.push({
      ts: Number((ts + i * 0.001).toFixed(6)),
      data: tcpPacket({
        srcIp: '10.0.0.66',
        dstIp: '198.51.100.9',
        srcPort: 41000,
        dstPort: 8080,
        seq: uploadSeq,
        flags: { psh: true, ack: true },
        payload: Buffer.alloc(uploadChunkSize, 0x41),
      }),
    });
    uploadSeq += uploadChunkSize;
  }
  ts += 1;
  // 4) 罕见服务端口：20 条不同客户端端口到 10.0.0.1:4444 的流
  for (let i = 0; i < 20; i++) {
    records.push({
      ts: Number((ts + i * 0.01).toFixed(6)),
      data: tcpPacket({ srcIp: '10.0.0.77', dstIp: '10.0.0.1', srcPort: 60000 + i, dstPort: 4444, flags: { syn: true } }),
    });
  }
  ts += 1;
  // 5) 明文 HTTP 会话
  const httpConversation = tcpConversation({
    clientIp: '10.0.0.66',
    clientPort: 42000,
    serverIp: '93.184.216.34',
    serverPort: 80,
    clientPayloads: [httpRequest({ method: 'GET', uri: '/plain' })],
    serverPayloads: [httpResponse({ status: 200, body: Buffer.from('ok') })],
    startTs: ts,
  });
  records.push(...httpConversation);
  const pcap = buildPcap(records, { snaplen: 2000000 });
  const result = await cap('network.anomalies').run(makeInput(pcap));
  const types = new Set(result.data.anomalies.map((anomaly) => anomaly.type));
  assert.ok(types.has('port-scan-fanout'), `应检测端口扫描，实际：${[...types].join(',')}`);
  assert.ok(types.has('beaconing-interval'), '应检测周期性信标');
  assert.ok(types.has('large-upload'), '应检测大上传');
  assert.ok(types.has('rare-service-ports'), '应检测罕见服务端口');
  assert.ok(types.has('cleartext-http'), '应检测明文 HTTP');
  assert.ok(result.data.anomalyCount >= 5);
  const scanAnomaly = result.data.anomalies.find((anomaly) => anomaly.type === 'port-scan-fanout');
  assert.equal(scanAnomaly.metrics.distinctPorts, 20);
  assert.equal(scanAnomaly.metrics.src, '10.0.0.66');
  const beaconAnomaly = result.data.anomalies.find((anomaly) => anomaly.type === 'beaconing-interval');
  assert.equal(beaconAnomaly.metrics.meanGapSeconds, 10);
  assert.equal(beaconAnomaly.metrics.cv, 0);
  const uploadAnomaly = result.data.anomalies.find((anomaly) => anomaly.type === 'large-upload');
  assert.equal(uploadAnomaly.metrics.uploadBytes, 20 * uploadChunkSize);
  assert.equal(uploadAnomaly.metrics.downloadBytes, 0);
  // findings 验证等级：明文 HTTP=observed，其它启发式=hypothesis
  assert.ok(result.findings.length >= 5);
  const cleartextFinding = result.findings.find((finding) => /明文 HTTP/.test(finding.title));
  assert.ok(cleartextFinding);
  assert.equal(cleartextFinding.verification, 'observed');
  assert.equal(cleartextFinding.cwe, 'CWE-319');
  for (const finding of result.findings) {
    if (/明文 HTTP/.test(finding.title)) continue;
    assert.equal(finding.verification, 'hypothesis', `${finding.title} 是启发式，必须标 hypothesis`);
    assert.equal(finding.cvss, null);
    assert.ok(finding.evidence[0].excerpt.length > 0);
  }
  assert.equal(result.meta.thresholds.portScanDistinctPorts, 15);
  // 阈值调高后应屏蔽对应启发式
  const relaxed = await cap('network.anomalies').run(
    makeInput(pcap, { portScanDistinctPorts: 1000, rarePortMinFlows: 100000, beaconMinPackets: 1000, fanoutDistinctHosts: 1000 }),
  );
  const relaxedTypes = new Set(relaxed.data.anomalies.map((anomaly) => anomaly.type));
  assert.ok(!relaxedTypes.has('port-scan-fanout'));
  assert.ok(!relaxedTypes.has('beaconing-interval'));
  assert.ok(!relaxedTypes.has('rare-service-ports'));
  assert.ok(relaxedTypes.has('large-upload'));
});

test('network: 不支持的链路类型返回结构化告警而非崩溃', async () => {
  const frame = tcpPacket({ srcIp: '10.0.0.5', dstIp: '10.0.0.6', srcPort: 1000, dstPort: 2000, flags: { syn: true } });
  const pcap = buildPcap([{ ts: 1700000000, data: frame }], { linkType: 105 }); // 802.11
  const result = await cap('network.pcap_overview').run(makeInput(pcap));
  assert.equal(result.data.packetCount, 0);
  assert.equal(result.data.linkTypes[0].linkType, 105);
  assert.ok(result.data.unsupportedLinkTypes.some((entry) => entry.linkType === 105 && entry.count === 1));
  assert.equal(result.data.decodeErrors.length, 1);
  assert.match(result.data.decodeErrors[0].reason, /不支持的链路类型/);
});

test('network.anomalies: DNS NXDOMAIN 比例与 TLS 缺 SNI 启发式（直接单测）', () => {
  const risky = detectAnomalies(
    {
      flows: [],
      flowPackets: new Map(),
      dns: { responseCount: 30, nxdomainCount: 12, qtypeCounts: [{ type: 'A', count: 30 }] },
      tls: { sessionCount: 4, sessions: [{ sni: null }, { sni: null }, { sni: null }, { sni: 'example.com' }] },
      http: null,
    },
    {},
  );
  const riskyTypes = risky.anomalies.map((anomaly) => anomaly.type);
  assert.ok(riskyTypes.includes('dns-nxdomain-ratio'), `应命中 DNS NXDOMAIN，实际：${riskyTypes.join(',')}`);
  assert.ok(riskyTypes.includes('tls-no-sni'), '应命中 TLS 缺 SNI');
  const dnsAnomaly = risky.anomalies.find((anomaly) => anomaly.type === 'dns-nxdomain-ratio');
  assert.equal(dnsAnomaly.metrics.responses, 30);
  assert.equal(dnsAnomaly.metrics.nxdomain, 12);
  assert.equal(dnsAnomaly.metrics.ratio, 0.4);
  assert.equal(dnsAnomaly.severity, 'low');
  const tlsAnomaly = risky.anomalies.find((anomaly) => anomaly.type === 'tls-no-sni');
  assert.equal(tlsAnomaly.metrics.sessions, 4);
  assert.equal(tlsAnomaly.metrics.noSni, 3);
  // 低于阈值时不产生
  const quiet = detectAnomalies(
    {
      flows: [],
      flowPackets: new Map(),
      dns: { responseCount: 10, nxdomainCount: 1, qtypeCounts: [] },
      tls: { sessionCount: 2, sessions: [{ sni: null }, { sni: 'example.com' }] },
      http: null,
    },
    { dnsMinResponses: 20, dnsNxdomainRatio: 0.3, tlsMinSessions: 3, tlsNoSniRatio: 0.5 },
  );
  assert.equal(quiet.anomalies.length, 0);
});

test('network: Result 契约（summary/data 体积/meta 与全部 capability 可执行）', async () => {
  const dnsRecords = [
    { ts: 1700000000, data: udpPacket({ srcIp: '10.0.0.5', dstIp: '8.8.8.8', srcPort: 40000, dstPort: 53, payload: dnsQuery({ name: 'contract.example' }) }) },
    {
      ts: 1700000000.1,
      data: udpPacket({
        srcIp: '8.8.8.8',
        dstIp: '10.0.0.5',
        srcPort: 53,
        dstPort: 40000,
        payload: dnsResponse({ name: 'contract.example', answers: [{ type: 1, value: '93.184.216.34' }] }),
      }),
    },
  ];
  const httpConversation = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 34567,
    serverIp: '93.184.216.34',
    serverPort: 80,
    clientPayloads: [httpRequest({ uri: '/contract' })],
    serverPayloads: [httpResponse({ body: Buffer.from('ok') })],
  });
  const tlsConversation = tcpConversation({
    clientIp: '10.0.0.5',
    clientPort: 34568,
    serverIp: '93.184.216.34',
    serverPort: 443,
    clientPayloads: [buildClientHello({ sni: 'contract.example' })],
    serverPayloads: [buildServerHello()],
  });
  const pcap = buildPcap([...dnsRecords, ...httpConversation, ...tlsConversation]);
  const input = makeInput(pcap);
  for (const capability of networkManifest.capabilities) {
    if (capability.id === 'network.tshark') continue; // external tool + capture; covered by external-adapters-v2.test.mjs / Gate B
    const result = await capability.run(input);
    assert.equal(typeof result.summary, 'string', `${capability.id} summary 必须是字符串`);
    assert.ok(result.summary.length > 0 && result.summary.length <= 4000, `${capability.id} summary 长度为 1..4000`);
    assert.ok(Array.isArray(result.findings), `${capability.id} findings 必须是数组`);
    assert.ok(result.data && typeof result.data === 'object' && !Array.isArray(result.data), `${capability.id} data 必须是对象`);
    const dataBytes = Buffer.byteLength(JSON.stringify(result.data), 'utf8');
    assert.ok(dataBytes <= 256 * 1024, `${capability.id} data 体积 ${dataBytes} 超过 256KiB`);
    assert.ok(result.meta && typeof result.meta === 'object', `${capability.id} meta 必须是对象`);
    for (const finding of result.findings) {
      for (const key of ['title', 'severity', 'description', 'verification', 'method', 'cwe', 'cvss', 'remediation', 'target', 'evidence']) {
        assert.ok(key in finding, `${capability.id} finding 缺字段 ${key}`);
      }
      assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(finding.verification));
    }
  }
});

test('network: IP 分类与 data 预算裁剪工具', () => {
  assert.equal(classifyIp('10.1.2.3').category, 'private');
  assert.equal(classifyIp('192.168.1.1').isPrivate, true);
  assert.equal(classifyIp('93.184.216.34').isPublic, true);
  assert.equal(classifyIp('127.0.0.1').category, 'loopback');
  assert.equal(classifyIp('169.254.10.10').category, 'link-local');
  assert.equal(classifyIp('100.64.0.1').category, 'cgnat');
  assert.equal(classifyIp('::1').category, 'ipv6-loopback');
  assert.equal(classifyIp('fe80::1').category, 'ipv6-link-local');
  assert.equal(classifyIp('fd00::1').category, 'ipv6-ula');
  assert.equal(classifyIp('2001:db8::1').category, 'ipv6-documentation');
  const data = { items: Array.from({ length: 8000 }, (_, index) => ({ marker: 'y'.repeat(80), index })) };
  const trimmed = enforceDataBudget(data, 256 * 1024);
  assert.ok(Buffer.byteLength(JSON.stringify(trimmed), 'utf8') <= 256 * 1024);
  assert.equal(trimmed.dataBudget.truncated, true);
  assert.ok(trimmed.items.length < 8000);
  const small = { items: [1, 2, 3] };
  assert.deepEqual(enforceDataBudget(small, 256 * 1024), { items: [1, 2, 3] });
});

test('network: 空输入/不可识别输入报可操作错误，TCP 重组处理 seq 缺口', async () => {
  await assert.rejects(
    () => cap('network.flows').run(makeInput(Buffer.alloc(0))),
    (err) => {
      assert.match(err.message, /缺少可分析字节/);
      return true;
    },
  );
  await assert.rejects(
    () => cap('network.dns').run(makeInput(Buffer.from('this is not a capture file at all'))),
    (err) => {
      assert.match(err.message, /无法识别的抓包格式/);
      assert.match(err.message, /pcap/);
      return true;
    },
  );
  // 直接单测 TCP 重组：seq 缺口 + 重复段
  const base = { proto: 'tcp', payloadLength: 0, tsSeconds: 1 };
  const stream = reassembleTcpStream([
    { ...base, index: 1, tcpSeq: 1000, payload: Buffer.from('abc'), payloadLength: 3, tsSeconds: 1 },
    { ...base, index: 2, tcpSeq: 1013, payload: Buffer.from('def'), payloadLength: 3, tsSeconds: 2 }, // 缺口 10 字节
    { ...base, index: 3, tcpSeq: 1013, payload: Buffer.from('def'), payloadLength: 3, tsSeconds: 3 }, // 重复
  ]);
  assert.equal(stream.data.toString(), 'abcdef');
  assert.equal(stream.gaps, 1);
  assert.equal(stream.gapBytes, 10);
  assert.equal(stream.overlaps, 1);
  assert.equal(stream.truncated, false);
});
