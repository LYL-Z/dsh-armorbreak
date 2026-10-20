// ArmorBreak - 流（5 元组会话）重建与 TCP 单向流重组（纯 node:*）
// 所有聚合有上限；TCP 乱序只按 seq 追加（遇到缺口记 gap，不做完整重排），结果里标注 gaps。
import { portService, isEphemeralPort } from './util.js';

const TCP_FLAG_ORDER = ['syn', 'ack', 'psh', 'fin', 'rst', 'urg', 'ece', 'cwr'];

function endpointCompare(a, b) {
  // IP 字符串比较（IPv4/IPv6 各自内部一致；跨族极少见，用整体字符串）
  if (a.ip !== b.ip) return a.ip < b.ip ? -1 : 1;
  return a.port - b.port;
}

function isSameEndpoint(endpoint, packet) {
  return endpoint.ip === packet.src && endpoint.port === packet.srcPort;
}

/**
 * 根据解码后的报文构建流表。
 * @param {Array} packets
 * @param {{maxFlows?:number, keepPackets?:boolean, maxPacketsPerFlow?:number}} opts
 */
export function buildFlows(packets, opts = {}) {
  const maxFlows = Math.max(1, Math.min(opts.maxFlows ?? 2000, 50000));
  const keepPackets = opts.keepPackets !== false;
  const maxPacketsPerFlow = Math.max(1, Math.min(opts.maxPacketsPerFlow ?? 4096, 65536));
  const map = new Map();
  for (const packet of packets) {
    if (packet.proto !== 'tcp' && packet.proto !== 'udp') continue;
    if (!packet.src || !packet.dst || !Number.isInteger(packet.srcPort) || !Number.isInteger(packet.dstPort)) continue;
    const srcEp = { ip: packet.src, port: packet.srcPort };
    const dstEp = { ip: packet.dst, port: packet.dstPort };
    const cmp = endpointCompare(srcEp, dstEp);
    const a = cmp <= 0 ? srcEp : dstEp;
    const b = cmp <= 0 ? dstEp : srcEp;
    const key = `${packet.proto}|${a.ip}:${a.port}|${b.ip}:${b.port}`;
    let flow = map.get(key);
    if (!flow) {
      flow = {
        key,
        proto: packet.proto,
        a,
        b,
        packets: 0,
        bytes: 0,
        packetsByDirection: { ab: 0, ba: 0 },
        bytesByDirection: { ab: 0, ba: 0 },
        firstTs: Number.isFinite(packet.tsSeconds) ? packet.tsSeconds : null,
        lastTs: Number.isFinite(packet.tsSeconds) ? packet.tsSeconds : null,
        firstSide: null,
        firstPacketIndex: packet.index,
        tcpFlags: new Set(),
        synFrom: new Set(),
        synackFrom: new Set(),
        ackSeenFrom: new Set(),
        rstSeenFrom: new Set(),
        finSeenFrom: new Set(),
        packetsTruncated: false,
        directions: keepPackets ? { ab: [], ba: [] } : null,
      };
      map.set(key, flow);
    }
    const side = isSameEndpoint(a, packet) ? 'ab' : 'ba';
    if (flow.firstSide === null) flow.firstSide = side;
    if (!Number.isFinite(packet.tsSeconds)) {
      // SPB 无时间戳：保持 null 时间语义
    } else if (flow.firstTs === null || packet.tsSeconds < flow.firstTs) {
      flow.firstTs = packet.tsSeconds;
    }
    if (Number.isFinite(packet.tsSeconds) && (flow.lastTs === null || packet.tsSeconds > flow.lastTs)) {
      flow.lastTs = packet.tsSeconds;
    }
    flow.packets += 1;
    flow.bytes += packet.payloadLength || 0;
    flow.packetsByDirection[side] += 1;
    flow.bytesByDirection[side] += packet.payloadLength || 0;
    if (packet.proto === 'tcp' && packet.tcpFlags) {
      for (const flag of TCP_FLAG_ORDER) {
        if (packet.tcpFlags[flag]) flow.tcpFlags.add(flag);
      }
      if (packet.tcpFlags.syn) {
        flow.synFrom.add(side);
        if (packet.tcpFlags.ack) flow.synackFrom.add(side);
      }
      if (packet.tcpFlags.ack) flow.ackSeenFrom.add(side);
      if (packet.tcpFlags.rst) flow.rstSeenFrom.add(side);
      if (packet.tcpFlags.fin) flow.finSeenFrom.add(side);
    }
    if (flow.directions) {
      const dir = flow.directions[side];
      if (dir.length < maxPacketsPerFlow) dir.push(packet);
      else flow.packetsTruncated = true;
    }
  }

  const flows = [];
  const flowPackets = new Map();
  for (const flow of map.values()) {
    const serverSide = decideServerSide(flow);
    const clientSide = serverSide === 'ab' ? 'ba' : serverSide === 'ba' ? 'ab' : null;
    const serverEp = serverSide === 'ab' ? flow.a : serverSide === 'ba' ? flow.b : null;
    const clientEp = clientSide === 'ab' ? flow.a : clientSide === 'ba' ? flow.b : null;
    const state = decideState(flow);
    const duration =
      flow.firstTs !== null && flow.lastTs !== null ? Number((flow.lastTs - flow.firstTs).toFixed(6)) : null;
    const finalFlow = {
      id: flow.key,
      proto: flow.proto,
      endpoints: {
        a: flow.a,
        b: flow.b,
      },
      client: clientEp,
      server: serverEp,
      serverPort: serverEp ? serverEp.port : null,
      service: serverEp ? portService(serverEp.port) : null,
      packets: flow.packets,
      bytes: flow.bytes,
      packetsByDirection: flow.packetsByDirection,
      bytesByDirection: flow.bytesByDirection,
      firstTs: flow.firstTs,
      lastTs: flow.lastTs,
      duration,
      firstSide: flow.firstSide,
      state,
      tcpFlags: [...flow.tcpFlags].sort((a, b) => TCP_FLAG_ORDER.indexOf(a) - TCP_FLAG_ORDER.indexOf(b)),
      resetSeen: flow.rstSeenFrom.size > 0,
      finSeen: flow.finSeenFrom.size > 0,
      packetsTruncated: flow.packetsTruncated,
    };
    flows.push(finalFlow);
    if (flow.directions) flowPackets.set(flow.key, { flow: finalFlow, directions: flow.directions });
  }
  flows.sort((x, y) => {
    const tx = x.firstTs ?? Number.POSITIVE_INFINITY;
    const ty = y.firstTs ?? Number.POSITIVE_INFINITY;
    if (tx !== ty) return tx - ty;
    return x.id < y.id ? -1 : x.id > y.id ? 1 : 0;
  });
  const truncated = flows.length > maxFlows;
  const kept = flows.slice(0, maxFlows);
  const keptKeys = new Set(kept.map((f) => f.id));
  for (const key of flowPackets.keys()) if (!keptKeys.has(key)) flowPackets.delete(key);
  const stateCounts = new Map();
  const protoCounts = new Map();
  for (const flow of kept) {
    stateCounts.set(flow.state, (stateCounts.get(flow.state) || 0) + 1);
    protoCounts.set(flow.proto, (protoCounts.get(flow.proto) || 0) + 1);
  }
  return {
    flows: kept,
    flowPackets,
    truncated,
    flowCount: kept.length,
    totalFlowCount: flows.length,
    stateCounts: [...stateCounts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([state, count]) => ({ state, count })),
    protoCounts: [...protoCounts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([proto, count]) => ({ proto, count })),
  };
}

function decideServerSide(flow) {
  const candidates = [
    { side: 'ab', ep: flow.a },
    { side: 'ba', ep: flow.b },
  ];
  // 1) 公认服务端口
  for (const c of candidates) if (portService(c.ep.port)) return c.side;
  // 2) 特权端口
  const privileged = candidates.filter((c) => c.ep.port > 0 && c.ep.port < 1024);
  if (privileged.length === 1) return privileged[0].side;
  // 3) 非临时端口优先作为服务端
  const nonEphemeral = candidates.filter((c) => !isEphemeralPort(c.ep.port));
  if (nonEphemeral.length === 1) return nonEphemeral[0].side;
  if (flow.proto === 'tcp') {
    // 4) SYN/SYNACK 方向：发 SYN 的一侧是客户端
    if (flow.synFrom.size === 1) {
      const clientSide = [...flow.synFrom][0];
      return clientSide === 'ab' ? 'ba' : 'ab';
    }
  }
  // 5) 端口较小侧
  if (flow.a.port !== flow.b.port) return flow.a.port < flow.b.port ? 'ab' : 'ba';
  // 6) 首包发送方视为客户端
  if (flow.firstSide) return flow.firstSide === 'ab' ? 'ba' : 'ab';
  return null;
}

function decideState(flow) {
  if (flow.proto === 'udp') return 'datagram';
  const synSeen = flow.synFrom.size > 0;
  const synackSeen = flow.synackFrom.size > 0;
  const ackSeen = flow.ackSeenFrom.size > 0;
  const established = synackSeen && ackSeen;
  if (established && flow.rstSeenFrom.size > 0) return 'reset-after-established';
  if (established) return flow.finSeenFrom.size > 0 ? 'closed' : 'established';
  if (synackSeen) return 'half-open';
  if (synSeen) return flow.rstSeenFrom.size > 0 ? 'reset' : 'syn-sent';
  if (flow.rstSeenFrom.size > 0) return 'reset';
  return 'midstream';
}

/**
 * 单方向 TCP 字节流重组。
 * 语义：按捕获顺序追加 payload；seq 前向缺口计入 gaps（仍追加后续数据，不填零）；重复/重叠剪裁。
 * @param {Array} packets 同一方向的报文（按捕获顺序）
 * @param {{maxBytes?:number}} opts
 * @returns {{data:Buffer, gaps:number, gapBytes:number, overlaps:number, packetsUsed:number, truncated:boolean, firstSeq:number|null, lastSeq:number|null}}
 */
export function reassembleTcpStream(packets, opts = {}) {
  const maxBytes = Math.max(1, Math.min(opts.maxBytes ?? 8 * 1024 * 1024, 64 * 1024 * 1024));
  const chunks = [];
  let total = 0;
  let expected = null;
  let gaps = 0;
  let gapBytes = 0;
  let overlaps = 0;
  let packetsUsed = 0;
  let truncated = false;
  let firstSeq = null;
  let lastSeq = null;
  const ordered = [...packets].sort((a, b) => {
    const ta = Number.isFinite(a.tsSeconds) ? a.tsSeconds : 0;
    const tb = Number.isFinite(b.tsSeconds) ? b.tsSeconds : 0;
    if (ta !== tb) return ta - tb;
    return a.index - b.index;
  });
  for (const packet of ordered) {
    if (packet.proto !== 'tcp' || packet.payloadLength === 0) continue;
    const seq = packet.tcpSeq >>> 0;
    const payload = packet.payload;
    if (firstSeq === null) firstSeq = seq;
    lastSeq = (seq + payload.length) >>> 0;
    let offset = 0;
    if (expected !== null) {
      const delta = (seq - expected) >>> 0;
      if (delta === 0) {
        offset = 0;
      } else if (delta < 0x80000000) {
        // seq 前向缺口：记 gap，继续追加
        gaps += 1;
        gapBytes += delta;
        offset = 0;
      } else {
        // seq 回退/重叠：剪裁已覆盖部分
        const overlap = (expected - seq) >>> 0;
        if (overlap >= payload.length) {
          overlaps += 1;
          continue;
        }
        offset = overlap;
        overlaps += 1;
      }
    }
    if (total + (payload.length - offset) > maxBytes) {
      const room = maxBytes - total;
      if (room > 0) chunks.push(payload.subarray(offset, offset + room));
      total = maxBytes;
      truncated = true;
      packetsUsed += 1;
      break;
    }
    if (payload.length - offset > 0) {
      chunks.push(payload.subarray(offset));
      total += payload.length - offset;
    }
    expected = (seq + payload.length) >>> 0;
    packetsUsed += 1;
  }
  return {
    data: chunks.length > 0 ? Buffer.concat(chunks, total) : Buffer.alloc(0),
    gaps,
    gapBytes,
    overlaps,
    packetsUsed,
    truncated,
    firstSeq,
    lastSeq,
  };
}

/**
 * 根据流表条目（buildFlows 的 flowPackets value）重组客户端->服务端、服务端->客户端两条流。
 * 客户端方向由 decideServerSide 的结果决定；无法判定时用首包发送方为客户端。
 */
export function buildFlowStreams(entry, opts = {}) {
  if (!entry) return null;
  const { flow, directions } = entry;
  let serverSide;
  if (flow.server && flow.server === flow.endpoints.a) serverSide = 'ab';
  else if (flow.server && flow.server === flow.endpoints.b) serverSide = 'ba';
  else serverSide = flow.firstSide === 'ab' ? 'ba' : 'ab';
  const clientSide = serverSide === 'ab' ? 'ba' : 'ab';
  const clientToServer = reassembleTcpStream(directions[clientSide], opts);
  const serverToClient = reassembleTcpStream(directions[serverSide], opts);
  return { clientToServer, serverToClient, clientSide, serverSide };
}

/** 流表摘要友好端点文本。 */
export function formatEndpoint(ep) {
  if (!ep) return '?';
  if (ep.ip.includes(':')) return `[${ep.ip}]:${ep.port}`;
  return `${ep.ip}:${ep.port}`;
}
