// ArmorBreak - network 域能力清单（离线 pcap/pcapng 流量分析）
// 契约见 docs/CONTRACT.md：run(input) -> { summary, findings?, evidence?, data, meta? }
import { loadCapture, protocolHistogram, ipVersionHistogram, topTalkers, portHistogram } from './capture.js';
import { buildFlows, formatEndpoint } from './flows.js';
import { collectDns } from './dns.js';
import { scanTlsSessions } from './tls.js';
import { scanHttpStreams } from './http.js';
import { detectAnomalies, DEFAULT_THRESHOLDS } from './anomalies.js';
import {
  optionsOf,
  limitsOf,
  limitOf,
  sanitizeText,
  humanBytes,
  makeResult,
  checkAbort,
  classifyIp,
  isoTime,
} from './util.js';

// ---------------------------------------------------------------------------
// 共享辅助
// ---------------------------------------------------------------------------

const MAX_PACKETS_PROP = { type: 'integer', minimum: 1, maximum: 200000, description: '最多解码的报文数（超出截断）' };

function params(properties) {
  return { type: 'object', properties: { maxPackets: MAX_PACKETS_PROP, ...properties }, additionalProperties: false };
}

function load(input, options) {
  const limits = limitsOf(input);
  const capture = loadCapture(input, options, limits);
  return { capture, limits };
}

function captureMeta(capture, extra = {}) {
  return {
    format: capture.format,
    endianness: capture.endianness,
    truncated: capture.truncated || Boolean(extra.truncated),
    warnings: [...capture.warnings, ...(extra.warnings || [])].slice(0, 20),
    decodeErrorCount: capture.decodeErrors.length,
    maxPackets: capture.maxPackets,
    ...(extra.meta || {}),
  };
}

function endpointJson(ep) {
  if (!ep) return null;
  return { ip: ep.ip, port: ep.port };
}

function timeRangeText(capture) {
  if (!capture.firstPacketIso) return '时间范围：不可用';
  return `时间范围 ${capture.firstPacketIso} ~ ${capture.lastPacketIso}（${capture.durationSeconds}s）`;
}

function domainLooksValid(value) {
  if (typeof value !== 'string') return false;
  const lower = value.toLowerCase().replace(/\.$/, '');
  if (lower.length < 3 || lower.length > 253) return false;
  if (/^\d+(\.\d+){3}$/.test(lower)) return false;
  return /^[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?(\.[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?)+$/.test(lower);
}

function hostWithoutPort(host) {
  if (typeof host !== 'string') return null;
  const trimmed = host.trim();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    if (end > 0) return trimmed.slice(1, end);
  }
  const lastColon = trimmed.lastIndexOf(':');
  if (lastColon > 0 && trimmed.indexOf(':') === lastColon) return trimmed.slice(0, lastColon);
  return trimmed;
}

function looksLikeIp(value) {
  if (typeof value !== 'string') return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return true;
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value);
}

/** 把 ISO 时间字符串或秒级时间戳转成 epoch 毫秒（无法解析返回 null）。 */
function toEpochMs(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value * 1000;
  if (typeof value === 'string') {
    const ms = Date.parse(value);
    return Number.isFinite(ms) ? ms : null;
  }
  return null;
}

function isoFromMs(ms) {
  return ms === null ? null : new Date(ms).toISOString();
}

/** 从 flows/dns/tls/http 汇总 IOC（观测指标，不含威胁情报定性）。 */
function collectIocs({ capture, flowsResult, dnsResult, tlsResult, httpResult }, maxItems) {
  const ipEntries = new Map();
  for (const packet of capture.packets) {
    for (const [ip, role] of [
      [packet.src, 'src'],
      [packet.dst, 'dst'],
    ]) {
      if (!ip) continue;
      const entry = ipEntries.get(ip) || { ip, packets: 0, bytes: 0, srcPackets: 0, dstPackets: 0, firstTs: null, lastTs: null };
      entry.packets += 1;
      entry.bytes += packet.payloadLength || 0;
      if (role === 'src') entry.srcPackets += 1;
      else entry.dstPackets += 1;
      if (Number.isFinite(packet.tsSeconds)) {
        if (entry.firstTs === null || packet.tsSeconds < entry.firstTs) entry.firstTs = packet.tsSeconds;
        if (entry.lastTs === null || packet.tsSeconds > entry.lastTs) entry.lastTs = packet.tsSeconds;
      }
      ipEntries.set(ip, entry);
    }
  }
  const ipList = [...ipEntries.values()].map((entry) => {
    const cls = classifyIp(entry.ip);
    return {
      ...entry,
      category: cls.category,
      categoryLabel: cls.label,
      isPublic: cls.isPublic,
      isPrivate: cls.isPrivate,
      firstSeen: isoTime(entry.firstTs),
      lastSeen: isoTime(entry.lastTs),
    };
  });
  const byCategory = new Map();
  for (const entry of ipList) {
    const prev = byCategory.get(entry.category) || { category: entry.category, label: entry.categoryLabel, distinctCount: 0 };
    prev.distinctCount += 1;
    byCategory.set(entry.category, prev);
  }
  const sortIp = (a, b) => b.packets - a.packets || a.ip.localeCompare(b.ip);
  const publicIps = ipList
    .filter((entry) => entry.isPublic)
    .sort(sortIp)
    .slice(0, maxItems)
    .map((entry) => ({
      ip: entry.ip,
      packets: entry.packets,
      bytes: entry.bytes,
      srcPackets: entry.srcPackets,
      dstPackets: entry.dstPackets,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
    }));
  const privateIps = ipList
    .filter((entry) => entry.isPrivate && entry.category !== 'loopback')
    .sort(sortIp)
    .slice(0, Math.min(maxItems, 50))
    .map((entry) => ({
      ip: entry.ip,
      category: entry.category,
      packets: entry.packets,
      bytes: entry.bytes,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
    }));

  // 域名来源：DNS 问题/答案、TLS SNI、HTTP Host
  const domainMap = new Map();
  const addDomain = (rawDomain, source, seenAt) => {
    const domain = hostWithoutPort(String(rawDomain ?? '')).toLowerCase().replace(/\.$/, '');
    if (!domainLooksValid(domain)) return;
    const entry = domainMap.get(domain) || { domain, sources: new Set(), count: 0, firstMs: null };
    entry.sources.add(source);
    entry.count += 1;
    const ms = toEpochMs(seenAt);
    if (ms !== null && (entry.firstMs === null || ms < entry.firstMs)) entry.firstMs = ms;
    domainMap.set(domain, entry);
  };
  if (dnsResult) {
    for (const entry of dnsResult.names) addDomain(entry.name, 'dns', entry.firstSeen);
    for (const answer of dnsResult.answers) {
      if (answer.type === 'CNAME' || answer.type === 'NS' || answer.type === 'PTR') addDomain(answer.value, 'dns-answer', null);
    }
  }
  if (tlsResult) {
    for (const session of tlsResult.sessions) if (session.sni) addDomain(session.sni, 'tls-sni', session.firstSeen);
  }
  if (httpResult) {
    for (const entry of httpResult.hosts) addDomain(entry.host, 'http-host', entry.firstSeen);
  }
  const domains = [...domainMap.values()]
    .map((entry) => ({ domain: entry.domain, sources: [...entry.sources].sort(), count: entry.count, firstSeen: isoFromMs(entry.firstMs) }))
    .sort((a, b) => b.count - a.count || a.domain.localeCompare(b.domain))
    .slice(0, maxItems);

  // URI：仅明文 HTTP 请求可还原；查询参数值脱敏（http.js 已处理）
  const uriMap = new Map();
  if (httpResult) {
    for (const request of httpResult.requests) {
      const host = request.host ?? null;
      if (!host) continue;
      const uri = `http://${host}${request.uri.startsWith('/') ? '' : '/'}${request.uri}`;
      const prev = uriMap.get(uri) || { uri, method: request.method, host, count: 0, firstMs: null };
      prev.count += 1;
      const ms = toEpochMs(request.firstSeen);
      if (ms !== null && (prev.firstMs === null || ms < prev.firstMs)) prev.firstMs = ms;
      uriMap.set(uri, prev);
    }
  }
  const uris = [...uriMap.values()]
    .sort((a, b) => b.count - a.count || a.uri.localeCompare(b.uri))
    .slice(0, maxItems)
    .map((entry) => ({ uri: entry.uri, method: entry.method, host: entry.host, count: entry.count, firstSeen: isoFromMs(entry.firstMs) }));

  // 流级角色统计补充：对外连接的服务端 IP
  const serverIps = new Map();
  if (flowsResult) {
    for (const flow of flowsResult.flows) {
      if (!flow.server) continue;
      serverIps.set(flow.server.ip, (serverIps.get(flow.server.ip) || 0) + 1);
    }
  }
  const serverIpList = [...serverIps.entries()]
    .map(([ip, flowCount]) => ({ ip, flowCount, category: classifyIp(ip).category }))
    .sort((a, b) => b.flowCount - a.flowCount || a.ip.localeCompare(b.ip))
    .slice(0, maxItems);

  return {
    ipClassification: [...byCategory.values()].sort((a, b) => b.distinctCount - a.distinctCount || a.category.localeCompare(b.category)),
    publicIps,
    privateIps,
    serverIps: serverIpList,
    domains,
    uris,
    counts: {
      distinctIps: ipList.length,
      publicIps: publicIps.length,
      privateIps: privateIps.length,
      domains: domains.length,
      uris: uris.length,
    },
    note: '以上为抓包中观测到的指标（IP/域名/URI），仅作 IOC 线索，不代表已确认的恶意或威胁情报定性。',
  };
}

// ---------------------------------------------------------------------------
// 能力实现
// ---------------------------------------------------------------------------

export const capabilities = [
  {
    id: 'network.pcap_overview',
    title: '抓包文件概览',
    description:
      '离线解析经典 pcap 与 pcapng（多 Section/多接口）：格式、字节序、链路类型、报文数与字节数、时间范围、协议直方图、IP 版本分布、Top 交谈方与目的端口。用于快速了解流量规模与构成，再决定深入 flows/dns/tls/http。',
    riskLevel: 'L0',
    params: params({}),
    async run(input) {
      const options = optionsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const protocols = protocolHistogram(capture.packets);
      const sectors = capture.sections
        ? capture.sections.map((section) => ({
            index: section.index,
            endianness: section.endianness,
            version: section.version,
            interfaceCount: section.interfaces.length,
            packetCount: section.packetCount,
          }))
        : null;
      let tcpSyn = 0;
      let tcpRst = 0;
      let tcpFin = 0;
      let fragmented = 0;
      let retransmissionLike = 0;
      const seqSeen = new Set();
      for (const packet of capture.packets) {
        if (packet.proto === 'tcp' && packet.tcpFlags) {
          if (packet.tcpFlags.syn && !packet.tcpFlags.ack) tcpSyn++;
          if (packet.tcpFlags.rst) tcpRst++;
          if (packet.tcpFlags.fin) tcpFin++;
          if (packet.payloadLength > 0) {
            const key = `${packet.src}|${packet.srcPort}|${packet.dst}|${packet.dstPort}|${packet.tcpSeq}|${packet.payloadLength}`;
            if (seqSeen.has(key)) retransmissionLike++;
            else if (seqSeen.size < 200000) seqSeen.add(key);
          }
        }
        if (packet.fragmented) fragmented++;
      }
      const data = {
        format: capture.format,
        endianness: capture.endianness,
        nanosecondTimestamps: capture.nanosecond,
        snaplen: capture.snaplen,
        sections: sectors,
        interfaces: capture.interfaces,
        linkTypes: capture.linkTypes,
        packetCount: capture.decodedCount,
        rawPacketCount: capture.rawPacketCount,
        decodeErrors: capture.decodeErrors,
        unsupportedLinkTypes: capture.unsupportedLinkTypes,
        capturedBytes: capture.capturedBytes,
        originalBytes: capture.originalBytes,
        firstPacketIso: capture.firstPacketIso,
        lastPacketIso: capture.lastPacketIso,
        durationSeconds: capture.durationSeconds,
        protocols,
        ipVersions: ipVersionHistogram(capture.packets),
        topTalkers: topTalkers(capture.packets, 10),
        topDestinationPorts: portHistogram(capture.packets, { serverSide: true, limit: 15 }),
        tcp: { synCount: tcpSyn, resetCount: tcpRst, finCount: tcpFin, retransmissionLikeCount: retransmissionLike },
        fragmentedPacketCount: fragmented,
        truncated: capture.truncated,
      };
      const protoText = protocols.slice(0, 6).map((p) => `${p.proto}=${p.count}`).join('/');
      const summary = [
        `抓包概览：${capture.format}（${capture.endianness ?? 'n/a'} 字节序）`,
        capture.format === 'pcapng' ? `${capture.sections?.length ?? 0} 个 Section / ${capture.interfaces.length} 个接口` : `链路类型 ${capture.linkTypes.map((l) => l.name).join(',')}`,
        `${capture.decodedCount} 个报文（捕获 ${humanBytes(capture.capturedBytes)} / 原始 ${humanBytes(capture.originalBytes)}）`,
        protoText ? `协议 ${protoText}` : null,
        timeRangeText(capture),
        `SYN ${tcpSyn} / RST ${tcpRst}`,
        capture.truncated ? '抓包截断' : null,
        capture.decodeErrors.length > 0 ? `解码失败 ${capture.decodeErrors.length} 例` : null,
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data,
        meta: captureMeta(capture),
      });
    },
  },

  {
    id: 'network.flows',
    title: 'TCP/UDP 会话流重建',
    description:
      '按 5 元组（协议 + 双端 IP/端口）聚合成会话：双方向包数/字节数、首末时间、持续时间、TCP 状态启发式（established/half-open/reset/midstream）、客户端/服务端判定与服务名。用于梳理连接关系与主机通信画像。',
    riskLevel: 'L0',
    params: params({
      maxFlows: { type: 'integer', minimum: 1, maximum: 50000, description: '最多返回的流数量' },
    }),
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const maxFlows = limitOf(options.maxFlows, limits.maxItems, 1, 50000);
      const flowsResult = buildFlows(capture.packets, { maxFlows, keepPackets: false });
      checkAbort(input);
      const data = {
        flowCount: flowsResult.flowCount,
        totalFlowCount: flowsResult.totalFlowCount,
        protoCounts: flowsResult.protoCounts,
        stateCounts: flowsResult.stateCounts,
        flows: flowsResult.flows.map((flow) => ({
          id: flow.id,
          proto: flow.proto,
          client: endpointJson(flow.client),
          server: endpointJson(flow.server),
          serverPort: flow.serverPort,
          service: flow.service,
          packets: flow.packets,
          bytes: flow.bytes,
          bytesByDirection: flow.bytesByDirection,
          firstSeen: isoTime(flow.firstTs),
          lastSeen: isoTime(flow.lastTs),
          durationSeconds: flow.duration,
          state: flow.state,
          tcpFlags: flow.tcpFlags,
          resetSeen: flow.resetSeen,
          finSeen: flow.finSeen,
        })),
        truncated: flowsResult.truncated,
      };
      const topStates = flowsResult.stateCounts.slice(0, 4).map((s) => `${s.state}=${s.count}`).join('/');
      const summary = [
        `会话流：${flowsResult.flowCount} 条（TCP/UDP；上限 ${maxFlows}${flowsResult.truncated ? '，已截断' : ''}）`,
        topStates ? `状态 ${topStates}` : null,
        `TCP ${flowsResult.protoCounts.find((p) => p.proto === 'tcp')?.count ?? 0} 条 / UDP ${flowsResult.protoCounts.find((p) => p.proto === 'udp')?.count ?? 0} 条`,
        capture.truncated ? '抓包截断，吞吐为下界' : null,
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data,
        meta: captureMeta(capture, { truncated: flowsResult.truncated }),
      });
    },
  },

  {
    id: 'network.dns',
    title: 'DNS 查询/响应分析',
    description:
      '解析 UDP/TCP DNS 报文：查询与响应数量、QNAME/QTYPE、响应码（NXDOMAIN/SERVFAIL 等）、A/AAAA/CNAME/MX/TXT 等答案、客户端->解析器配对与高频域名。用于发现域名访问、解析失败与可疑解析行为。',
    riskLevel: 'L0',
    params: params({
      maxMessages: { type: 'integer', minimum: 1, maximum: 20000, description: '最多处理的 DNS 报文数' },
      maxAnswers: { type: 'integer', minimum: 1, maximum: 128, description: '单条响应最多解析的答案数' },
      maxNames: { type: 'integer', minimum: 1, maximum: 2000, description: '最多返回的域名/解析器对数' },
    }),
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const dns = collectDns(capture.packets, {
        maxMessages: limitOf(options.maxMessages, 2000, 1, 20000),
        maxAnswers: limitOf(options.maxAnswers, 32, 1, 128),
        maxNames: limitOf(options.maxNames, Math.min(limits.maxStrings, 200), 1, 2000),
        maxSamples: Math.min(limits.maxItems, 50),
      });
      checkAbort(input);
      const data = {
        ...dns,
        truncated: dns.truncated || capture.truncated,
      };
      const summary = [
        `DNS：报文 ${dns.messageCount}（查询 ${dns.queryCount} / 响应 ${dns.responseCount}）`,
        dns.nxdomainCount > 0 ? `NXDOMAIN ${dns.nxdomainCount}` : null,
        dns.servfailCount > 0 ? `SERVFAIL ${dns.servfailCount}` : null,
        dns.parseErrors > 0 ? `解析失败 ${dns.parseErrors}` : null,
        dns.qtypeCounts.length > 0 ? `QTYPE ${dns.qtypeCounts.slice(0, 5).map((q) => `${q.type}=${q.count}`).join('/')}` : null,
        dns.resolverPairs.length > 0 ? `客户端->解析器 ${dns.resolverPairs.length} 组` : null,
        dns.queries.length > 0 ? `高频域名：${dns.queries.slice(0, 3).map((q) => q.name).join(', ')}` : null,
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data,
        meta: captureMeta(capture, { truncated: data.truncated }),
      });
    },
  },

  {
    id: 'network.tls',
    title: 'TLS 握手与 SNI 分析',
    description:
      '在 TCP 单向流重组基础上解析 TLS record/handshake：ClientHello 的 SNI、ALPN、支持版本、密码套件与 GREASE 过滤后的 JA3-like 指纹，ServerHello 的协商版本/密码套件。用于识别加密访问目的地与客户端指纹；不验证证书链、不解密应用数据。',
    riskLevel: 'L0',
    params: params({
      maxSessions: { type: 'integer', minimum: 1, maximum: 5000, description: '最多返回的 TLS 会话数' },
    }),
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const maxSessions = limitOf(options.maxSessions, limits.maxItems, 1, 5000);
      const flowsResult = buildFlows(capture.packets, { maxFlows: Math.min(limits.maxItems * 5, 5000), keepPackets: true });
      const tls = scanTlsSessions(flowsResult.flowPackets, { maxSessions, maxStreamBytes: Math.min(limits.maxBytes, 512 * 1024) });
      checkAbort(input);
      const sniCounts = new Map();
      const versionCounts = new Map();
      const alpnCounts = new Map();
      const ja3Clusters = new Map();
      for (const session of tls.sessions) {
        if (session.sni) sniCounts.set(session.sni, (sniCounts.get(session.sni) || 0) + 1);
        if (session.selectedVersion) versionCounts.set(session.selectedVersion, (versionCounts.get(session.selectedVersion) || 0) + 1);
        for (const proto of session.alpn) alpnCounts.set(proto, (alpnCounts.get(proto) || 0) + 1);
        if (session.ja3LikeSha256) {
          const cluster = ja3Clusters.get(session.ja3LikeSha256) || { sha256: session.ja3LikeSha256, ja3Like: session.ja3Like, count: 0, sampleSni: [] };
          cluster.count += 1;
          if (session.sni && cluster.sampleSni.length < 5 && !cluster.sampleSni.includes(session.sni)) cluster.sampleSni.push(session.sni);
          ja3Clusters.set(session.ja3LikeSha256, cluster);
        }
      }
      const sorted = (map) => [...map.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([value, count]) => ({ value, count }));
      const data = {
        sessionCount: tls.sessionCount,
        candidateFlowCount: tls.candidateFlowCount,
        sessions: tls.sessions,
        sniValues: sorted(sniCounts).map((entry) => ({ sni: entry.value, count: entry.count })),
        versionCounts: sorted(versionCounts).map((entry) => ({ version: entry.value, count: entry.count })),
        alpnCounts: sorted(alpnCounts).map((entry) => ({ protocol: entry.value, count: entry.count })),
        ja3Clusters: [...ja3Clusters.values()].sort((a, b) => b.count - a.count || a.sha256.localeCompare(b.sha256)).slice(0, 20),
        truncated: tls.truncated || capture.truncated,
      };
      const summary = [
        `TLS：识别 ${tls.sessionCount} 个会话（候选 TCP 流 ${tls.candidateFlowCount}）`,
        data.sniValues.length > 0 ? `SNI ${data.sniValues.length} 个（${data.sniValues.slice(0, 5).map((s) => s.sni).join(', ')}）` : '未提取到 SNI',
        data.versionCounts.length > 0 ? `版本 ${data.versionCounts.map((v) => `${v.version}=${v.count}`).join('/')}` : null,
        data.ja3Clusters.length > 0 ? `JA3-like 指纹 ${data.ja3Clusters.length} 类` : null,
        '未验证证书链/未解密应用数据',
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data,
        meta: captureMeta(capture, { truncated: data.truncated }),
      });
    },
  },

  {
    id: 'network.http',
    title: '明文 HTTP 请求/响应分析',
    description:
      '从 TCP 流重组结果中解析明文 HTTP/1.x 请求行、响应行与头部（Host/User-Agent/Content-Type/Server 等），统计状态码、主机与 URI；Authorization/Cookie 等敏感头值脱敏。用于分析业务接口、上传/下载与明文凭据线索。',
    riskLevel: 'L0',
    params: params({
      maxStreams: { type: 'integer', minimum: 1, maximum: 2000, description: '最多解析的 HTTP 流数量' },
      maxMessages: { type: 'integer', minimum: 1, maximum: 500, description: '每个方向最多解析的 HTTP 消息数' },
    }),
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const flowsResult = buildFlows(capture.packets, { maxFlows: Math.min(limits.maxItems * 5, 20000), keepPackets: true });
      const http = scanHttpStreams(flowsResult.flowPackets, {
        maxStreams: limitOf(options.maxStreams, Math.min(limits.maxItems, 100), 1, 2000),
        maxMessages: limitOf(options.maxMessages, 50, 1, 500),
        maxStreamBytes: Math.min(limits.maxBytes, 512 * 1024),
      });
      checkAbort(input);
      const requestSample = http.requests.slice(0, Math.min(limits.maxItems, 100));
      const responseSample = http.responses.slice(0, Math.min(limits.maxItems, 100));
      const transactionSample = http.transactions.slice(0, Math.min(limits.maxItems, 50)).map((t) => ({
        request: t.request,
        response: t.response,
        pairing: t.pairing,
      }));
      const data = {
        streamCount: http.streamCount,
        requestCount: http.requestCount,
        responseCount: http.responseCount,
        requests: requestSample,
        responses: responseSample,
        transactions: transactionSample,
        streams: http.streams,
        hosts: http.hosts,
        userAgents: http.userAgents,
        statusCodes: http.statusCodes,
        servers: http.servers,
        parseErrors: http.parseErrors,
        redaction: { headers: ['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token'], uriQueryParams: 'token/key/secret/password/auth/session 类参数值已脱敏' },
        truncated: http.truncated || capture.truncated,
      };
      const summary = [
        `明文 HTTP：${http.streamCount} 条流，请求 ${http.requestCount} / 响应 ${http.responseCount}`,
        http.hosts.length > 0 ? `主机 ${http.hosts.slice(0, 5).map((h) => h.host).join(', ')}` : null,
        http.statusCodes.length > 0 ? `状态码 ${http.statusCodes.map((s) => `${s.status}=${s.count}`).join('/')}` : null,
        http.parseErrors > 0 ? `解析告警 ${http.parseErrors}` : null,
        '敏感头已脱敏',
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data,
        meta: captureMeta(capture, { truncated: data.truncated, meta: { parseErrors: http.parseErrors } }),
      });
    },
  },

  {
    id: 'network.iocs',
    title: '网络 IOC 线索提取',
    description:
      '从抓包汇总观测型 IOC：IP（公网/私有/回环/链路本地等分类与包数）、域名（来自 DNS/SNI/HTTP Host）、明文 URI 与对外服务端列表。用于输出可复核的指标清单，不包含威胁情报定性。',
    riskLevel: 'L0',
    params: params({
      maxItems: { type: 'integer', minimum: 1, maximum: 2000, description: '每类 IOC 最多返回数量' },
    }),
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const maxItems = limitOf(options.maxItems, limits.maxItems, 1, 2000);
      const flowsResult = buildFlows(capture.packets, { maxFlows: Math.min(limits.maxItems * 5, 5000), keepPackets: false });
      const dnsResult = collectDns(capture.packets, { maxMessages: 4000, maxAnswers: 16, maxNames: Math.min(limits.maxStrings, 300), maxSamples: 20 });
      const httpResult = scanHttpStreams(
        buildFlows(capture.packets, { maxFlows: Math.min(limits.maxItems * 3, 500), keepPackets: true }).flowPackets,
        { maxStreams: Math.min(limits.maxItems, 100), maxMessages: 20, maxStreamBytes: 256 * 1024 },
      );
      const tlsResult = scanTlsSessions(
        buildFlows(capture.packets, { maxFlows: Math.min(limits.maxItems * 3, 500), keepPackets: true }).flowPackets,
        { maxSessions: Math.min(limits.maxItems, 100), maxStreamBytes: 256 * 1024 },
      );
      checkAbort(input);
      const iocs = collectIocs({ capture, flowsResult, dnsResult, tlsResult, httpResult }, maxItems);
      const data = {
        ...iocs,
        sources: {
          dnsMessages: dnsResult.messageCount,
          httpRequests: httpResult.requestCount,
          tlsSessions: tlsResult.sessionCount,
          flows: flowsResult.flowCount,
        },
        truncated: capture.truncated,
      };
      const summary = [
        `IOC 线索：${iocs.counts.distinctIps} 个 IP（公网 ${iocs.counts.publicIps} / 私有 ${iocs.counts.privateIps}）`,
        `域名 ${iocs.counts.domains} 个`,
        `URI ${iocs.counts.uris} 条`,
        iocs.publicIps.length > 0 ? `公网样例：${iocs.publicIps.slice(0, 5).map((i) => i.ip).join(', ')}` : null,
        '仅观测指标，无威胁情报定性',
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data,
        meta: captureMeta(capture, { truncated: data.truncated }),
      });
    },
  },

  {
    id: 'network.anomalies',
    title: '网络异常启发式检测',
    description:
      '基于流表与报文时序的启发式检测：同源对同目标大量端口的扫描扇出、横向主机扇出、周期性信标（包间隔 CV）、大流量上传、罕见服务端口、DNS NXDOMAIN 偏高、TLS 缺 SNI、明文 HTTP。所有异常标注 hypothesis，须人工复核；findings 不做已确认攻击断言。',
    riskLevel: 'L0',
    params: params({
      portScanDistinctPorts: { type: 'integer', minimum: 2, maximum: 10000, description: '端口扫描判定阈值（同源对同目标的不同目的端口数）' },
      fanoutDistinctHosts: { type: 'integer', minimum: 2, maximum: 10000, description: '横向扇出判定阈值（同源不同目标 IP 数）' },
      beaconMinPackets: { type: 'integer', minimum: 2, maximum: 1000, description: '信标检测所需最少报文数' },
      beaconMaxCv: { type: 'number', minimum: 0, maximum: 5, description: '信标判定：间隔变异系数上限（越小越严格）' },
      largeUploadBytes: { type: 'integer', minimum: 1, maximum: 1073741824, description: '大上传判定阈值（客户端方向字节数）' },
      rarePortMinFlows: { type: 'integer', minimum: 1, maximum: 100000, description: '罕见端口判定阈值（该服务端口的流数）' },
      maxFlows: { type: 'integer', minimum: 1, maximum: 50000, description: '参与分析的最大流数量' },
    }),
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { capture } = load(input, options);
      const flowsResult = buildFlows(capture.packets, {
        maxFlows: limitOf(options.maxFlows, Math.min(limits.maxItems * 10, 20000), 1, 50000),
        keepPackets: true,
        maxPacketsPerFlow: 2048,
      });
      const dnsResult = collectDns(capture.packets, { maxMessages: 4000, maxAnswers: 8, maxNames: 100, maxSamples: 0 });
      const httpResult = scanHttpStreams(flowsResult.flowPackets, {
        maxStreams: Math.min(limits.maxItems, 100),
        maxMessages: 20,
        maxStreamBytes: 256 * 1024,
      });
      const tlsResult = scanTlsSessions(flowsResult.flowPackets, { maxSessions: Math.min(limits.maxItems, 100), maxStreamBytes: 256 * 1024 });
      checkAbort(input);
      const result = detectAnomalies(
        { flows: flowsResult.flows, flowPackets: flowsResult.flowPackets, dns: dnsResult, http: httpResult, tls: tlsResult },
        {
          portScanDistinctPorts: options.portScanDistinctPorts,
          fanoutDistinctHosts: options.fanoutDistinctHosts,
          beaconMinPackets: options.beaconMinPackets,
          beaconMaxCv: options.beaconMaxCv,
          largeUploadBytes: options.largeUploadBytes,
          rarePortMinFlows: options.rarePortMinFlows,
        },
      );
      const anomalies = result.anomalies.slice(0, Math.min(limits.maxFindings, 50));
      const methodFor = {
        'port-scan-fanout': '流表聚合：同源->同目标不同目的端口数阈值判定',
        'host-fanout': '流表聚合：同源不同目标 IP 数阈值判定',
        'beaconing-interval': '同流客户端方向包间隔均值/标准差（变异系数）判定',
        'large-upload': '流内客户端方向字节数与上传/下载比判定',
        'rare-service-ports': '服务端口白名单 + 每端口流数阈值判定',
        'dns-nxdomain-ratio': 'DNS 响应码统计：NXDOMAIN 占比阈值判定',
        'tls-no-sni': 'TLS ClientHello SNI 缺失比例判定',
        'cleartext-http': 'TCP 流重组后明文 HTTP 解析（观测）',
      };
      const remediationFor = {
        'port-scan-fanout': '确认源主机是否被入侵或为授权扫描器；被扫描目标建议临时封禁源 IP 并检查服务暴露面。',
        'host-fanout': '确认是否为授权扫描/业务批量访问；异常时隔离源主机并排查横向移动痕迹。',
        'beaconing-interval': '结合域名信誉与进程网络行为复核；必要时对目标域名/IP 做封禁与取证。',
        'large-upload': '确认上传目的地与数据敏感性；审计进程与用户行为，必要时限制出站流量。',
        'rare-service-ports': '确认非标准端口服务是否为已知业务；未知服务建议进一步做协议识别与服务指纹。',
        'dns-nxdomain-ratio': '检查 DNS 日志与主机进程；排查 DGA 或域名隧道，关注高频长随机域名。',
        'tls-no-sni': '结合目标 IP、JA3-like 指纹与进程行为复核；对异常目的的 TLS 流量做进一步取证。',
        'cleartext-http': '推动业务迁移 HTTPS；对明文登录/Token 场景立即整改并检查凭据是否泄露。',
      };
      const findings = anomalies.map((anomaly) => ({
        title: sanitizeText(anomaly.title, 160),
        severity: anomaly.severity,
        description: sanitizeText(anomaly.description, 2000),
        verification: anomaly.type === 'cleartext-http' ? 'observed' : 'hypothesis',
        method: methodFor[anomaly.type] ?? '启发式流量统计',
        cwe: anomaly.type === 'cleartext-http' ? 'CWE-319' : null,
        cvss: null,
        remediation: remediationFor[anomaly.type] ?? '结合上下文人工复核该启发式告警。',
        target: anomaly.target ? sanitizeText(String(anomaly.target), 300) : null,
        evidence: [
          {
            title: '启发式指标',
            excerpt: sanitizeText(JSON.stringify(anomaly.metrics), 2000),
          },
        ],
      }));
      const data = {
        anomalyCount: anomalies.length,
        anomalies,
        thresholds: result.thresholds,
        flowsAnalyzed: flowsResult.flowCount,
        dnsMessages: dnsResult.messageCount,
        tlsSessions: tlsResult.sessionCount,
        httpRequests: httpResult.requestCount,
        truncated: capture.truncated || flowsResult.truncated,
        note: result.note,
      };
      const summary = [
        `异常启发式：${anomalies.length} 条（分析 ${flowsResult.flowCount} 条流）`,
        anomalies.length > 0 ? `类型：${[...new Set(anomalies.map((a) => a.type))].join(', ')}` : '未命中阈值',
        '全部为启发式/观测结论，须人工复核',
      ].join('；');
      return makeResult({
        summary: `${summary}。`,
        findings,
        data,
        meta: captureMeta(capture, {
          truncated: data.truncated,
          meta: { thresholds: result.thresholds, defaults: DEFAULT_THRESHOLDS },
        }),
      });
    },
  },
];

export default {
  domain: 'network',
  capabilities,
};
