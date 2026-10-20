// ArmorBreak - 网络异常启发式检测（纯 node:*）
// 端口扫描扇出、信标周期性、大上传、罕见端口、DNS NXDOMAIN、无 SNI 的 TLS、明文 HTTP。
// 全部为启发式：结论必须标 hypothesis，不得当作已确认攻击。
import { portService, mean, stdev } from './util.js';

export const DEFAULT_THRESHOLDS = {
  portScanDistinctPorts: 15,
  fanoutDistinctHosts: 15,
  beaconMinPackets: 5,
  beaconMinDurationSeconds: 10,
  beaconMaxCv: 0.25,
  beaconMinMeanGapSeconds: 1,
  largeUploadBytes: 1024 * 1024,
  largeUploadRatio: 8,
  rarePortMinFlows: 20,
  dnsMinResponses: 20,
  dnsNxdomainRatio: 0.3,
  tlsMinSessions: 3,
  tlsNoSniRatio: 0.5,
};

function clientSideOfFlow(flow) {
  if (flow.client && flow.client === flow.endpoints.a) return 'ab';
  if (flow.client && flow.client === flow.endpoints.b) return 'ba';
  if (flow.firstSide) return flow.firstSide;
  return null;
}

function endpointText(ep) {
  if (!ep) return null;
  return ep.ip.includes(':') ? `[${ep.ip}]:${ep.port}` : `${ep.ip}:${ep.port}`;
}

/**
 * 检测启发式异常。
 * @param {{flows:Array, flowPackets:Map, dns?:object, http?:object, tls?:object}} context
 * @param {object} options 阈值覆盖
 */
export function detectAnomalies(context, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS };
  for (const key of Object.keys(DEFAULT_THRESHOLDS)) {
    if (Number.isFinite(options[key])) thresholds[key] = options[key];
  }
  const flows = context.flows || [];
  const anomalies = [];
  const portServiceKnown = (port) => portService(port);

  // ---- 1) 端口扫描：同一源主机对同一目标端口离散度大 ----
  const srcToDstPorts = new Map(); // src -> Map(dst -> Set(ports))
  const srcToDsts = new Map(); // src -> Map(dst -> connections)
  for (const flow of flows) {
    const client = flow.client;
    const server = flow.server;
    if (!client || !server) continue;
    if (!srcToDstPorts.has(client.ip)) srcToDstPorts.set(client.ip, new Map());
    const dstMap = srcToDstPorts.get(client.ip);
    if (!dstMap.has(server.ip)) dstMap.set(server.ip, new Set());
    dstMap.get(server.ip).add(server.port);
    if (!srcToDsts.has(client.ip)) srcToDsts.set(client.ip, new Map());
    const dstCounts = srcToDsts.get(client.ip);
    dstCounts.set(server.ip, (dstCounts.get(server.ip) || 0) + 1);
  }
  let portScanFound = false;
  for (const [src, dstMap] of srcToDstPorts) {
    for (const [dst, ports] of dstMap) {
      if (ports.size >= thresholds.portScanDistinctPorts) {
        anomalies.push({
          type: 'port-scan-fanout',
          title: '疑似端口扫描（同源对同目标大量端口）',
          severity: 'medium',
          description: `${src} 对 ${dst} 建立了 ${ports.size} 个不同目的端口的连接（阈值 ${thresholds.portScanDistinctPorts}）。可能是端口扫描/服务爆破，也可能是扫描器、监控或 P2P 发现行为，需结合时间窗与包数判定。`,
          metrics: {
            src,
            dst,
            distinctPorts: ports.size,
            samplePorts: [...ports].sort((a, b) => a - b).slice(0, 20),
            connections: srcToDsts.get(src)?.get(dst) ?? 0,
          },
          target: `${src} -> ${dst}`,
        });
        portScanFound = true;
        break;
      }
    }
    if (portScanFound) break;
  }

  // ---- 2) 横向扇出：同一源连接大量不同目标 IP ----
  let fanout = null;
  for (const [src, dstCounts] of srcToDsts) {
    if (dstCounts.size >= thresholds.fanoutDistinctHosts) {
      fanout = { src, distinctHosts: dstCounts.size, sampleDsts: [...dstCounts.keys()].slice(0, 10) };
      break;
    }
  }
  if (fanout) {
    anomalies.push({
      type: 'host-fanout',
      title: '疑似横向扫描/批量连接（大量目标主机）',
      severity: 'medium',
      description: `${fanout.src} 与 ${fanout.distinctHosts} 个不同目标 IP 建立连接（阈值 ${thresholds.fanoutDistinctHosts}）。可能是主机发现/横向移动，也可能是 CDN、负载均衡或正常业务批量访问，需结合端口与域名判断。`,
      metrics: fanout,
      target: fanout.src,
    });
  }

  // ---- 3) 信标周期性：同一流内客户端方向包间隔稳定 ----
  const beaconFindings = [];
  if (context.flowPackets) {
    for (const entry of context.flowPackets.values()) {
      const flow = entry.flow;
      if (flow.packets < thresholds.beaconMinPackets) continue;
      if (!Number.isFinite(flow.duration) || flow.duration < thresholds.beaconMinDurationSeconds) continue;
      const side = clientSideOfFlow(flow);
      if (!side || !entry.directions[side]) continue;
      const packets = entry.directions[side].filter((p) => Number.isFinite(p.tsSeconds));
      if (packets.length < thresholds.beaconMinPackets) continue;
      const gaps = [];
      for (let i = 1; i < packets.length; i++) {
        const gap = packets[i].tsSeconds - packets[i - 1].tsSeconds;
        if (gap > 0.0001) gaps.push(gap);
      }
      if (gaps.length < thresholds.beaconMinPackets - 1) continue;
      const avg = mean(gaps);
      const sd = stdev(gaps);
      if (!Number.isFinite(avg) || avg < thresholds.beaconMinMeanGapSeconds) continue;
      const cv = avg > 0 ? sd / avg : Number.POSITIVE_INFINITY;
      if (cv <= thresholds.beaconMaxCv) {
        beaconFindings.push({
          flowId: flow.id,
          client: endpointText(flow.client),
          server: endpointText(flow.server),
          packets: flow.packets,
          clientPackets: packets.length,
          meanGapSeconds: Number(avg.toFixed(3)),
          stdevSeconds: Number(sd.toFixed(3)),
          cv: Number(cv.toFixed(3)),
          durationSeconds: flow.duration,
        });
      }
      if (beaconFindings.length >= 5) break;
    }
  }
  for (const beacon of beaconFindings) {
    anomalies.push({
      type: 'beaconing-interval',
      title: `疑似周期性信标（间隔 ${beacon.meanGapSeconds}s，CV=${beacon.cv}）`,
      severity: 'low',
      description: `${beacon.client} -> ${beacon.server} 的客户端方向报文间隔稳定（均值 ${beacon.meanGapSeconds}s，标准差 ${beacon.stdevSeconds}s，变异系数 ${beacon.cv} <= 阈值 ${thresholds.beaconMaxCv}）。这可能是 C2 心跳，也可能是健康检查/长轮询/遥测；需结合域名信誉与负载内容确认。`,
      metrics: beacon,
      target: `${beacon.client} -> ${beacon.server}`,
    });
  }

  // ---- 4) 大上传 / 上传占比异常 ----
  const uploads = [];
  for (const flow of flows) {
    const side = clientSideOfFlow(flow);
    if (!side) continue;
    const up = flow.bytesByDirection[side] ?? 0;
    const down = flow.bytesByDirection[side === 'ab' ? 'ba' : 'ab'] ?? 0;
    if (up >= thresholds.largeUploadBytes && (down === 0 || up / Math.max(down, 1) >= thresholds.largeUploadRatio)) {
      uploads.push({
        flowId: flow.id,
        client: endpointText(flow.client),
        server: endpointText(flow.server),
        uploadBytes: up,
        downloadBytes: down,
        ratio: down > 0 ? Number((up / down).toFixed(2)) : null,
        packets: flow.packets,
        state: flow.state,
      });
    }
    if (uploads.length >= 5) break;
  }
  for (const upload of uploads) {
    anomalies.push({
      type: 'large-upload',
      title: '疑似大流量上传',
      severity: 'low',
      description: `${upload.client} -> ${upload.server} 客户端方向传输 ${upload.uploadBytes} 字节，服务端返回 ${upload.downloadBytes} 字节${upload.ratio ? `（上传/下载比 ${upload.ratio}）` : ''}。可能是数据外传，也可能是备份/文件上传/视频上传等正常业务。`,
      metrics: upload,
      target: `${upload.client} -> ${upload.server}`,
    });
  }

  // ---- 5) 罕见服务端口（非公认端口且大量出现） ----
  const rarePorts = new Map();
  for (const flow of flows) {
    const port = flow.serverPort;
    if (!Number.isInteger(port)) continue;
    if (port < 1024) continue; // 系统端口单独看
    if (portServiceKnown(port)) continue;
    const entry = rarePorts.get(port) || { port, flows: 0, hosts: new Set() };
    entry.flows += 1;
    if (flow.server) entry.hosts.add(flow.server.ip);
    rarePorts.set(port, entry);
  }
  const rareList = [...rarePorts.values()]
    .filter((entry) => entry.flows >= thresholds.rarePortMinFlows)
    .sort((a, b) => b.flows - a.flows)
    .slice(0, 5);
  if (rareList.length > 0) {
    anomalies.push({
      type: 'rare-service-ports',
      title: '大量连接使用非标准服务端口',
      severity: 'low',
      description: `检测到 ${rareList.length} 个非标准高位的服务端口流量较大（每端口 >= ${thresholds.rarePortMinFlows} 条流），可能是自建服务、隧道、C2 或非标准业务端口；不构成结论。`,
      metrics: rareList.map((entry) => ({ port: entry.port, flows: entry.flows, distinctHosts: entry.hosts.size })),
      target: rareList.map((entry) => String(entry.port)).join(','),
    });
  }

  // ---- 6) DNS NXDOMAIN 比例异常 ----
  if (context.dns && context.dns.responseCount >= thresholds.dnsMinResponses) {
    const ratio = context.dns.nxdomainCount / context.dns.responseCount;
    if (ratio >= thresholds.dnsNxdomainRatio) {
      anomalies.push({
        type: 'dns-nxdomain-ratio',
        title: `DNS NXDOMAIN 比例偏高（${(ratio * 100).toFixed(1)}%）`,
        severity: 'low',
        description: `DNS 响应 ${context.dns.responseCount} 条，其中 NXDOMAIN ${context.dns.nxdomainCount} 条（${(ratio * 100).toFixed(1)}%，阈值 ${(thresholds.dnsNxdomainRatio * 100).toFixed(0)}%）。可能是域名拼写错误、广告/追踪域名解析失败，也可能是 DGA/域名隧道尝试，需结合域名形态与时序判断。`,
        metrics: {
          responses: context.dns.responseCount,
          nxdomain: context.dns.nxdomainCount,
          ratio: Number(ratio.toFixed(3)),
          topTypes: context.dns.qtypeCounts.slice(0, 5),
        },
        target: 'DNS',
      });
    }
  }

  // ---- 7) TLS 缺 SNI ----
  if (context.tls && context.tls.sessionCount >= thresholds.tlsMinSessions) {
    const noSni = context.tls.sessions.filter((s) => !s.sni).length;
    const ratio = noSni / context.tls.sessionCount;
    if (ratio >= thresholds.tlsNoSniRatio) {
      anomalies.push({
        type: 'tls-no-sni',
        title: 'TLS ClientHello 普遍缺少 SNI',
        severity: 'low',
        description: `${context.tls.sessionCount} 个 TLS 会话中 ${noSni} 个 ClientHello 未携带 SNI（比例 ${(ratio * 100).toFixed(1)}%）。直接 IP 访问、旧客户端或规避域名检测的恶意软件都可能出现该特征；需结合 JA3 与目的地判断。`,
        metrics: { sessions: context.tls.sessionCount, noSni, ratio: Number(ratio.toFixed(3)) },
        target: 'TLS',
      });
    }
  }

  // ---- 8) 明文 HTTP ----
  if (context.http && context.http.requestCount > 0) {
    anomalies.push({
      type: 'cleartext-http',
      title: `存在 ${context.http.requestCount} 个明文 HTTP 请求`,
      severity: 'low',
      description: `抓包中解析到 ${context.http.requestCount} 个明文 HTTP 请求（流 ${context.http.streamCount} 条）。明文流量可被同网段嗅探/篡改；若包含登录或 Token，风险更高。此条为观测事实，非启发式。`,
      metrics: {
        streams: context.http.streamCount,
        requests: context.http.requestCount,
        responses: context.http.responseCount,
        hosts: context.http.hosts.slice(0, 5),
      },
      target: context.http.hosts[0]?.host ?? 'HTTP',
    });
  }

  return { anomalies, thresholds, note: '异常检测均为启发式或其于观测流量，须结合上下文人工复核；不是已确认攻击。' };
}
