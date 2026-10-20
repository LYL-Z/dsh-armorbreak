/**
 * TShark external adapter (v1.2.0).
 *
 * Runs `tshark -r <capture> -T json -c <bound>` with argv arrays, then maps the
 * JSON to a bounded flow/http/dns/tls summary. Findings are observations from the
 * capture (cleartext HTTP, malformed packets), never vulnerability confirmations.
 * @module dsh-armorbreak/lib/analyzers/network/tshark
 */
import { existsSync } from 'node:fs'
import { basename } from 'node:path'
import { executeTool, parseJsonOutput, resolveTshark, sha256, EXTERNAL_TOOL_GUIDANCE } from '../../core/externalTools.js'

function finding(fields) {
  return {
    severity: 'info', verification: 'observed', cwe: null, cvss: null, confidence: 'medium',
    ...fields,
    evidence: Array.isArray(fields.evidence) ? fields.evidence.slice(0, 8) : [],
  }
}

function evidence(title, kind, excerpt, meta = {}) {
  return { title, kind, excerpt: String(excerpt).slice(0, 2000), meta }
}

function collectFieldValues(node, predicate, out, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 8) return
  for (const [key, value] of Object.entries(node)) {
    if (predicate(key) && (typeof value === 'string' || typeof value === 'number')) out.push(String(value))
    else if (value && typeof value === 'object') collectFieldValues(value, predicate, out, depth + 1)
  }
}

function collectNamedValues(node, names, out, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 8) return
  for (const [key, value] of Object.entries(node)) {
    if (names.has(key) && (typeof value === 'string' || typeof value === 'number') && !out.has(key)) out.set(key, String(value))
    else if (value && typeof value === 'object') collectNamedValues(value, names, out, depth + 1)
  }
}

/**
 * @param {string} raw
 * @param {{maxPackets?: number, maxFindings?: number}} [options]
 */
export function parseTsharkJson(raw, options = {}) {
  const packets = parseJsonOutput(raw, 'tshark')
  if (!Array.isArray(packets)) throw new Error('tshark output JSON is not a packet array (expected -T json output)')
  const maxPackets = Math.max(1, Math.min(Number(options.maxPackets ?? 1000), 20000))
  const maxFindings = Math.max(1, Math.min(Number(options.maxFindings ?? 200), 1000))
  const protocols = new Map()
  const endpoints = new Map()
  const httpRequests = []
  const dnsQueries = []
  const tlsNames = []
  let malformed = 0
  const truncated = packets.length > maxPackets
  for (const packet of packets.slice(0, maxPackets)) {
    if (!packet || typeof packet !== 'object') continue
    const layers = packet._source?.layers ?? {}
    if (packet._ws?.malformed || layers._ws?.malformed) malformed += 1
    const protocolText = String(layers.frame?.protocols ?? '')
    const names = protocolText ? protocolText.split(':').filter(Boolean) : Object.keys(layers).filter((key) => key !== 'frame')
    for (const name of names) protocols.set(name, (protocols.get(name) ?? 0) + 1)
    for (const [key, value] of [['ip.src', layers.ip?.['ip.src']], ['ip.dst', layers.ip?.['ip.dst']], ['ipv6.src', layers.ipv6?.['ipv6.src']], ['ipv6.dst', layers.ipv6?.['ipv6.dst']]]) {
      if (value) endpoints.set(`${key}=${String(value)}`, (endpoints.get(`${key}=${String(value)}`) ?? 0) + 1)
    }
    const http = layers.http && typeof layers.http === 'object' ? layers.http : null
    if (http) {
      const httpFields = new Map()
      collectNamedValues(http, new Set(['http.request.method', 'http_request_method', 'http.request.uri', 'http_request_uri', 'http.host', 'http_host', 'http.request.full_uri', 'http.response.code']), httpFields)
      const host = String(httpFields.get('http.host') ?? httpFields.get('http_host') ?? '')
      const uri = String(httpFields.get('http.request.uri') ?? httpFields.get('http_request_uri') ?? '')
      const method = String(httpFields.get('http.request.method') ?? httpFields.get('http_request_method') ?? '')
      const status = String(httpFields.get('http.response.code') ?? '')
      if (method || uri || status) httpRequests.push({ method: method.slice(0, 16), host: host.slice(0, 200), uri: uri.slice(0, 300), status: status ? Number(status) : null })
    }
    const dnsValues = []
    collectFieldValues(layers.dns, (key) => key === 'dns.qry.name' || key === 'dns_qry_name', dnsValues)
    for (const value of dnsValues) {
      if (dnsQueries.length < 200 && !dnsQueries.includes(value)) dnsQueries.push(value.slice(0, 200))
    }
    const tlsValues = []
    collectFieldValues(layers.tls, (key) => /server_name$/.test(key), tlsValues)
    for (const value of tlsValues) {
      if (tlsNames.length < 200 && !tlsNames.includes(value)) tlsNames.push(value.slice(0, 200))
    }
  }
  const findings = []
  if (httpRequests.length > 0) {
    findings.push(finding({
      title: `捕获中存在 ${httpRequests.length} 条明文 HTTP 请求`,
      severity: 'low',
      description: '明文 HTTP 请求可被同链路观察者读取；这是抓包中的观测事实，不代表目标系统当前仍可被利用。',
      method: 'TShark JSON 解析 http.request_method/http_host/http_request_uri',
      cwe: 'CWE-319',
      target: httpRequests[0]?.host ?? null,
      evidence: [evidence('明文 HTTP 样本', 'tshark-http', JSON.stringify(httpRequests.slice(0, 10)))],
    }))
  }
  if (malformed > 0) {
    findings.push(finding({
      title: `捕获中存在 ${malformed} 个畸形报文`,
      severity: 'info',
      description: '畸形报文可能是截断抓包、MTU/分片问题或协议模糊测试；需要结合抓包环境复核。',
      method: 'TShark _ws.malformed 标记',
      evidence: [evidence('畸形报文计数', 'tshark-malformed', String(malformed))],
    }))
  }
  const data = {
    capture: basename(String(options.path ?? 'capture')),
    packetCount: Math.min(packets.length, maxPackets),
    truncated,
    malformed,
    protocols: [...protocols.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30).map(([name, count]) => ({ name, count })),
    endpoints: [...endpoints.entries()].sort((a, b) => b[1] - a[1]).slice(0, 30).map(([endpoint, count]) => ({ endpoint, count })),
    httpRequests: httpRequests.slice(0, 50),
    dnsQueries: dnsQueries.slice(0, 100),
    tlsServerNames: [...new Set(tlsNames)].slice(0, 100),
    verification: 'observed',
    tool: 'tshark',
  }
  const summary = [
    `TShark：${data.packetCount} 个报文${truncated ? '（已截断）' : ''}，${data.protocols.length} 类协议，HTTP 请求 ${httpRequests.length}，DNS 查询 ${dnsQueries.length}，畸形 ${malformed}。`,
    httpRequests.length > 0 ? `明文 HTTP 主机样本：${[...new Set(httpRequests.map((item) => item.host).filter(Boolean))].slice(0, 5).join(', ')}` : '未观察到明文 HTTP 请求。',
    '结论来自抓包观测，不等同于漏洞确认；如需复现应使用相同抓包/时间窗。',
  ].join('\n')
  return { summary, findings: findings.slice(0, maxFindings), evidence: [evidence('TShark 抓包摘要', 'tshark-summary', JSON.stringify({ packetCount: data.packetCount, malformed, http: httpRequests.length, dns: dnsQueries.length }))], data }
}

export const tsharkCapability = {
  id: 'network.tshark',
  title: 'TShark 抓包解析（外部工具）',
  description: '调用本机 TShark 读取 pcap/pcapng，输出协议统计、端点、HTTP/DNS/TLS 摘要与畸形报文观测。argv 数组调用、无 shell、输出有界；缺失工具时 fail-closed 并给出安装指引。所有结论为 observed/hypothesis，不确认漏洞。',
  riskLevel: 'L0',
  targetKind: 'file',
  params: {
    type: 'object',
    properties: {
      maxPackets: { type: 'integer', minimum: 1, maximum: 20000, description: '最多解析的报文数，默认 1000。' },
    },
    additionalProperties: false,
  },
  async run(input) {
    const options = input.options ?? {}
    const targetPath = input.targetPath ?? null
    if (!targetPath) throw new Error('network.tshark needs a capture file target')
    if (!existsSync(targetPath)) throw new Error(`capture file not found: ${targetPath}`)
    const maxPackets = Math.max(1, Math.min(Number(options.maxPackets ?? 1000), 20000))
    const tool = typeof input.env?.execExternal === 'function'
      ? { command: 'tshark', prefixArgs: [] }
      : { command: resolveTshark(process.env), prefixArgs: [] }
    const args = ['-r', targetPath, '-T', 'json', '-c', String(maxPackets), '-n']
    let result
    try {
      result = await executeTool(input.env, tool, args, { timeoutMs: input.limits?.timeoutMs ?? 120_000, maxOutputBytes: 32 * 1024 * 1024 })
    } catch (error) {
      throw new Error(`network.tshark failed: ${String(error?.message ?? error)} ${EXTERNAL_TOOL_GUIDANCE.tshark}`.trim())
    }
    if (!result.stdout.trim()) throw new Error('tshark produced no JSON output; the capture may be empty or unreadable')
    const parsed = parseTsharkJson(result.stdout, { ...options, path: targetPath })
    const meta = {
      domain: 'network', capability: 'network.tshark', tool: 'tshark', target: targetPath,
      stdoutSha256: sha256(result.stdout), stdoutBytes: Buffer.byteLength(result.stdout), truncated: parsed.data.truncated,
    }
    return { ...parsed, meta }
  },
}
