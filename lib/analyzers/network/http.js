// ArmorBreak - 明文 HTTP 解析（纯 node:*）
// 从 TCP 单方向流解析请求/响应行、头部、Content-Length/chunked 长度与有界 body 样本。
// 敏感头（Authorization/Cookie/Set-Cookie 等）值脱敏；URI 中敏感查询参数值脱敏。
import { buildFlowStreams, formatEndpoint } from './flows.js';
import { sanitizeText, isoTime } from './util.js';

const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-session-token',
  'api-key',
]);

const TEXT_CONTENT_TYPES = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|graphql|problem\+json))/i;

const INTERESTING_HEADERS = new Set([
  'host',
  'user-agent',
  'content-type',
  'content-length',
  'accept',
  'accept-language',
  'accept-encoding',
  'referer',
  'origin',
  'server',
  'location',
  'transfer-encoding',
  'connection',
  'x-forwarded-for',
  'authorization',
  'cookie',
  'set-cookie',
]);

/** 脱敏 URI 中的敏感查询参数值。 */
export function redactUri(uri, maxLen = 1000) {
  const text = typeof uri === 'string' ? uri : String(uri ?? '');
  const redacted = text.replace(/([?&])([^=&#]+)=([^&#]*)/g, (match, sep, name, value) => {
    if (/token|key|secret|password|passwd|auth|session|sig|credential/i.test(name)) {
      return `${sep}${name}=[redacted:${value.length}]`;
    }
    return match;
  });
  return sanitizeText(redacted, maxLen);
}

function parseHeaders(lines) {
  const headers = {};
  const headerCount = lines.length;
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = sanitizeText(line.slice(0, idx).trim().toLowerCase(), 100);
    const rawValue = line.slice(idx + 1).trim();
    if (!name || Object.prototype.hasOwnProperty.call(headers, name)) continue;
    if (SENSITIVE_HEADERS.has(name)) {
      headers[name] = `[redacted:${rawValue.length}]`;
    } else {
      headers[name] = sanitizeText(rawValue, 500);
    }
  }
  return { headers, headerCount };
}

function findHeaderEnd(buf, start, maxHeaderBytes) {
  const end = Math.min(buf.length, start + maxHeaderBytes);
  const idx = buf.indexOf('\r\n\r\n', start, 'latin1');
  if (idx === -1 || idx + 4 > end) return -1;
  return idx;
}

function bodySampleFor(contentType, body) {
  if (!body || body.length === 0) return { bodySample: null, bodyIsText: false };
  if (contentType && TEXT_CONTENT_TYPES.test(contentType)) {
    return { bodySample: sanitizeText(body.toString('utf8'), 300), bodyIsText: true };
  }
  return { bodySample: null, bodyHexSample: body.subarray(0, 16).toString('hex'), bodyIsText: false };
}

/**
 * 解析单方向 HTTP 流。
 * @param {Buffer} buf
 * @param {{maxMessages?:number, maxHeaderBytes?:number, maxBodyBytes?:number}} opts
 */
export function parseHttpStream(buf, opts = {}) {
  const maxMessages = Math.max(1, Math.min(opts.maxMessages ?? 100, 2000));
  const maxHeaderBytes = Math.max(512, Math.min(opts.maxHeaderBytes ?? 16384, 1024 * 1024));
  const maxBodyBytes = Math.max(1, Math.min(opts.maxBodyBytes ?? 4096, 1024 * 1024));
  const messages = [];
  const errors = [];
  let truncated = false;
  let pos = 0;
  while (pos < buf.length && messages.length < maxMessages) {
    // 允许前导空行
    while (pos + 1 < buf.length && buf[pos] === 0x0d && buf[pos + 1] === 0x0a) pos += 2;
    if (pos >= buf.length) break;
    const headerEnd = findHeaderEnd(buf, pos, maxHeaderBytes);
    if (headerEnd === -1) {
      if (buf.length - pos > 0) {
        truncated = true;
        errors.push(`偏移 ${pos} 处未找到完整 HTTP 头结尾（CRLFCRLF），已停止`);
      }
      break;
    }
    const headerText = buf.subarray(pos, headerEnd).toString('utf8');
    const lines = headerText.split('\r\n');
    const startLine = lines[0] ?? '';
    let kind = null;
    let method = null;
    let uri = null;
    let version = null;
    let status = null;
    let reason = null;
    let m;
    if ((m = /^([A-Z][A-Z0-9_-]{0,15}) (\S{1,4096}) HTTP\/(\d\.\d)$/.exec(startLine))) {
      kind = 'request';
      method = m[1];
      uri = m[2];
      version = m[3];
    } else if ((m = /^HTTP\/(\d\.\d) (\d{3})(?: (.*))?$/.exec(startLine))) {
      kind = 'response';
      version = m[1];
      status = Number(m[2]);
      reason = sanitizeText(m[3] ?? '', 120);
    } else {
      errors.push(`偏移 ${pos} 处起始行不是 HTTP 请求/响应行：${sanitizeText(startLine, 120)}`);
      break;
    }
    const { headers } = parseHeaders(lines.slice(1));
    const bodyStart = headerEnd + 4;
    let consumedBody = 0;
    let declaredBodyLength = null;
    let bodyTruncated = false;
    const contentLengthHeader = headers['content-length'];
    if (contentLengthHeader && /^\d+$/.test(contentLengthHeader)) declaredBodyLength = Number(contentLengthHeader);
    else if (headers['transfer-encoding'] && /chunked/i.test(headers['transfer-encoding'])) declaredBodyLength = -1;

    let bodyInfo = { bodySample: null, bodyIsText: false };
    if (declaredBodyLength === null) {
      // 无 Content-Length：请求通常无 body；响应/其它视为读到流末尾（语义不确定）
      const isBodylessRequest = kind === 'request' && ['GET', 'HEAD', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE'].includes(method);
      const isBodylessResponse = kind === 'response' && (status < 200 || status === 204 || status === 304);
      if (isBodylessRequest || isBodylessResponse) {
        consumedBody = 0;
      } else {
        const available = buf.subarray(bodyStart, Math.min(buf.length, bodyStart + maxBodyBytes));
        bodyInfo = bodySampleFor(headers['content-type'], available);
        consumedBody = buf.length - bodyStart;
        bodyTruncated = consumedBody > maxBodyBytes;
        declaredBodyLength = null;
      }
    } else if (declaredBodyLength === -1) {
      // chunked
      let p = bodyStart;
      const chunks = [];
      let captured = 0;
      let chunksGuard = 0;
      let sawTerminator = false;
      while (p < buf.length && chunksGuard++ < 10000) {
        const lineEnd = buf.indexOf('\r\n', p, 'latin1');
        if (lineEnd === -1) {
          bodyTruncated = true;
          break;
        }
        const sizeLine = buf.subarray(p, lineEnd).toString('latin1').split(';')[0].trim();
        const chunkSize = /^[0-9a-fA-F]+$/.test(sizeLine) ? parseInt(sizeLine, 16) : NaN;
        p = lineEnd + 2;
        if (!Number.isFinite(chunkSize)) {
          errors.push(`chunked 编码块长度非法：${sanitizeText(sizeLine, 40)}`);
          bodyTruncated = true;
          break;
        }
        if (chunkSize === 0) {
          // 尾部 headers：找到空行
          const trailerEnd = buf.indexOf('\r\n\r\n', p, 'latin1');
          if (trailerEnd === -1) {
            p = Math.min(buf.length, p + 2);
          } else {
            p = trailerEnd + 4;
          }
          sawTerminator = true;
          break;
        }
        if (p + chunkSize + 2 > buf.length) {
          bodyTruncated = true;
          p = buf.length;
          break;
        }
        if (captured < maxBodyBytes) {
          const part = buf.subarray(p, p + Math.min(chunkSize, maxBodyBytes - captured));
          chunks.push(part);
          captured += part.length;
        }
        p += chunkSize + 2;
      }
      consumedBody = p - bodyStart;
      if (!sawTerminator) truncated = true;
      bodyInfo = bodySampleFor(headers['content-type'], Buffer.concat(chunks, Math.min(captured, maxBodyBytes)));
    } else {
      const fullEnd = bodyStart + declaredBodyLength;
      if (fullEnd > buf.length) {
        bodyTruncated = true;
        truncated = true;
      }
      const available = buf.subarray(bodyStart, Math.min(fullEnd, buf.length, bodyStart + maxBodyBytes));
      bodyInfo = bodySampleFor(headers['content-type'], available);
      consumedBody = Math.min(declaredBodyLength, Math.max(0, buf.length - bodyStart));
      if (fullEnd <= buf.length) consumedBody = declaredBodyLength;
    }

    const nextPos = bodyStart + consumedBody;
    if (truncated && bodyTruncated && nextPos >= buf.length) {
      messages.push(buildMessage());
      break;
    }
    messages.push(buildMessage());
    pos = nextPos;
    if (pos <= bodyStart && bodyTruncated) break;

    function buildMessage() {
      const base = {
        index: messages.length,
        kind,
        version,
        headers,
        headerCount: lines.length - 1,
        declaredBodyLength,
        bodyCaptured: bodyInfo.bodySample !== null,
        bodySample: bodyInfo.bodySample,
        bodyHexSample: bodyInfo.bodyHexSample ?? null,
        bodyTruncated,
      };
      if (kind === 'request') {
        return { ...base, method, uri: redactUri(uri), rawUriLength: uri.length };
      }
      return { ...base, status, reason };
    }
  }
  if (pos < buf.length && messages.length >= maxMessages) truncated = true;
  const requests = messages.filter((m) => m.kind === 'request');
  const responses = messages.filter((m) => m.kind === 'response');
  return { messages, requests, responses, truncated, errors, consumedBytes: pos };
}

/**
 * 从流表扫描明文 HTTP 会话。
 * @param {Map} flowPackets
 * @param {{maxStreams?:number, maxMessages?:number, maxStreamBytes?:number}} opts
 */
export function scanHttpStreams(flowPackets, opts = {}) {
  const maxStreams = Math.max(1, Math.min(opts.maxStreams ?? 100, 2000));
  const maxMessages = Math.max(1, Math.min(opts.maxMessages ?? 50, 500));
  const maxStreamBytes = Math.max(1024, Math.min(opts.maxStreamBytes ?? 512 * 1024, 8 * 1024 * 1024));
  const entries = [...flowPackets.values()]
    .filter((entry) => entry.flow.proto === 'tcp')
    .sort((a, b) => (a.flow.firstTs ?? 0) - (b.flow.firstTs ?? 0));
  const streams = [];
  const requests = [];
  const responses = [];
  const transactions = [];
  let parseErrors = 0;
  let truncated = false;
  const hosts = new Map();
  const userAgents = new Map();
  const statusCodes = new Map();
  const servers = new Map();
  for (const entry of entries) {
    if (streams.length >= maxStreams) {
      truncated = true;
      break;
    }
    const streamPair = buildFlowStreams(entry, { maxBytes: maxStreamBytes });
    if (!streamPair) continue;
    const streamFirstSeen = isoTime(entry.flow.firstTs);
    const clientParse = parseHttpStream(streamPair.clientToServer.data, { maxMessages });
    const serverParse = parseHttpStream(streamPair.serverToClient.data, { maxMessages });
    if (clientParse.requests.length === 0 && serverParse.responses.length === 0) continue;
    parseErrors += clientParse.errors.length + serverParse.errors.length;
    const streamRequests = clientParse.requests.slice(0, maxMessages);
    const streamResponses = serverParse.responses.slice(0, maxMessages);
    // 按出现顺序配对请求/响应（不校验 TCP 层请求 id；HTTP/2 不解复用，仅明文 HTTP/1.x）
    for (let i = 0; i < Math.max(streamRequests.length, streamResponses.length); i++) {
      const req = streamRequests[i] ?? null;
      const res = streamResponses[i] ?? null;
      if (req) {
        const host = req.headers.host ?? null;
        if (host) {
          const prev = hosts.get(host) || { count: 0, firstSeen: null };
          prev.count += 1;
          if (prev.firstSeen === null) prev.firstSeen = streamFirstSeen;
          hosts.set(host, prev);
        }
        if (req.headers['user-agent']) userAgents.set(req.headers['user-agent'], (userAgents.get(req.headers['user-agent']) || 0) + 1);
        requests.push({
          streamIndex: streams.length + 1,
          firstSeen: streamFirstSeen,
          method: req.method,
          uri: req.uri,
          host,
          userAgent: req.headers['user-agent'] ?? null,
          contentType: req.headers['content-type'] ?? null,
          referer: req.headers.referer ? sanitizeText(req.headers.referer, 500) : null,
          hasAuthorization: Boolean(req.headers.authorization),
          hasCookie: Boolean(req.headers.cookie),
          bodySample: req.bodySample,
          bodyTruncated: req.bodyTruncated,
        });
      }
      if (res) {
        statusCodes.set(res.status, (statusCodes.get(res.status) || 0) + 1);
        if (res.headers.server) servers.set(res.headers.server, (servers.get(res.headers.server) || 0) + 1);
        responses.push({
          streamIndex: streams.length + 1,
          firstSeen: streamFirstSeen,
          status: res.status,
          reason: res.reason,
          server: res.headers.server ?? null,
          contentType: res.headers['content-type'] ?? null,
          location: res.headers.location ? sanitizeText(res.headers.location, 500) : null,
          hasSetCookie: Boolean(res.headers['set-cookie']),
          bodySample: res.bodySample,
          bodyTruncated: res.bodyTruncated,
        });
      }
      if (req) transactions.push({ request: requests[requests.length - 1], response: res ? responses[responses.length - 1] : null, pairing: 'sequential-heuristic' });
    }
    streams.push({
      flowId: entry.flow.id,
      firstSeen: streamFirstSeen,
      client: formatEndpoint(entry.flow.client),
      server: formatEndpoint(entry.flow.server),
      serverPort: entry.flow.serverPort,
      requestCount: clientParse.requests.length,
      responseCount: serverParse.responses.length,
      clientToServerBytes: streamPair.clientToServer.data.length,
      serverToClientBytes: streamPair.serverToClient.data.length,
      streamGaps: { clientToServer: streamPair.clientToServer.gaps, serverToClient: streamPair.serverToClient.gaps },
      truncated: clientParse.truncated || serverParse.truncated,
      parseErrors: clientParse.errors.length + serverParse.errors.length,
    });
    if (clientParse.truncated || serverParse.truncated) truncated = true;
  }
  return {
    streamCount: streams.length,
    requestCount: requests.length,
    responseCount: responses.length,
    streams,
    requests,
    responses,
    transactions,
    hosts: [...hosts.entries()]
      .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
      .map(([host, entry]) => ({ host, count: entry.count, firstSeen: entry.firstSeen })),
    userAgents: [...userAgents.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([userAgent, count]) => ({ userAgent, count })),
    statusCodes: [...statusCodes.entries()].sort((a, b) => a[0] - b[0]).map(([status, count]) => ({ status, count })),
    servers: [...servers.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([server, count]) => ({ server, count })),
    parseErrors,
    truncated,
  };
}
