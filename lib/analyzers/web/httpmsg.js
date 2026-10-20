// ArmorBreak web domain — raw HTTP request/response message parsing.
//
// Only metadata is reported: header names/values (credential values redacted),
// body size/content-type, and a small set of structural checks. Body content is
// never echoed because raw requests may carry passwords or tokens.

import {
  clip,
  compact,
  finding,
  getHeader,
  isHtmlMime,
  normalizeHeaderPairs,
  parseCacheControl,
  redactHeaderValue,
  redactParamValue,
  redactUrl,
  sensitiveParamInfo,
  sortFindings,
  tryParseUrl,
} from './common.js';
import { auditHeaders } from './headers.js';

const MAX_HEADER_LINES = 500;
const MAX_JSON_BODY_BYTES = 64 * 1024;

/**
 * Parse one raw HTTP message (request or response) from text.
 * @returns {{type:'request'|'response', version:string|null, startLine:string,
 *   method?:string, target?:string, status?:number, statusText?:string,
 *   headers:{name:string,value:string}[], bodyText:string, bodySize:number}}
 */
export function parseHttpMessage(text) {
  const raw = String(text ?? '').replace(/^\uFEFF/, '');
  if (!raw.trim()) {
    throw new Error(
      'HTTP 报文为空：请提供完整的原始请求/响应文本（起始行 + 头部 + 空行 + 可选 body）。' +
        ' 示例：“GET /api/user HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n”。',
    );
  }
  const normalized = raw.replace(/\r\n?/g, '\n');
  const separator = normalized.indexOf('\n\n');
  const headText = separator === -1 ? normalized : normalized.slice(0, separator);
  const bodyText = separator === -1 ? '' : normalized.slice(separator + 2);
  const lines = headText.split('\n');
  const startLine = (lines.shift() || '').trim();
  if (!startLine) {
    throw new Error('HTTP 报文缺少起始行：第一行必须是 “METHOD /path HTTP/1.1” 或 “HTTP/1.1 200 OK”。');
  }

  const responseMatch = /^HTTP\/(\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$/.exec(startLine);
  const requestMatch = /^([A-Z][A-Z0-9_-]{0,19})\s+(\S+)(?:\s+HTTP\/(\d(?:\.\d)?))?$/.exec(startLine);

  let headers = [];
  if (lines.length) {
    try {
      headers = normalizeHeaderPairs(lines.join('\n'), { source: 'HTTP 头部' }).slice(0, MAX_HEADER_LINES);
    } catch (error) {
      throw new Error(`HTTP 头部解析失败：${error.message}`);
    }
  }
  const bodySize = Buffer.byteLength(bodyText, 'utf8');

  if (responseMatch) {
    return {
      type: 'response',
      version: responseMatch[1],
      startLine,
      status: Number(responseMatch[2]),
      statusText: compact(responseMatch[3] ?? '', 200),
      headers,
      bodyText,
      bodySize,
    };
  }
  if (requestMatch) {
    const target = requestMatch[2];
    const looksLikeTarget = /^(?:\/|https?:\/\/|\*|[\w.-]+\/)/i.test(target);
    if (!looksLikeTarget) {
      throw new Error(
        `HTTP 起始行无法识别：目标 “${clip(target, 80)}” 不是合法请求目标。期望 “GET /path HTTP/1.1” 或绝对 URL。`,
      );
    }
    return {
      type: 'request',
      version: requestMatch[3] ?? null,
      startLine,
      method: requestMatch[1].toUpperCase(),
      target,
      headers,
      bodyText,
      bodySize,
    };
  }
  throw new Error(
    `HTTP 起始行无法识别：“${clip(startLine, 160)}”。支持 “METHOD /path HTTP/1.1” 请求行或 “HTTP/1.1 200 OK” 状态行；` +
      '请确认输入是原始 HTTP 报文（不是浏览器请求头片段）。',
  );
}

function reconstructHead(message, displayStartLine) {
  const lines = [displayStartLine];
  for (const { name, value } of message.headers) {
    lines.push(`${name}: ${redactHeaderValue(name, value)}`);
  }
  return clip(lines.join('\n'), 2000);
}

function tryParseJsonBody(bodyText) {
  if (!bodyText || Buffer.byteLength(bodyText, 'utf8') > MAX_JSON_BODY_BYTES) return null;
  const trimmed = bodyText.trim();
  if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

function queryParamsOf(message) {
  const raw = message.type === 'request' ? message.target : null;
  if (!raw) return [];
  const host = getHeader(message.headers, 'host') || 'placeholder.invalid';
  let parsed = tryParseUrl(raw);
  if (!parsed) {
    try {
      parsed = new URL(raw, `http://${host}`);
    } catch {
      return [];
    }
  }
  const out = [];
  for (const [name, value] of parsed.searchParams) out.push([name, value]);
  return out;
}

/** Analyze a parsed HTTP message (no network, no body echo). */
export function analyzeHttpMessage(message, opts = {}) {
  const maxFindings = Number.isFinite(opts.maxFindings) ? Math.max(1, Math.trunc(opts.maxFindings)) : 100;
  const findings = [];
  const checks = [];
  const url = message.type === 'request' ? message.target : null;
  const targetForDisplay = url ? redactUrl(url) : null;
  // Never echo the raw request target (it may contain tokens in the query string).
  const displayStartLine =
    message.type === 'request'
      ? `${message.method ?? 'GET'} ${targetForDisplay ?? '/'}${message.version ? ` HTTP/${message.version}` : ''}`
      : clip(message.startLine, 300);

  // ----- generic structural checks ----------------------------------------
  const transferEncoding = getHeader(message.headers, 'transfer-encoding');
  const contentLengthRaw = getHeader(message.headers, 'content-length');
  if (transferEncoding && contentLengthRaw) {
    findings.push(
      finding({
        title: '[http-te-cl-conflict] Transfer-Encoding 与 Content-Length 同时出现',
        severity: 'medium',
        description:
          '报文同时声明 Transfer-Encoding 与 Content-Length，不同实现可能选取不同边界解析，是 HTTP 请求走私（smuggling）的经典前置条件。' +
          ' 此判定基于报文结构，是否可实际利用依赖前后端代理组合。',
        verification: 'hypothesis',
        method: 'http-message-structure-analysis',
        cwe: 'CWE-444',
        remediation: '规范化报文：只保留一种长度语义（优先 Transfer-Encoding，且拒绝 TE+CL 并存的请求）。',
        target: targetForDisplay,
        evidence: [{ title: '冲突头', excerpt: `Transfer-Encoding: ${clip(transferEncoding, 120)}\nContent-Length: ${clip(contentLengthRaw, 40)}` }],
      }),
    );
  }
  if (contentLengthRaw != null && /^\d+$/.test(contentLengthRaw.trim())) {
    const declared = Number(contentLengthRaw.trim());
    if (declared !== message.bodySize && !transferEncoding) {
      findings.push(
        finding({
          title: '[http-content-length-mismatch] Content-Length 与实际 body 长度不一致',
          severity: 'low',
          description:
            `Content-Length 声明 ${declared} 字节，但解析到的 body 为 ${message.bodySize} 字节。` +
            ' 若输入是文本化/截断的报文，差异可能来自编码损失；若为原始报文则说明长度头不可信。',
          verification: 'hypothesis',
          method: 'http-message-structure-analysis',
          cwe: 'CWE-436',
          remediation: '校验客户端发送的 Content-Length；服务端按实际读取长度做上限校验。',
          target: targetForDisplay,
        }),
      );
    }
  }

  if (message.type === 'request') {
    const hostHeader = getHeader(message.headers, 'host');
    if (!hostHeader && message.version === '1.1') {
      findings.push(
        finding({
          title: '[http-request-no-host] HTTP/1.1 请求缺少 Host 头',
          severity: 'low',
          description: 'HTTP/1.1 要求请求携带 Host 头；缺失会导致 400 或虚拟主机路由异常。',
          verification: 'observed',
          method: 'http-message-structure-analysis',
          cwe: null,
          remediation: '在请求中加入准确且经过白名单校验的 Host 头。',
          target: targetForDisplay,
        }),
      );
    }
    if (!hostHeader && message.version === null) {
      // HTTP/0.9 style request; nothing more to check.
    }

    for (const [name, value] of queryParamsOf(message)) {
      const info = sensitiveParamInfo(name);
      if (!info) continue;
      findings.push(
        finding({
          title: `[http-query-token] 请求 URL 携带敏感参数：${clip(name, 80)}`,
          severity: info.severity,
          description: `查询参数 “${clip(name, 80)}” 疑似携带凭据（值已脱敏：${redactParamValue(value)}）。URL 会进入日志/Referer/历史记录。`,
          verification: 'observed',
          method: 'http-request-url-analysis',
          cwe: 'CWE-598',
          remediation: '改用 Authorization 头或服务端会话传递凭据。',
          target: targetForDisplay,
          evidence: [{ title: '已脱敏 URL', excerpt: url ? redactUrl(url) : '(n/a)' }],
        }),
      );
    }

    const contentType = getHeader(message.headers, 'content-type');
    if (message.bodySize > 0 && !contentType) {
      findings.push(
        finding({
          title: '[http-body-no-content-type] 请求体缺少 Content-Type',
          severity: 'low',
          description: '请求包含 body 但没有 Content-Type，服务端可能猜测解析格式，增加解析歧义风险。',
          verification: 'observed',
          method: 'http-message-structure-analysis',
          cwe: null,
          remediation: '为带 body 的请求显式设置 Content-Type。',
          target: targetForDisplay,
        }),
      );
    }

    const authHeader = getHeader(message.headers, 'authorization');
    if (authHeader) {
      const scheme = (/^([A-Za-z][A-Za-z0-9+.-]*)\s+/.exec(authHeader.trim()) || [])[1] || null;
      if (scheme) {
        checks.push({ id: 'request-auth-scheme', title: '认证方案', status: 'info', severity: 'info', detail: `Authorization 使用 ${clip(scheme, 40)} 方案（值已脱敏）。` });
      }
    }

    // Sensitive fields in a JSON body: names only, values never echoed.
    const jsonBody = tryParseJsonBody(message.bodyText);
    if (jsonBody && jsonBody && typeof jsonBody === 'object' && !Array.isArray(jsonBody)) {
      const fields = Object.keys(jsonBody)
        .filter((key) => sensitiveParamInfo(key))
        .slice(0, 20);
      if (fields.length) {
        findings.push(
          finding({
            title: '[http-body-sensitive-fields] 请求体 JSON 含敏感字段',
            severity: 'info',
            description: `请求体包含敏感字段 ${fields.map((f) => `“${clip(f, 60)}”`).join('、')}（值已省略）。请确认传输为 HTTPS 且日志已脱敏。`,
            verification: 'observed',
            method: 'http-request-body-analysis',
            cwe: null,
            remediation: '确保 HTTPS；避免在访问日志中记录请求体。',
            target: targetForDisplay,
          }),
        );
      }
    }
  } else {
    // ----- response security-header audit ---------------------------------
    const contentType = getHeader(message.headers, 'content-type');
    const html = isHtmlMime(contentType ?? '');
    const audit = auditHeaders(message.headers, {
      contentType: contentType ?? undefined,
      html,
      https: null,
    });
    for (const check of audit.checks) checks.push(check);
    for (const f of audit.findings) {
      findings.push(
        finding({
          title: f.title,
          severity: f.severity,
          description: `${f.description}（状态码 ${message.status ?? 'unknown'}）`,
          verification: f.verification,
          method: 'http-response-header-audit',
          cwe: f.cwe,
          remediation: f.remediation,
          target: targetForDisplay,
          evidence: f.evidence,
        }),
      );
    }
    if (message.status != null && message.status >= 200 && message.status < 300) {
      const cacheRaw = getHeader(message.headers, 'cache-control');
      const setCookies = getHeader(message.headers, 'set-cookie');
      if (setCookies && !cacheRaw) {
        checks.push({
          id: 'response-cookie-cache',
          title: 'Set-Cookie 与缓存',
          status: 'info',
          severity: 'info',
          detail: '响应设置 Cookie 但未声明 Cache-Control，建议对认证响应使用 no-store。',
        });
      }
    }
  }

  const sortedFindings = sortFindings(findings);
  const finalFindings = sortedFindings.slice(0, maxFindings);
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of finalFindings) severityCounts[f.severity] += 1;

  const headersOut = message.headers.map(({ name, value }) => ({
    name: clip(String(name), 100),
    value: redactHeaderValue(name, value),
  }));

  const bodyInfo = {
    size: message.bodySize,
    contentType: getHeader(message.headers, 'content-type') ? clip(getHeader(message.headers, 'content-type'), 160) : null,
    transferEncoding: getHeader(message.headers, 'transfer-encoding') ? clip(getHeader(message.headers, 'transfer-encoding'), 120) : null,
    contentLength: getHeader(message.headers, 'content-length') ? clip(getHeader(message.headers, 'content-length'), 40) : null,
    jsonKeyCount: null,
    sensitiveFields: [],
  };
  if (message.type === 'request' && message.bodySize > 0 && message.bodySize <= MAX_JSON_BODY_BYTES) {
    const jsonBody = tryParseJsonBody(message.bodyText);
    if (jsonBody && typeof jsonBody === 'object' && !Array.isArray(jsonBody)) {
      bodyInfo.jsonKeyCount = Object.keys(jsonBody).length;
      bodyInfo.sensitiveFields = Object.keys(jsonBody)
        .filter((key) => sensitiveParamInfo(key))
        .slice(0, 20);
    }
  }

  const data = {
    messageType: message.type,
    startLine: displayStartLine,
    version: message.version,
    method: message.method ?? null,
    target: targetForDisplay,
    status: message.status ?? null,
    statusText: message.statusText ? clip(message.statusText, 200) : null,
    headerCount: message.headers.length,
    headers: headersOut,
    body: bodyInfo,
    checks: checks.map((c) => ({
      id: c.id,
      title: c.title,
      status: c.status,
      severity: c.severity,
      detail: c.detail,
    })),
    severityCounts,
    truncated: { headers: message.headers.length >= MAX_HEADER_LINES },
  };

  const evidence = [
    {
      title: message.type === 'request' ? '已脱敏请求头' : '已脱敏响应头',
      kind: 'http-message',
      excerpt: reconstructHead(message, displayStartLine),
      meta: { messageType: message.type, headerCount: message.headers.length },
    },
  ];

  const kindLabel =
    message.type === 'request'
      ? `HTTP 请求 ${message.method ?? ''} ${clip(targetForDisplay ?? '/', 200)}`
      : `HTTP 响应 ${message.status ?? ''} ${message.statusText ?? ''}`.trim();
  const summary = compact(
    `${kindLabel}（HTTP/${message.version ?? '?'}）：${message.headers.length} 个头，body ${message.bodySize} 字节。` +
      `发现 ${finalFindings.length} 条问题：high ${severityCounts.high} / medium ${severityCounts.medium} / ` +
      `low ${severityCounts.low} / info ${severityCounts.info}。凭据类头值均已脱敏。`,
    4000,
  );

  return {
    summary,
    findings: finalFindings,
    evidence,
    data,
    meta: {
      format: 'http-message',
      messageType: message.type,
      headerCount: message.headers.length,
      bodySize: message.bodySize,
      maxFindings,
    },
  };
}
