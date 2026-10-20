// ArmorBreak web domain — capability manifest.
//
// Domain: offline web / API / browser-traffic analysis.
// All capabilities are riskLevel L0 (read-only, fully offline, no network).

import { boundedInt, textFromInput } from './common.js';
import { auditHeaders, parseHeaderSet } from './headers.js';
import { analyzeHar, parseHarDocument } from './har.js';
import { analyzeHttpMessage, parseHttpMessage } from './httpmsg.js';
import { analyzeOpenApi, parseOpenApiDocument } from './openapi.js';

const EMPTY_PARAMS = Object.freeze({ type: 'object', properties: {}, additionalProperties: false });

function budget(input) {
  const limits = input.limits ?? {};
  return {
    maxBytes: boundedInt(limits.maxBytes, 1024 * 1024, 1, 64 * 1024 * 1024),
    maxFindings: boundedInt(limits.maxFindings, 100, 1, 1000),
    maxItems: boundedInt(limits.maxItems, 200, 1, 5000),
  };
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

export default {
  domain: 'web',
  capabilities: [
    {
      id: 'web.har',
      title: 'HAR 流量安全审计',
      description:
        '离线解析浏览器/代理导出的 HAR 1.2 JSON：统计请求、主机与状态分布；逐响应审计安全头（CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy）、Cookie 安全属性、CORS 通配+凭据、敏感 URL 参数与 token 泄露、明文 HTTP 凭据、敏感响应缓存策略、HTTPS 页面混合内容。不读取响应体，不回显凭据；结果按检查项聚合避免重复。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          maxEntries: {
            type: 'integer',
            minimum: 1,
            maximum: 50000,
            description: '最多分析的 HAR 条目数（默认 5000）',
          },
          maxAuditedUrls: {
            type: 'integer',
            minimum: 1,
            maximum: 1000,
            description: '最多逐响应审计的唯一 URL 数（默认 1000）',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const har = parseHarDocument(textFromInput(input, 'HAR 文档'));
        const result = analyzeHar(har, {
          maxEntries: options.maxEntries,
          maxAuditedUrls: options.maxAuditedUrls,
          maxFindings: limits.maxFindings,
          maxItems: limits.maxItems,
        });
        return {
          ...result,
          meta: { ...result.meta, domain: 'web', capability: 'web.har', limits },
        };
      },
    },
    {
      id: 'web.openapi',
      title: 'OpenAPI 规范安全审查',
      description:
        '离线解析 OpenAPI 3.x（JSON 或内置 YAML 子集；兼容 Swagger 2.0）：审计 servers（明文 HTTP、模板变量缺省值）、认证方案（query 中的 apiKey、Basic+HTTP、OAuth2 implicit/password、OIDC 缺 URL）、路径/方法清单、非公开操作缺认证声明、参数 schema 缺失、requestBody/响应契约缺失、deprecated 接口与 operationId 重复。用于接口上线前契约评审。',
      riskLevel: 'L0',
      params: EMPTY_PARAMS,
      async run(input) {
        const limits = budget(input);
        const parsed = parseOpenApiDocument(textFromInput(input, 'OpenAPI 文档'));
        const result = analyzeOpenApi(parsed, {
          maxFindings: limits.maxFindings,
          maxItems: limits.maxItems,
        });
        return {
          ...result,
          meta: { ...result.meta, domain: 'web', capability: 'web.openapi', limits },
        };
      },
    },
    {
      id: 'web.headers',
      title: 'HTTP 响应头安全审计',
      description:
        '审计一组 HTTP 响应头（JSON 对象/数组或 “Header: value” 文本）：CSP 质量（unsafe-inline/unsafe-eval/通配/frame-ancestors）、HSTS、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy、CORS 通配+凭据、技术栈指纹泄露、敏感响应缓存策略、Set-Cookie 的 Secure/HttpOnly/SameSite 与前缀约束。凭据类头值输出时脱敏。',
      riskLevel: 'L0',
      params: {
        type: 'object',
        properties: {
          url: {
            type: 'string',
            description: '可选：响应对应的绝对 URL（用于判断 HTTPS/敏感路径/HSTS 适用性）',
          },
          contentType: {
            type: 'string',
            description: '可选：响应 Content-Type；省略时从响应头读取；非 HTML 时跳过 CSP/点击劫持检查',
          },
        },
        additionalProperties: false,
      },
      async run(input) {
        const options = input.options ?? {};
        const limits = budget(input);
        const parsed = parseHeaderSet(textFromInput(input, '响应头'));
        const audit = auditHeaders(parsed.pairs, {
          url: options.url ?? parsed.url ?? undefined,
          contentType: options.contentType ?? parsed.contentType ?? undefined,
          requestOrigin: parsed.origin ?? undefined,
        });
        const counts = severityCounts(audit.findings);
        const findings = audit.findings.slice(0, limits.maxFindings);
        const statusCounts = { pass: 0, warn: 0, fail: 0, info: 0, na: 0 };
        for (const check of audit.checks) statusCounts[check.status] = (statusCounts[check.status] ?? 0) + 1;
        const data = {
          url: audit.url,
          https: audit.https,
          documentContext: audit.html,
          headerCount: parityCount(audit.headers),
          headers: audit.headers,
          securityChecks: audit.checks,
          cookies: audit.cookies,
          statusCounts,
          severityCounts: severityCounts(findings),
          truncated: { findings: audit.findings.length > findings.length },
        };
        const summary =
          `已审计 ${data.headerCount} 个响应头：fail ${statusCounts.fail} / warn ${statusCounts.warn} / ` +
          `pass ${statusCounts.pass} / info ${statusCounts.info}，Cookie ${audit.cookies.length} 个。` +
          `发现 ${findings.length} 条问题：high ${counts.high} / medium ${counts.medium} / ` +
          `low ${counts.low} / info ${counts.info}。`;
        return {
          summary,
          findings,
          evidence: [
            {
              title: '被审计的响应头（凭据值已脱敏）',
              kind: 'header-set',
              excerpt: audit.headers.map((h) => `${h.name}: ${h.value}`).join('\n').slice(0, 2000),
              meta: { url: audit.url, https: audit.https },
            },
          ],
          data,
          meta: {
            domain: 'web',
            capability: 'web.headers',
            headerCount: data.headerCount,
            url: audit.url,
            https: audit.https,
            limits,
          },
        };
      },
    },
    {
      id: 'web.http_message',
      title: '原始 HTTP 报文解析与检查',
      description:
        '解析原始 HTTP 请求/响应文本（起始行、头部、空行、body）：识别请求方法/目标/状态码，检查 Host 缺失、URL 敏感参数、TE+CL 走私前置条件、Content-Length 不一致、body 缺 Content-Type、请求体敏感字段名，并对响应执行安全头与 Cookie 审计。Authorization/Cookie 等凭据头与 body 内容均不回显。',
      riskLevel: 'L0',
      params: EMPTY_PARAMS,
      async run(input) {
        const limits = budget(input);
        const message = parseHttpMessage(textFromInput(input, 'HTTP 报文'));
        const result = analyzeHttpMessage(message, { maxFindings: limits.maxFindings });
        return {
          ...result,
          meta: { ...result.meta, domain: 'web', capability: 'web.http_message', limits },
        };
      },
    },
  ],
};

function parityCount(value) {
  return Array.isArray(value) ? value.length : 0;
}
