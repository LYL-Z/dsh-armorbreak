// ArmorBreak web domain — HAR 1.2 parsing and offline security analysis.
//
// Design notes:
//   * only `log.entries` metadata is read; response bodies are never echoed;
//   * every URL that reaches output goes through redactUrl() so tokens in query
//     strings are masked;
//   * findings aggregate per check across URLs so a 500-entry HAR does not
//     produce 500 duplicate findings;
//   * malformed HAR structures raise actionable Errors, malformed entries are
//     skipped defensively and counted.

import {
  clip,
  compact,
  finding,
  getHeader,
  isHtmlMime,
  isSensitiveUrlPath,
  normalizeHeaderPairs,
  parseCacheControl,
  redactParamValue,
  redactUrl,
  sensitiveParamInfo,
  severityRank,
  sortFindings,
  tryParseUrl,
} from './common.js';
import { auditHeaders } from './headers.js';

const DEFAULT_MAX_ENTRIES = 5000;
const MAX_AUDITED_URLS = 1000;
const BUILTIN_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'];

function safePairs(value) {
  try {
    return normalizeHeaderPairs(value, { source: 'HAR headers' });
  } catch {
    // A single entry with a malformed header array must not abort the analysis.
    return [];
  }
}

function sortedObject(map) {
  const out = {};
  for (const key of [...map.keys()].sort()) out[key] = map.get(key);
  return out;
}

function uniqueSamples(list, max = 3) {
  const seen = new Set();
  const out = [];
  for (const item of list) {
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Parse and validate a HAR 1.2 document.
 * @returns {{version:string, creator:object|null, pages:object[], entries:object[], rawEntryCount:number}}
 */
export function parseHarDocument(text) {
  const raw = String(text ?? '')
    .replace(/^\uFEFF/, '')
    .trim();
  if (!raw) {
    throw new Error(
      'HAR 输入为空：HAR 1.2 是浏览器/代理导出的 JSON 文件（含 log.entries 数组）。' +
        ' 请把 .har 文件作为目标（targetPath）或在 input.text 中提供其 JSON 内容。',
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `HAR 不是合法 JSON：${error.message}。请从浏览器 DevTools → Network → 右键 “Save all as HAR with content” 重新导出，并确认文件没有被截断。`,
    );
  }
  const log = parsed && typeof parsed === 'object' ? parsed.log : null;
  if (!log || typeof log !== 'object' || Array.isArray(log)) {
    throw new Error(
      'HAR 结构不合法：缺少顶层 log 对象。HAR 1.2 文档形如 {"log":{"version":"1.2","entries":[...]}}；请确认导出格式，而不是普通 JSON 或 HTTP Archive 的旧版本。',
    );
  }
  if (!Array.isArray(log.entries)) {
    throw new Error(
      'HAR 结构不合法：log.entries 必须是数组。请确认该文件是 HAR 1.2 文档；若只有 log.pages，则没有可分析的请求记录。',
    );
  }
  const entries = log.entries.filter((entry) => entry && typeof entry === 'object' && !Array.isArray(entry));
  const pages = Array.isArray(log.pages) ? log.pages.filter((p) => p && typeof p === 'object') : [];
  const creator =
    log.creator && typeof log.creator === 'object'
      ? {
          name: clip(log.creator.name ?? '', 120) || null,
          version: clip(log.creator.version ?? '', 60) || null,
        }
      : null;
  return {
    version: typeof log.version === 'string' ? clip(log.version, 20) : 'unknown',
    creator,
    pages: pages.slice(0, 500),
    entries,
    rawEntryCount: log.entries.length,
  };
}

/**
 * Analyze a parsed HAR document.
 *
 * opts: { maxEntries, maxFindings, maxItems, maxAuditedUrls }
 * @returns {{summary:string, findings:object[], evidence:object[], data:object, meta:object}}
 */
export function analyzeHar(har, opts = {}) {
  const maxEntries = Number.isFinite(opts.maxEntries)
    ? Math.max(1, Math.min(50000, Math.trunc(opts.maxEntries)))
    : DEFAULT_MAX_ENTRIES;
  const maxFindings = Number.isFinite(opts.maxFindings) ? Math.max(1, Math.trunc(opts.maxFindings)) : 100;
  const maxItems = Number.isFinite(opts.maxItems) ? Math.max(1, Math.trunc(opts.maxItems)) : 200;
  const maxAuditedUrls = Number.isFinite(opts.maxAuditedUrls)
    ? Math.max(1, Math.min(MAX_AUDITED_URLS, Math.trunc(opts.maxAuditedUrls)))
    : MAX_AUDITED_URLS;

  const entries = har.entries.slice(0, maxEntries);
  const entriesTruncated = har.entries.length > entries.length;

  let skippedEntries = 0;
  const records = [];
  for (const entry of entries) {
    const req = entry.request;
    if (!req || typeof req !== 'object') {
      skippedEntries += 1;
      continue;
    }
    const urlRaw = typeof req.url === 'string' ? req.url.trim() : '';
    if (!urlRaw) {
      skippedEntries += 1;
      continue;
    }
    const res = entry.response && typeof entry.response === 'object' ? entry.response : null;
    records.push({
      urlRaw,
      url: tryParseUrl(urlRaw),
      method: typeof req.method === 'string' && req.method.trim() ? req.method.trim().toUpperCase() : 'GET',
      status: Number.isFinite(Number(res?.status)) ? Number(res.status) : 0,
      mimeType: typeof res?.content?.mimeType === 'string' ? clip(res.content.mimeType, 120) : '',
      requestHeaders: safePairs(req.headers),
      responseHeaders: safePairs(res?.headers),
      pageRef: typeof entry.pageref === 'string' ? entry.pageref : null,
      queryString: Array.isArray(req.queryString) ? req.queryString : null,
      postData: req.postData && typeof req.postData === 'object' ? req.postData : null,
      hasResponse: Boolean(res),
    });
  }

  // ----- aggregate summary -------------------------------------------------
  const hosts = new Set();
  const methods = new Map();
  const statusClasses = new Map();
  let httpsResponses = 0;
  let httpResponses = 0;
  let documents = 0;
  for (const rec of records) {
    if (rec.url) hosts.add(rec.url.hostname);
    methods.set(rec.method, (methods.get(rec.method) ?? 0) + 1);
    if (rec.status > 0) {
      const cls = `${Math.min(9, Math.floor(rec.status / 100))}xx`;
      statusClasses.set(cls, (statusClasses.get(cls) ?? 0) + 1);
    }
    if (rec.url) {
      if (rec.url.protocol === 'https:') httpsResponses += 1;
      else if (rec.url.protocol === 'http:') httpResponses += 1;
    }
    if (isHtmlMime(rec.mimeType)) documents += 1;
  }

  // ----- header audit (unique response URLs, bounded) ----------------------
  const uniqueResponses = new Map();
  for (const rec of records) {
    if (!rec.hasResponse) continue;
    if (!uniqueResponses.has(rec.urlRaw)) uniqueResponses.set(rec.urlRaw, rec);
  }
  const responseList = [...uniqueResponses.values()];
  const audited = responseList.slice(0, maxAuditedUrls);
  const auditsTruncated = responseList.length > audited.length;

  const checkAgg = new Map(); // checkId -> aggregate
  const findingAgg = new Map(); // finding title -> { finding, count, samples }
  const cookieAgg = new Map(); // name|domain -> cookie record + count

  const addFinding = (f, urlRaw) => {
    let agg = findingAgg.get(f.title);
    if (!agg) {
      agg = { finding: f, count: 0, samples: [] };
      findingAgg.set(f.title, agg);
    }
    agg.count += 1;
    agg.samples.push(redactUrl(urlRaw));
  };

  for (const rec of audited) {
    const audit = auditHeaders(rec.responseHeaders, {
      url: rec.urlRaw,
      contentType: rec.mimeType || undefined,
      requestOrigin: getHeader(rec.requestHeaders, 'origin'),
    });
    for (const check of audit.checks) {
      let agg = checkAgg.get(check.id);
      if (!agg) {
        agg = {
          id: check.id,
          title: check.title,
          fail: 0,
          warn: 0,
          pass: 0,
          info: 0,
          na: 0,
          affectedHosts: new Set(),
          detail: check.detail,
        };
        checkAgg.set(check.id, agg);
      }
      agg[check.status] = (agg[check.status] ?? 0) + 1;
      if ((check.status === 'fail' || check.status === 'warn') && rec.url) {
        agg.affectedHosts.add(rec.url.hostname);
      }
    }
    for (const f of audit.findings) addFinding(f, rec.urlRaw);
    for (const cookie of audit.cookies) {
      const key = `${cookie.name.toLowerCase()}|${cookie.domain ?? ''}`;
      let agg = cookieAgg.get(key);
      if (!agg) {
        agg = { ...cookie, count: 0 };
        cookieAgg.set(key, agg);
      }
      agg.count += 1;
      if (agg.issues.length < cookie.issues.length) agg.issues = cookie.issues.slice();
    }
  }

  // ----- HAR-specific issues ----------------------------------------------
  const tokenLeaks = new Map(); // host|param -> aggregate
  const postFields = new Map(); // host|field -> aggregate
  const plaintextCreds = new Map(); // host|scheme -> aggregate
  const cacheIssues = new Map(); // host|issue -> aggregate
  const mixedContent = new Map(); // pageRef|resource -> aggregate

  for (const rec of records) {
    const host = rec.url ? rec.url.hostname : '(invalid-url)';
    const params = [];
    if (Array.isArray(rec.queryString)) {
      for (const item of rec.queryString) {
        if (item && typeof item === 'object' && typeof item.name === 'string') {
          params.push([item.name, String(item.value ?? '')]);
        }
      }
    }
    if (!params.length && rec.url) {
      for (const [name, value] of rec.url.searchParams) params.push([name, value]);
    }
    for (const [name, value] of params) {
      const info = sensitiveParamInfo(name);
      if (!info) continue;
      const key = `${host}|${info.marker}`;
      let agg = tokenLeaks.get(key);
      if (!agg) {
        agg = {
          host,
          param: info.name,
          marker: info.marker,
          severity: info.severity,
          count: 0,
          sampleUrl: redactUrl(rec.urlRaw),
          redactedValue: redactParamValue(value),
        };
        tokenLeaks.set(key, agg);
      }
      agg.count += 1;
    }

    if (rec.postData && Array.isArray(rec.postData.params)) {
      for (const item of rec.postData.params.slice(0, 100)) {
        const name = item && typeof item === 'object' ? String(item.name ?? '') : '';
        if (!name || !sensitiveParamInfo(name)) continue;
        const key = `${host}|${name.toLowerCase()}`;
        let agg = postFields.get(key);
        if (!agg) {
          agg = { host, field: name, count: 0, scheme: rec.url?.protocol?.replace(':', '') ?? 'unknown' };
          postFields.set(key, agg);
        }
        agg.count += 1;
      }
    }

    const authHeader = getHeader(rec.requestHeaders, 'authorization');
    if (authHeader && rec.url && rec.url.protocol === 'http:') {
      const key = `${host}|authorization`;
      let agg = plaintextCreds.get(key);
      if (!agg) {
        agg = { host, header: 'authorization', count: 0, sampleUrl: redactUrl(rec.urlRaw) };
        plaintextCreds.set(key, agg);
      }
      agg.count += 1;
    }

    if (rec.url && isSensitiveUrlPath(rec.url) && rec.status >= 200 && rec.status < 300) {
      const mime = rec.mimeType || '';
      if (isHtmlMime(mime) || /json|xml/i.test(mime)) {
        const cacheRaw = getHeader(rec.responseHeaders, 'cache-control');
        const cc = cacheRaw ? parseCacheControl(cacheRaw) : new Map();
        const noStore = cc.get('no-store') === true;
        const isPublic = cc.get('public') === true;
        let issue = null;
        if (!cacheRaw) issue = 'cache-control-missing';
        else if (isPublic && !noStore) issue = 'cache-control-public';
        else if (!noStore) issue = 'cache-control-no-store-missing';
        if (issue) {
          const key = `${host}|${issue}`;
          let agg = cacheIssues.get(key);
          if (!agg) {
            agg = {
              host,
              issue,
              count: 0,
              sampleUrl: redactUrl(rec.urlRaw),
              cacheControl: cacheRaw ? clip(cacheRaw, 200) : null,
            };
            cacheIssues.set(key, agg);
          }
          agg.count += 1;
        }
      }
    }
  }

  // Mixed content: approximate by pageref groups (document protocol vs resource protocol).
  const docByPage = new Map();
  for (const rec of records) {
    if (!rec.pageRef || !rec.url) continue;
    if (!isHtmlMime(rec.mimeType)) continue;
    if (!docByPage.has(rec.pageRef)) docByPage.set(rec.pageRef, rec);
  }
  for (const rec of records) {
    if (!rec.pageRef || !rec.url || rec.url.protocol !== 'http:') continue;
    const doc = docByPage.get(rec.pageRef);
    if (!doc || !doc.url || doc.url.protocol !== 'https:') continue;
    const key = `${rec.pageRef}|${rec.urlRaw}`;
    if (mixedContent.has(key)) continue;
    mixedContent.set(key, {
      page: redactUrl(doc.urlRaw),
      resource: redactUrl(rec.urlRaw),
      pageRef: clip(rec.pageRef, 100),
    });
  }

  // ----- build findings ----------------------------------------------------
  const findings = [];

  const aggregatedHeaderFindings = [...findingAgg.values()].sort((a, b) => {
    const sev = severityRank(b.finding.severity) - severityRank(a.finding.severity);
    return sev || (a.finding.title < b.finding.title ? -1 : a.finding.title > b.finding.title ? 1 : 0);
  });
  for (const agg of aggregatedHeaderFindings) {
    const base = agg.finding;
    const samples = uniqueSamples(agg.samples, 3);
    findings.push(
      finding({
        title: base.title,
        severity: base.severity,
        description: `${base.description}（在 ${agg.count} 个响应中观察到；示例：${samples.join('、') || 'n/a'}）`,
        verification: base.verification,
        method: base.method,
        cwe: base.cwe,
        remediation: base.remediation,
        target: samples[0] ? clip(samples[0], 300) : null,
        evidence: [
          {
            title: base.title,
            excerpt: compact(
              `受影响响应数: ${agg.count}\n示例: ${samples.join('\n')}\n${base.evidence[0]?.excerpt ?? ''}`,
              2000,
            ),
          },
        ],
      }),
    );
  }

  for (const agg of tokenLeaks.values()) {
    findings.push(
      finding({
        title: `[url-token-leak] URL 查询参数携带敏感凭据：${clip(agg.param, 80)}`,
        severity: agg.severity,
        description:
          `观察到 ${agg.count} 个请求把敏感值放在 URL 查询参数 “${clip(agg.param, 80)}” 中（值已脱敏：${agg.redactedValue}）。` +
          ' URL 会进入浏览器历史、代理/服务器访问日志、Referer 与监控系统，凭据因此可横向泄露。',
        verification: 'observed',
        method: 'har-url-parameter-analysis',
        cwe: 'CWE-598',
        remediation: '改用 Authorization 头或服务端会话；若必须使用查询参数，限制其生命周期并确保日志脱敏。',
        target: agg.host,
        evidence: [{ title: '示例 URL（已脱敏）', excerpt: agg.sampleUrl }],
      }),
    );
  }

  for (const agg of postFields.values()) {
    findings.push(
      finding({
        title: `[sensitive-request-field] 请求体携带敏感字段：${clip(agg.field, 80)}`,
        severity: agg.scheme === 'http' ? 'medium' : 'info',
        description:
          `观察到 ${agg.count} 个请求在请求体中提交敏感字段 “${clip(agg.field, 80)}”（HAR 可能包含明文值，请勿分发原始 HAR）。` +
          (agg.scheme === 'http' ? ' 该请求经明文 HTTP 发送，凭据可被链路监听截获。' : ' 传输为 HTTPS，风险主要在 HAR 文件本身的留存与共享。'),
        verification: 'observed',
        method: 'har-request-body-analysis',
        cwe: agg.scheme === 'http' ? 'CWE-319' : null,
        remediation: '避免在可分享的 HAR 中保留提交内容；生产环境应启用 HTTPS 并对 HAR 做脱敏。',
        target: agg.host,
        evidence: [{ title: 'HAR postData.params（值已省略）', excerpt: `${agg.host} 中字段 ${clip(agg.field, 80)} 出现 ${agg.count} 次` }],
      }),
    );
  }

  for (const agg of plaintextCreds.values()) {
    findings.push(
      finding({
        title: '[plaintext-auth] 明文 HTTP 请求携带 Authorization 头',
        severity: 'medium',
        description: `观察到 ${agg.count} 个 HTTP（非 HTTPS）请求携带 Authorization 头，凭据在传输链路上可被截获。`,
        verification: 'observed',
        method: 'har-transport-analysis',
        cwe: 'CWE-319',
        remediation: '强制 HTTPS（HSTS + 全站跳转），不要在明文信道发送认证头。',
        target: agg.host,
        evidence: [{ title: '示例 URL（已脱敏）', excerpt: agg.sampleUrl }],
      }),
    );
  }

  for (const agg of cacheIssues.values()) {
    const titles = {
      'cache-control-missing': '敏感响应缺少 Cache-Control',
      'cache-control-public': '敏感响应被标记为 public 缓存',
      'cache-control-no-store-missing': '敏感响应未设置 no-store',
    };
    findings.push(
      finding({
        title: `[${agg.issue}] ${titles[agg.issue] || agg.issue}`,
        severity: agg.issue === 'cache-control-public' ? 'medium' : 'low',
        description:
          `观察到 ${agg.count} 个敏感 URL 的响应存在缓存策略缺口` +
          `${agg.cacheControl ? `（Cache-Control: ${agg.cacheControl}）` : '（未设置 Cache-Control）'}。` +
          ' 共享缓存/中间代理可能把响应提供给其他用户。',
        verification: 'observed',
        method: 'har-cache-control-analysis',
        cwe: 'CWE-524',
        remediation: '对认证/账户相关响应设置 Cache-Control: no-store。',
        target: agg.host,
        evidence: [{ title: '示例 URL（已脱敏）', excerpt: agg.sampleUrl }],
      }),
    );
  }

  if (mixedContent.size > 0) {
    const items = [...mixedContent.values()].sort((a, b) =>
      a.page < b.page ? -1 : a.page > b.page ? 1 : a.resource < b.resource ? -1 : a.resource > b.resource ? 1 : 0,
    );
    const samples = uniqueSamples(items.map((i) => `${i.page} → ${i.resource}`), 3);
    findings.push(
      finding({
        title: '[mixed-content] HTTPS 页面加载明文 HTTP 资源',
        severity: 'medium',
        description:
          `检测到 ${items.length} 个 HTTPS 页面上下文中的 http:// 资源引用（基于 HAR pageref 关联，可能包含预检/重定向请求）。` +
          ' 混合内容会被现代浏览器拦截或降级，且可能被中间人替换。',
        verification: 'hypothesis',
        method: 'har-pageref-mixed-content-inference',
        cwe: 'CWE-319',
        remediation: '把资源改用 https:// 或以 CSP upgrade-insecure-requests 强制升级。',
        target: items[0]?.page ?? null,
        evidence: [{ title: '混合内容示例', excerpt: compact(samples.join('\n'), 2000) }],
      }),
    );
  }

  const sortedFindings = sortFindings(findings);
  const finalFindings = sortedFindings.slice(0, maxFindings);
  const findingsTruncated = sortedFindings.length > finalFindings.length;

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of finalFindings) severityCounts[f.severity] += 1;

  // ----- data --------------------------------------------------------------
  const securityHeaders = [...checkAgg.values()]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((agg) => ({
      id: agg.id,
      title: agg.title,
      fail: agg.fail,
      warn: agg.warn,
      pass: agg.pass,
      info: agg.info,
      na: agg.na,
      affectedHosts: agg.affectedHosts.size,
      sampleHosts: [...agg.affectedHosts].sort().slice(0, 3),
      detail: agg.detail,
    }));

  const cookies = [...cookieAgg.values()]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .slice(0, maxItems)
    .map((c) => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      path: c.path,
      domain: c.domain,
      issues: c.issues,
      observations: c.count,
    }));

  const data = {
    format: 'HAR',
    version: har.version,
    creator: har.creator,
    summary: {
      rawEntries: har.rawEntryCount,
      analyzedEntries: records.length,
      skippedEntries,
      uniqueResponseUrls: responseList.length,
      auditedResponseUrls: audited.length,
      pageCount: har.pages.length,
      hostCount: hosts.size,
      httpsResponses,
      httpResponses,
      documentResponses: documents,
      byMethod: sortedObject(methods),
      byStatusClass: sortedObject(statusClasses),
    },
    hosts: [...hosts].sort().slice(0, maxItems),
    securityHeaders,
    cookies,
    tokenLeaks: [...tokenLeaks.values()]
      .sort((a, b) => (a.host + a.param < b.host + b.param ? -1 : a.host + a.param > b.host + b.param ? 1 : 0))
      .slice(0, maxItems),
    sensitiveRequestFields: [...postFields.values()]
      .sort((a, b) => (a.host + a.field < b.host + b.field ? -1 : a.host + a.field > b.host + b.field ? 1 : 0))
      .slice(0, maxItems),
    plaintextCredentials: [...plaintextCreds.values()]
      .sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : 0))
      .slice(0, maxItems),
    cacheIssues: [...cacheIssues.values()]
      .sort((a, b) => (a.host + a.issue < b.host + b.issue ? -1 : a.host + a.issue > b.host + b.issue ? 1 : 0))
      .slice(0, maxItems),
    mixedContent: [...mixedContent.values()]
      .sort((a, b) => (a.page < b.page ? -1 : a.page > b.page ? 1 : a.resource < b.resource ? -1 : 1))
      .slice(0, maxItems),
    severityCounts,
    truncated: {
      entries: entriesTruncated,
      headerAudit: auditsTruncated,
      findings: findingsTruncated,
    },
  };

  // ----- evidence ----------------------------------------------------------
  const evidence = [
    {
      title: 'HAR 概览',
      kind: 'har-summary',
      excerpt: compact(
        [
          `HAR ${har.version}；原始条目 ${har.rawEntryCount}，分析 ${records.length}，跳过 ${skippedEntries}`,
          `主机 ${hosts.size}；HTTPS 响应 ${httpsResponses}；HTTP 响应 ${httpResponses}；文档响应 ${documents}`,
          `方法分布: ${[...methods.entries()].map(([k, v]) => `${k}=${v}`).join(', ')}`,
        ].join('\n'),
        2000,
      ),
      meta: { format: 'har', version: har.version },
    },
  ];
  const failingChecks = securityHeaders.filter((c) => c.fail > 0 || c.warn > 0).slice(0, 20);
  if (failingChecks.length) {
    evidence.push({
      title: '安全响应头缺口汇总',
      kind: 'header-audit',
      excerpt: compact(
        failingChecks
          .map((c) => `${c.id}: fail=${c.fail} warn=${c.warn} hosts=${c.affectedHosts}`)
          .join('\n'),
        2000,
      ),
      meta: { checks: failingChecks.map((c) => c.id) },
    });
  }

  const summaryText = compact(
    `HAR ${har.version}：分析 ${records.length} 个请求（跳过 ${skippedEntries}），${hosts.size} 台主机，` +
      `${responseList.length} 个唯一响应 URL。发现 ${finalFindings.length} 条问题：` +
      `critical ${severityCounts.critical} / high ${severityCounts.high} / medium ${severityCounts.medium} / ` +
      `low ${severityCounts.low} / info ${severityCounts.info}；` +
      `缺失安全头 ${securityHeaders.filter((c) => c.fail > 0 || c.warn > 0).length} 类，` +
      `敏感 URL 参数泄露 ${tokenLeaks.size} 处，Cookie 观察 ${cookies.length} 个。`,
    4000,
  );

  return {
    summary: summaryText,
    findings: finalFindings,
    evidence,
    data,
    meta: {
      format: 'HAR',
      harVersion: har.version,
      analyzedEntries: records.length,
      entriesTruncated,
      headerAuditTruncated: auditsTruncated,
      findingsTruncated,
      maxEntries,
      maxFindings,
    },
  };
}
