// ArmorBreak web domain — HTTP response header / cookie security audit.
//
// The audit is purely observational: every finding states exactly which
// header or attribute was observed (or missing). No exploitability claim is
// made; `verification` is always "observed" for header/cookie facts.

import {
  clip,
  compact,
  finding,
  getHeader,
  getHeaderValues,
  isHtmlMime,
  isSensitiveUrlPath,
  normalizeHeaderPairs,
  parseCacheControl,
  parseSetCookie,
  describeCookie,
  redactHeaderValue,
  redactUrl,
  sortFindings,
  severityRank,
  tryParseUrl,
} from './common.js';

// Hard bound so a hostile/oversized header set cannot blow up the audit.
const MAX_HEADER_PAIRS = 500;

const REFERRER_GOOD = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
]);

const COOKIE_REMEDIATION = {
  'cookie-secure-missing': '为所有 Cookie 添加 Secure 属性，并确保站点全站 HTTPS。',
  'cookie-httponly-missing': '对会话/认证 Cookie 添加 HttpOnly，避免被 XSS 读取。',
  'cookie-samesite-missing': '显式设置 SameSite=Lax（会话 Cookie 建议 Strict），不要依赖浏览器默认值。',
  'cookie-samesite-none-insecure': 'SameSite=None 必须同时带 Secure；否则移除 None 或改用 Lax/Strict。',
  'cookie-host-prefix-violation': '__Host- 前缀 Cookie 必须同时满足 Secure、Path=/、无 Domain 属性。',
  'cookie-secure-prefix-violation': '__Secure- 前缀 Cookie 必须带 Secure 属性。',
};

const HEADER_REMEDIATION = {
  csp: '配置 Content-Security-Policy：至少给出 default-src 与 script-src，避免 unsafe-inline/unsafe-eval/*。',
  hsts: '对 HTTPS 站点设置 Strict-Transport-Security: max-age=31536000; includeSubDomains（视需求加 preload）。',
  xfo: '设置 X-Frame-Options: DENY 或 SAMEORIGIN，或使用 CSP frame-ancestors 达到相同效果。',
  xcto: '设置 X-Content-Type-Options: nosniff，禁止浏览器 MIME 嗅探。',
  referrer: '设置 Referrer-Policy: strict-origin-when-cross-origin（或更严格的值），避免泄露 URL 中的敏感信息。',
  permissions: '按需设置 Permissions-Policy，显式禁用不需要的浏览器特性（camera、geolocation 等）。',
  cors: '不要对携带凭据的接口使用通配符 Origin；使用固定 allowlist 并在服务端校验 Origin。',
  cache: '对敏感响应设置 Cache-Control: no-store（必要时加 Pragma: no-cache）。',
};

/** Parse a CSP header value (multiple comma-separated policies are merged). */
export function parseCsp(value) {
  const directives = new Map();
  for (const policy of String(value ?? '').split(',')) {
    for (const part of policy.split(';')) {
      const tokens = part.trim().split(/\s+/).filter(Boolean);
      if (!tokens.length) continue;
      const name = tokens[0].toLowerCase();
      if (!directives.has(name)) directives.set(name, new Set());
      for (const token of tokens.slice(1)) directives.get(name).add(token.toLowerCase());
    }
  }
  return directives;
}

function cspDirectiveTokens(directives, name) {
  return directives.get(name) || new Set();
}

function cspEffectiveScript(directives) {
  if (directives.has('script-src')) return cspDirectiveTokens(directives, 'script-src');
  return cspDirectiveTokens(directives, 'default-src');
}

function inferHtml({ html, contentType, parsedUrl }) {
  if (typeof html === 'boolean') return html;
  if (contentType) return isHtmlMime(contentType);
  if (parsedUrl) {
    return !/\.(?:json|js|mjs|cjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|xml|txt|webp|avif|mp4|webm)$/i.test(
      parsedUrl.pathname,
    );
  }
  return true; // standalone header-set audits default to document expectations
}

function inferApi({ contentType, parsedUrl }) {
  if (contentType) return /(?:json|xml)/i.test(contentType);
  if (parsedUrl) return /\.(?:json|xml)$/i.test(parsedUrl.pathname);
  return false;
}

function check(status, id, title, severity, detail, extra = {}) {
  return {
    id,
    title,
    status,
    severity,
    detail: compact(detail, 1200),
    ...extra,
  };
}

/**
 * Audit one response's headers.
 *
 * ctx: {
 *   url?: string,                       // absolute URL of the response (used for scheme/path context)
 *   contentType?: string,
 *   html?: boolean,                     // override document/asset classification
 *   https?: boolean|null,               // override scheme knowledge
 *   requestOrigin?: string|null,        // value of the request Origin header (CORS reflection check)
 *   sensitiveUrl?: boolean,             // override sensitive-path inference
 * }
 *
 * Returns { checks, findings, cookies, headers, https, html, url }.
 */
export function auditHeaders(pairsInput, ctx = {}) {
  const pairs = normalizeHeaderPairs(pairsInput, { source: '响应头' }).slice(0, MAX_HEADER_PAIRS);
  const parsedUrl = ctx.url ? tryParseUrl(ctx.url) : null;
  const https =
    typeof ctx.https === 'boolean' ? ctx.https : parsedUrl ? parsedUrl.protocol === 'https:' : null;
  const contentType = ctx.contentType ?? getHeader(pairs, 'content-type');
  const html = inferHtml({ html: ctx.html, contentType, parsedUrl });
  const api = inferApi({ contentType, parsedUrl });
  const requestOrigin = ctx.requestOrigin ?? null;

  const checks = [];
  const cookieChecks = [];
  const findings = [];

  const add = (c) => checks.push(c);
  const cwe693 = 'CWE-693';

  // ----- Content-Security-Policy -------------------------------------------
  const cspRaw = getHeader(pairs, 'content-security-policy');
  const cspReportOnly = getHeader(pairs, 'content-security-policy-report-only');
  let cspFrameAncestors = false;
  if (!html) {
    add(check('na', 'csp', 'Content-Security-Policy', 'info', '非 HTML 响应，CSP 不适用。'));
  } else if (!cspRaw) {
    add(
      check(
        'fail',
        'csp',
        '缺少 Content-Security-Policy',
        'medium',
        `HTML 响应未设置 Content-Security-Policy${cspReportOnly ? '（仅有 Report-Only 不会阻止执行）' : ''}，` +
          '无法通过策略收敛 XSS/注入的利用面。',
        { cwe: cwe693, remediation: HEADER_REMEDIATION.csp },
      ),
    );
  } else {
    add(check('pass', 'csp', 'Content-Security-Policy', 'info', '已设置 CSP。'));
    const directives = parseCsp(cspRaw);
    cspFrameAncestors = directives.has('frame-ancestors');
    const script = cspEffectiveScript(directives);
    if (script.size === 0) {
      add(
        check(
          'fail',
          'csp-script-src',
          'CSP 未约束脚本来源',
          'medium',
          'CSP 既无 script-src 也无 default-src，脚本来源不受限制。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.csp },
        ),
      );
    }
    if (script.has("'unsafe-inline'")) {
      add(
        check(
          'warn',
          'csp-unsafe-inline',
          'CSP 允许 inline 脚本（unsafe-inline）',
          'medium',
          'script-src/default-src 包含 \'unsafe-inline\'，XSS 防护能力显著下降。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.csp },
        ),
      );
    }
    if (script.has("'unsafe-eval'")) {
      add(
        check(
          'warn',
          'csp-unsafe-eval',
          'CSP 允许 eval（unsafe-eval）',
          'low',
          'script-src/default-src 包含 \'unsafe-eval\'，扩大了代码注入执行面。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.csp },
        ),
      );
    }
    if (script.has('*') || cspDirectiveTokens(directives, 'default-src').has('*')) {
      add(
        check(
          'warn',
          'csp-wildcard',
          'CSP 使用通配符来源',
          'medium',
          'CSP 中出现 * 通配源，策略基本无法阻止加载外部恶意脚本。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.csp },
        ),
      );
    }
    if (!directives.has('object-src') && !cspDirectiveTokens(directives, 'default-src').has("'none'")) {
      add(check('info', 'csp-object-src', 'CSP 未显式禁用 object-src', 'info', '建议添加 object-src \'none\' 减少插件类攻击面。'));
    }
    if (!directives.has('base-uri')) {
      add(check('info', 'csp-base-uri', 'CSP 未限制 base-uri', 'info', '建议添加 base-uri \'none\' 防止 <base> 注入。'));
    }
    if (!directives.has('report-to') && !directives.has('report-uri')) {
      add(check('info', 'csp-reporting', 'CSP 未配置上报', 'info', '未配置 report-uri/report-to，策略违规不可观测。'));
    }
  }

  // ----- Strict-Transport-Security -----------------------------------------
  const hstsRaw = getHeader(pairs, 'strict-transport-security');
  if (!hstsRaw) {
    if (https === false) {
      add(check('na', 'hsts', 'Strict-Transport-Security', 'info', '响应经明文 HTTP 传输，HSTS 会被浏览器忽略，不适用。'));
    } else if (https === true) {
      add(
        check(
          'fail',
          'hsts',
          '缺少 Strict-Transport-Security',
          'medium',
          'HTTPS 响应未设置 HSTS，首次访问仍可能被降级劫持。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.hsts },
        ),
      );
    } else {
      add(
        check(
          'warn',
          'hsts',
          '无法判断 HTTPS 上下文且缺少 HSTS',
          'low',
          '未提供 URL 方案信息；若站点使用 HTTPS 则必须配置 HSTS（纯 HTTP 下该头无效）。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.hsts },
        ),
      );
    }
  } else {
    add(check('pass', 'hsts', 'Strict-Transport-Security', 'info', '已设置 HSTS。'));
    if (https === false) {
      add(
        check(
          'warn',
          'hsts-on-plain-http',
          'HSTS 出现在明文 HTTP 响应上',
          'low',
          'HSTS 头只在 HTTPS 响应中生效；明文响应上的该头会被浏览器忽略。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.hsts },
        ),
      );
    }
    const maxAgeMatch = /(?:^|;)\s*max-age\s*=\s*(\d+)/i.exec(hstsRaw);
    if (!maxAgeMatch) {
      add(
        check('fail', 'hsts-max-age', 'HSTS 缺少 max-age', 'medium', 'HSTS 未声明 max-age，浏览器不会缓存该策略。', {
          cwe: cwe693,
          remediation: HEADER_REMEDIATION.hsts,
        }),
      );
    } else {
      const maxAge = Number(maxAgeMatch[1]);
      if (maxAge === 0) {
        add(
          check('fail', 'hsts-max-age-zero', 'HSTS max-age=0（主动关闭）', 'medium', 'max-age=0 会清除已缓存的 HSTS 策略。', {
            cwe: cwe693,
            remediation: HEADER_REMEDIATION.hsts,
          }),
        );
      } else if (maxAge < 15552000) {
        add(
          check('warn', 'hsts-max-age-short', 'HSTS max-age 偏短', 'low', `max-age=${maxAge} 小于 180 天，建议 ≥31536000。`, {
            cwe: cwe693,
            remediation: HEADER_REMEDIATION.hsts,
          }),
        );
      }
    }
    if (!/includeSubDomains/i.test(hstsRaw)) {
      add(check('info', 'hsts-subdomains', 'HSTS 未包含 includeSubDomains', 'info', '子域不受 HSTS 保护，可按需添加 includeSubDomains。'));
    }
  }

  // ----- X-Frame-Options / frame-ancestors --------------------------------
  const xfoRaw = getHeader(pairs, 'x-frame-options');
  if (!html) {
    add(check('na', 'xfo', 'X-Frame-Options', 'info', '非 HTML 响应，点击劫持防护不适用。'));
  } else if (!xfoRaw && !cspFrameAncestors) {
    add(
      check(
        'fail',
        'xfo',
        '缺少点击劫持防护（X-Frame-Options / frame-ancestors）',
        'medium',
        '既未设置 X-Frame-Options，CSP 中也没有 frame-ancestors，页面可被任意站点嵌入。',
        { cwe: cwe693, remediation: HEADER_REMEDIATION.xfo },
      ),
    );
  } else if (xfoRaw) {
    const value = compact(xfoRaw, 120).toUpperCase();
    if (value === 'DENY' || value === 'SAMEORIGIN') {
      add(check('pass', 'xfo', 'X-Frame-Options', 'info', `已设置 X-Frame-Options: ${value}。`));
    } else if (value.startsWith('ALLOW-FROM')) {
      add(
        check('warn', 'xfo-allow-from', 'X-Frame-Options 使用已废弃的 ALLOW-FROM', 'low', 'ALLOW-FROM 已不被现代浏览器支持，请改用 CSP frame-ancestors。', {
          cwe: cwe693,
          remediation: HEADER_REMEDIATION.xfo,
        }),
      );
    } else {
      add(
        check('warn', 'xfo-invalid', 'X-Frame-Options 值无效', 'low', `无法识别的值：“${clip(xfoRaw, 80)}”。有效值为 DENY/SAMEORIGIN。`, {
          cwe: cwe693,
          remediation: HEADER_REMEDIATION.xfo,
        }),
      );
    }
  } else {
    add(check('pass', 'xfo', '点击劫持防护', 'info', 'CSP frame-ancestors 已提供点击劫持防护。'));
  }

  // ----- X-Content-Type-Options -------------------------------------------
  const xctoRaw = getHeader(pairs, 'x-content-type-options');
  if (!xctoRaw) {
    add(
      check('fail', 'xcto', '缺少 X-Content-Type-Options', 'low', '浏览器可能对响应做 MIME 嗅探，导致类型混淆内容被当作脚本执行。', {
        cwe: cwe693,
        remediation: HEADER_REMEDIATION.xcto,
      }),
    );
  } else if (/^\s*nosniff\s*$/i.test(xctoRaw)) {
    add(check('pass', 'xcto', 'X-Content-Type-Options', 'info', '已设置 nosniff。'));
  } else {
    add(
      check('warn', 'xcto-invalid', 'X-Content-Type-Options 值无效', 'low', `值应为 nosniff，实际为 “${clip(xctoRaw, 80)}”。`, {
        cwe: cwe693,
        remediation: HEADER_REMEDIATION.xcto,
      }),
    );
  }

  // ----- Referrer-Policy ---------------------------------------------------
  const referrerRaw = getHeader(pairs, 'referrer-policy');
  if (!referrerRaw) {
    add(
      check(
        html ? 'fail' : 'info',
        'referrer',
        '缺少 Referrer-Policy',
        html ? 'low' : 'info',
        '未限制 Referer 发送策略，敏感 URL（含 token）可能通过 Referer 泄露给第三方。',
        { cwe: cwe693, remediation: HEADER_REMEDIATION.referrer },
      ),
    );
  } else {
    const policies = referrerRaw
      .split(',')
      .map((p) => p.trim().toLowerCase())
      .filter(Boolean);
    const bad = policies.filter((p) => p === 'unsafe-url');
    if (bad.length) {
      add(
        check('warn', 'referrer-unsafe', 'Referrer-Policy 使用 unsafe-url', 'low', 'unsafe-url 会把完整 URL（含查询参数）发送给所有目标。', {
          cwe: cwe693,
          remediation: HEADER_REMEDIATION.referrer,
        }),
      );
    } else if (policies.some((p) => REFERRER_GOOD.has(p))) {
      add(check('pass', 'referrer', 'Referrer-Policy', 'info', `已设置 Referrer-Policy: ${compact(referrerRaw, 80)}。`));
    } else {
      add(
        check('warn', 'referrer-unknown', 'Referrer-Policy 值无法识别', 'info', `值 “${clip(referrerRaw, 80)}” 不在常见取值内，请确认语义。`, {
          cwe: cwe693,
          remediation: HEADER_REMEDIATION.referrer,
        }),
      );
    }
  }

  // ----- Permissions-Policy ------------------------------------------------
  const permissionsRaw = getHeader(pairs, 'permissions-policy');
  const featurePolicyRaw = getHeader(pairs, 'feature-policy');
  if (!permissionsRaw && !featurePolicyRaw) {
    add(check('info', 'permissions', '缺少 Permissions-Policy', 'info', '未显式禁用不需要的浏览器特性（camera/microphone/geolocation 等）。', {
      remediation: HEADER_REMEDIATION.permissions,
    }));
  } else if (!permissionsRaw && featurePolicyRaw) {
    add(check('warn', 'permissions-feature-policy', '仅使用已废弃的 Feature-Policy', 'info', 'Feature-Policy 已被 Permissions-Policy 取代，建议迁移。', {
      remediation: HEADER_REMEDIATION.permissions,
    }));
  } else {
    add(check('pass', 'permissions', 'Permissions-Policy', 'info', '已设置 Permissions-Policy。'));
  }

  // ----- CORS --------------------------------------------------------------
  const acao = getHeader(pairs, 'access-control-allow-origin');
  const acacRaw = getHeader(pairs, 'access-control-allow-credentials');
  const acac = String(acacRaw ?? '').trim().toLowerCase() === 'true';
  const acah = getHeader(pairs, 'access-control-allow-headers');
  if (acao != null) {
    const acaoTrim = acao.trim();
    if (acaoTrim === '*') {
      if (acac) {
        add(
          check(
            'fail',
            'cors-wildcard-credentials',
            'CORS 通配符来源 + 允许携带凭据',
            'high',
            '同时出现 Access-Control-Allow-Origin: * 与 Access-Control-Allow-Credentials: true。' +
              '浏览器会拒绝该组合的凭据响应，但配置意图即为跨域开放凭据；若实现改为反射 Origin 将直接造成越权读取。',
            { cwe: 'CWE-942', remediation: HEADER_REMEDIATION.cors },
          ),
        );
      } else {
        add(
          check(
            'info',
            'cors-wildcard-origin',
            'CORS 允许任意源（未携带凭据）',
            'info',
            'Access-Control-Allow-Origin: *：任意站点可读取该（无凭据）响应，仅对公开数据可接受。',
            { cwe: 'CWE-942', remediation: HEADER_REMEDIATION.cors },
          ),
        );
      }
    } else if (requestOrigin && acaoTrim === requestOrigin && acac) {
      add(
        check(
          'warn',
          'cors-reflect-credentials',
          'CORS 反射请求 Origin 且允许携带凭据',
          'medium',
          '响应回显了请求 Origin 并允许凭据；若未做 Origin allowlist 校验，任意站点可发起带凭据跨域读取。',
          { cwe: 'CWE-942', remediation: HEADER_REMEDIATION.cors },
        ),
      );
    } else if (acac && /authorization/i.test(String(acah ?? ''))) {
      add(
        check(
          'info',
          'cors-auth-header',
          'CORS 允许携带 Authorization 头',
          'info',
          'Access-Control-Allow-Headers 包含 Authorization；请确认允许来源经过严格 allowlist 校验。',
          { cwe: 'CWE-942', remediation: HEADER_REMEDIATION.cors },
        ),
      );
    }
  }

  // ----- Server version disclosure ----------------------------------------
  const serverRaw = getHeader(pairs, 'server');
  if (serverRaw && /\d+\.\d+/.test(serverRaw)) {
    add(
      check(
        'warn',
        'server-version-disclosure',
        'Server 头泄露版本信息',
        'info',
        `Server 头包含版本号：“${clip(serverRaw, 100)}”，便于攻击者匹配已知漏洞。`,
        { remediation: '在生产环境隐藏或泛化 Server / X-Powered-By 等指纹头。' },
      ),
    );
  }
  for (const name of ['x-powered-by', 'x-aspnet-version', 'x-generator']) {
    const value = getHeader(pairs, name);
    if (value) {
      add(
        check(
          'info',
          `disclosure-${name}`,
          `${name} 泄露技术栈信息`,
          'info',
          `响应包含 ${name}: ${clip(value, 80)}，便于攻击者识别技术栈与版本。`,
          { remediation: '移除或泛化技术栈指纹响应头。' },
        ),
      );
    }
  }

  // ----- Cache-Control on sensitive responses -----------------------------
  const sensitiveUrl =
    typeof ctx.sensitiveUrl === 'boolean'
      ? ctx.sensitiveUrl
      : parsedUrl
        ? isSensitiveUrlPath(parsedUrl)
        : false;
  if (sensitiveUrl && (html || api)) {
    const cacheRaw = getHeader(pairs, 'cache-control');
    if (!cacheRaw) {
      add(
        check(
          'warn',
          'cache-control-missing',
          '敏感响应缺少 Cache-Control',
          'low',
          'URL 具有敏感语义（登录/账户/token 等）但响应未声明 Cache-Control: no-store，可能被共享缓存或浏览器缓存留存。',
          { cwe: cwe693, remediation: HEADER_REMEDIATION.cache },
        ),
      );
    } else {
      const cc = parseCacheControl(cacheRaw);
      const noStore = cc.get('no-store') === true;
      const publicCache = cc.get('public') === true;
      if (!noStore && publicCache) {
        add(
          check(
            'warn',
            'cache-control-public',
            '敏感响应被标记为可公开缓存',
            'medium',
            `敏感 URL 的响应包含 “${clip(cacheRaw, 120)}”，public 缓存可能把该响应提供给其他用户。`,
            { cwe: cwe693, remediation: HEADER_REMEDIATION.cache },
          ),
        );
      } else if (!noStore) {
        add(
          check(
            'warn',
            'cache-control-no-store-missing',
            '敏感响应未设置 no-store',
            'low',
            `敏感 URL 的响应 Cache-Control 为 “${clip(cacheRaw, 120)}”，建议显式 no-store。`,
            { cwe: cwe693, remediation: HEADER_REMEDIATION.cache },
          ),
        );
      } else {
        add(check('pass', 'cache-control', 'Cache-Control', 'info', '敏感响应已设置 no-store。'));
      }
    }
  }

  // ----- Cookies -----------------------------------------------------------
  const cookieValues = getHeaderValues(pairs, 'set-cookie');
  const cookieFindings = [];
  const cookies = [];
  const seenCookies = new Set();
  for (const raw of cookieValues.slice(0, 100)) {
    const cookie = parseSetCookie(raw);
    if (!cookie) continue;
    const dedupeKey = `${cookie.name.toLowerCase()}|${cookie.attrs.domain ?? ''}`;
    if (seenCookies.has(dedupeKey)) continue;
    seenCookies.add(dedupeKey);
    const displayName = clip(cookie.name, 80);
    const issues = [];
    if (!cookie.attrs.secure) {
      issues.push({
        id: 'cookie-secure-missing',
        severity: 'medium',
        title: `Cookie “${displayName}” 缺少 Secure`,
        cwe: 'CWE-614',
      });
    }
    const sessionish = /(?:sess|sid|auth|token|jwt|login|remember|user|uid)/i.test(cookie.name);
    if (!cookie.attrs.httponly) {
      issues.push({
        id: 'cookie-httponly-missing',
        severity: sessionish ? 'medium' : 'low',
        title: `Cookie “${displayName}” 缺少 HttpOnly`,
        cwe: 'CWE-1004',
      });
    }
    if (!cookie.attrs.sameSite) {
      issues.push({
        id: 'cookie-samesite-missing',
        severity: 'low',
        title: `Cookie “${displayName}” 未显式设置 SameSite`,
        cwe: 'CWE-1275',
      });
    } else if (/^none$/i.test(String(cookie.attrs.sameSite)) && !cookie.attrs.secure) {
      issues.push({
        id: 'cookie-samesite-none-insecure',
        severity: 'high',
        title: `Cookie “${displayName}” SameSite=None 但缺少 Secure`,
        cwe: 'CWE-614',
      });
    }
    if (/^__Host-/i.test(cookie.name) && !(cookie.attrs.secure && cookie.attrs.path === '/' && !cookie.attrs.domain)) {
      issues.push({
        id: 'cookie-host-prefix-violation',
        severity: 'medium',
        title: `Cookie “${displayName}” 违反 __Host- 前缀约束`,
        cwe: 'CWE-614',
      });
    }
    if (/^__Secure-/i.test(cookie.name) && !cookie.attrs.secure) {
      issues.push({
        id: 'cookie-secure-prefix-violation',
        severity: 'medium',
        title: `Cookie “${displayName}” 违反 __Secure- 前缀约束`,
        cwe: 'CWE-614',
      });
    }
    cookies.push({
      name: displayName,
      secure: Boolean(cookie.attrs.secure),
      httpOnly: Boolean(cookie.attrs.httponly),
      sameSite: cookie.attrs.sameSite != null ? clip(String(cookie.attrs.sameSite), 20) : null,
      path: cookie.attrs.path != null ? clip(String(cookie.attrs.path), 120) : null,
      domain: cookie.attrs.domain != null ? clip(String(cookie.attrs.domain), 120) : null,
      issues: issues.map((i) => i.id),
    });
    for (const issue of issues) {
      cookieChecks.push({
        id: issue.id,
        title: issue.title,
        status: 'fail',
        severity: issue.severity,
        detail: `${issue.title}；Cookie 属性可由 Set-Cookie 直接观察，值已脱敏。`,
        silent: true,
      });
      cookieFindings.push(
        finding({
          title: `[${issue.id}] ${issue.title}`,
          severity: issue.severity,
          description: `${issue.title}。该缺口让 Cookie 更易被窃取/滥用；实际影响取决于 Cookie 用途与站点上下文。`,
          verification: 'observed',
          method: 'set-cookie-attribute-audit',
          cwe: issue.cwe,
          remediation: COOKIE_REMEDIATION[issue.id] || '为 Cookie 设置 Secure/HttpOnly/SameSite。',
          target: null,
          evidence: [{ title: 'Set-Cookie', excerpt: describeCookie(cookie) }],
        }),
      );
    }
  }

  // Derive findings from failed/warned header checks (cookie findings handled above).
  for (const c of checks) {
    if (c.status !== 'fail' && c.status !== 'warn') continue;
    findings.push(
      finding({
        title: `[${c.id}] ${c.title}`,
        severity: c.severity,
        description: c.detail,
        verification: 'observed',
        method: 'security-header-audit',
        cwe: c.cwe ?? null,
        remediation: c.remediation || '',
        target: null,
        evidence: [{ title: c.title, excerpt: c.detail }],
      }),
    );
  }
  findings.push(...cookieFindings);

  return {
    checks: checks.concat(cookieChecks).map((c) => ({
      id: c.id,
      title: c.title,
      status: c.status,
      severity: c.severity,
      detail: c.detail,
    })),
    findings: sortFindings(findings),
    cookies,
    headers: pairs.map(({ name, value }) => ({
      name: clip(String(name), 100),
      value: redactHeaderValue(name, value),
    })),
    https,
    html,
    url: parsedUrl ? redactUrl(parsedUrl.toString()) : ctx.url ? clip(String(ctx.url), 500) : null,
  };
}

export { HEADER_REMEDIATION, REFERRER_GOOD, severityRank };

/**
 * Parse a standalone header-set input: either a JSON object/array of headers,
 * a wrapper object {url, contentType, headers}, or raw "Name: value" lines.
 * @returns {{pairs:{name:string,value:string}[], url:string|null, contentType:string|null, origin:string|null}}
 */
export function parseHeaderSet(rawText) {
  const text = String(rawText ?? '')
    .replace(/^\uFEFF/, '')
    .trim();
  if (!text) {
    throw new Error(
      '响应头输入为空：请提供 JSON 对象（header 名→值）、[{"name","value"}] 数组，或 “Header-Name: value” 多行文本。',
    );
  }
  let url = null;
  let contentType = null;
  let origin = null;
  let headerSource = text;
  if (text.startsWith('{') || text.startsWith('[')) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      throw new Error(
        `响应头 JSON 解析失败：${error.message}。期望 {"header-name": "value"} 或 [{"name":"...","value":"..."}]；` +
          '若输入其实是原始 HTTP 响应文本，请改用 web.http_message 能力。',
      );
    }
    headerSource = parsed;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && parsed.headers != null) {
      headerSource = parsed.headers;
      if (typeof parsed.url === 'string') url = parsed.url;
      if (typeof parsed.contentType === 'string') contentType = parsed.contentType;
      else if (typeof parsed['content-type'] === 'string') contentType = parsed['content-type'];
      if (typeof parsed.origin === 'string') origin = parsed.origin;
    }
  }
  const pairs = normalizeHeaderPairs(headerSource, { source: '响应头' }).slice(0, MAX_HEADER_PAIRS);
  if (!pairs.length) {
    throw new Error('响应头输入没有解析出任何头：请至少提供一个 “Header-Name: value”。');
  }
  if (!contentType) contentType = getHeader(pairs, 'content-type');
  return { pairs, url, contentType, origin };
}

