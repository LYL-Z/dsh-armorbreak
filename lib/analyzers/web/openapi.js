// ArmorBreak web domain — offline OpenAPI 3.x / Swagger 2.0 specification audit.
//
// The analyzer is a *contract* review: it reports what the specification
// declares (servers, auth schemes, operations, parameters, responses). It never
// sends requests and never claims a runtime vulnerability; missing-auth and
// plain-HTTP findings are specification observations, not exploit proof.

import {
  clip,
  compact,
  finding,
  redactUrl,
  severityRank,
  sortFindings,
  tryParseUrl,
} from './common.js';
import { parseYamlLite, YamlParseError } from './yaml-lite.js';

const HTTP_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
const WRITE_METHODS = new Set(['post', 'put', 'patch', 'delete']);
const PUBLIC_PATH_RE =
  /(?:^|\/)(?:health|healthz|live|ready|readiness|liveness|ping|status|metrics|docs?|openapi|swagger|public|login|signin|sign-in|register|signup|sign-up|\.well-known)(?:\/|$)/i;

/** Parse JSON or YAML text into { doc, specVersion, swagger2 }. */
export function parseOpenApiDocument(text) {
  const raw = String(text ?? '')
    .replace(/^\uFEFF/, '')
    .trim();
  if (!raw) {
    throw new Error(
      'OpenAPI 输入为空：请提供 JSON 或 YAML 格式的 OpenAPI 3.x 文档（targetPath 指向 .json/.yaml/.yml 文件，或在 input.text 中提供内容）。',
    );
  }
  let doc;
  if (raw.startsWith('{') || raw.startsWith('[')) {
    try {
      doc = JSON.parse(raw);
    } catch (error) {
      throw new Error(
        `OpenAPI JSON 解析失败：${error.message}。请确认是完整 JSON 文档（常见原因：注释、尾随逗号、BOM、被截断）；也可以改用 YAML。`,
      );
    }
  } else {
    try {
      doc = parseYamlLite(raw);
    } catch (error) {
      if (error instanceof YamlParseError) {
        throw new Error(
          `OpenAPI YAML 解析失败：${error.message}。内置 YAML 子集支持缩进映射/序列、引号标量、| 与 > 块标量、内联 JSON flow；` +
            '不支持锚点/别名/merge 键/多文档。可改用 JSON 格式的 OpenAPI 文档，或简化该构造。',
        );
      }
      throw new Error(`OpenAPI YAML 解析失败：${error?.message ?? error}`);
    }
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error('OpenAPI 文档根节点必须是对象（YAML 映射 / JSON object），当前不是。');
  }
  if (typeof doc.openapi === 'string') {
    const version = doc.openapi.trim();
    if (!/^3\.\d+(?:\.\d+)?$/.test(version)) {
      throw new Error(
        `不支持的 OpenAPI 版本 “${clip(version, 40)}”：本能力解析 OpenAPI 3.x（如 3.0.3 / 3.1.0）。请升级规范或改用其他工具。`,
      );
    }
    return { doc, specVersion: version, swagger2: false };
  }
  if (typeof doc.swagger === 'string') {
    const version = doc.swagger.trim();
    if (version !== '2.0') {
      throw new Error(
        `不支持的 Swagger 版本 “${clip(version, 40)}”：本能力只兼容 2.0；请迁移到 OpenAPI 3.x。`,
      );
    }
    return { doc, specVersion: '2.0', swagger2: true };
  }
  throw new Error(
    '未检测到 openapi/swagger 版本字段：文档根节点必须包含 “openapi: 3.x”（推荐）或 “swagger: \"2.0\"”。请确认输入确实是 OpenAPI 规范。',
  );
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * Analyze a parsed OpenAPI document.
 * opts: { maxFindings, maxItems }
 */
export function analyzeOpenApi(parsed, opts = {}) {
  const { doc, specVersion, swagger2 } = parsed;
  const maxFindings = Number.isFinite(opts.maxFindings) ? Math.max(1, Math.trunc(opts.maxFindings)) : 100;
  const maxItems = Number.isFinite(opts.maxItems) ? Math.max(1, Math.trunc(opts.maxItems)) : 200;
  const maxOperations = Math.min(maxItems * 10, 2000);

  const info = isPlainObject(doc.info) ? doc.info : {};
  const title = typeof info.title === 'string' ? clip(info.title, 200) : null;
  const apiVersion = typeof info.version === 'string' ? clip(info.version, 100) : null;
  const findings = [];

  // ----- servers -----------------------------------------------------------
  const servers = [];
  const pushServer = (urlRaw, description, variables) => {
    const parsedUrl = /^https?:\/\//i.test(urlRaw) ? tryParseUrl(urlRaw) : null;
    const scheme = parsedUrl
      ? parsedUrl.protocol.replace(':', '')
      : urlRaw.startsWith('//')
        ? 'protocol-relative'
        : 'relative';
    const entry = {
      url: redactUrl(urlRaw, 300),
      scheme,
      plainHttp: scheme === 'http',
      description: description ? clip(description, 200) : null,
      variables: asArray(variables)
        .filter((v) => v && typeof v === 'object')
        .slice(0, 20)
        .map((v) => ({ name: clip(String(v.name ?? ''), 80), hasDefault: v.default !== undefined })),
    };
    servers.push(entry);
    if (entry.plainHttp) {
      findings.push(
        finding({
          title: '[server-plain-http] 服务器 URL 使用明文 HTTP',
          severity: 'medium',
          description: `servers 中的 “${entry.url}” 使用 http:// 协议，API 流量与凭据将以明文传输。`,
          verification: 'observed',
          method: 'openapi-servers-review',
          cwe: 'CWE-319',
          remediation: '把 server URL 改为 https://，并在文档中移除明文 HTTP 入口。',
          target: entry.url,
        }),
      );
    }
    return entry;
  };

  if (asArray(doc.servers).length) {
    for (const server of asArray(doc.servers).slice(0, 50)) {
      if (!isPlainObject(server) || typeof server.url !== 'string' || !server.url.trim()) continue;
      const variables = isPlainObject(server.variables)
        ? Object.entries(server.variables).map(([name, value]) => ({ name, ...(isPlainObject(value) ? value : {}) }))
        : [];
      const entry = pushServer(
        server.url.trim(),
        typeof server.description === 'string' ? server.description : '',
        variables,
      );
      for (const variable of entry.variables) {
        if (!variable.hasDefault) {
          findings.push(
            finding({
              title: '[server-variable-no-default] 服务器变量缺少 default 值',
              severity: 'low',
              description: `servers URL "${entry.url}" 中的变量 {${variable.name}} 未声明 default，客户端无法推导实际地址。`,
              verification: 'observed',
              method: 'openapi-servers-review',
              cwe: null,
              remediation: '为 server variables 提供 default 值，或在 CI 中校验替换后的 URL。',
              target: entry.url,
            }),
          );
        }
      }
    }
  } else if (swagger2 && typeof doc.host === 'string' && doc.host.trim()) {
    const schemes = asArray(doc.schemes).length ? asArray(doc.schemes) : ['http'];
    for (const schemeRaw of schemes.slice(0, 10)) {
      const scheme = String(schemeRaw).trim().toLowerCase();
      if (scheme !== 'http' && scheme !== 'https' && scheme !== 'ws' && scheme !== 'wss') continue;
      const basePath = typeof doc.basePath === 'string' ? doc.basePath : '';
      pushServer(`${scheme}://${doc.host.trim()}${basePath}`, null, []);
    }
  }

  // ----- security schemes --------------------------------------------------
  const rawSchemes = swagger2 ? doc.securityDefinitions : isPlainObject(doc.components) ? doc.components.securitySchemes : null;
  const securitySchemes = [];
  const definedSchemeNames = new Set();
  if (isPlainObject(rawSchemes)) {
    for (const [name, scheme] of Object.entries(rawSchemes).slice(0, 100)) {
      if (!isPlainObject(scheme)) continue;
      const type = String(scheme.type ?? 'unknown');
      const entry = {
        name: clip(name, 100),
        type,
        in: typeof scheme.in === 'string' ? clip(scheme.in, 40) : null,
        scheme: typeof scheme.scheme === 'string' ? clip(scheme.scheme, 60) : null,
        bearerFormat: typeof scheme.bearerFormat === 'string' ? clip(scheme.bearerFormat, 60) : null,
        flows: [],
      };
      definedSchemeNames.add(entry.name);
      if (isPlainObject(scheme.flows)) entry.flows = Object.keys(scheme.flows).sort();
      else if (typeof scheme.flow === 'string') entry.flows = [scheme.flow];
      securitySchemes.push(entry);

      const target = `#/securitySchemes/${entry.name}`;
      if (type === 'apiKey' && entry.in === 'query') {
        findings.push(
          finding({
            title: '[apikey-in-query] API Key 通过查询参数传递',
            severity: 'low',
            description: `安全方案 “${entry.name}” 使用 apiKey in: query，密钥会出现在 URL、访问日志与 Referer 中。`,
            verification: 'observed',
            method: 'openapi-security-schemes-review',
            cwe: 'CWE-598',
            remediation: '改用 Authorization 头（apiKey in: header）或更合适的 HTTP bearer 方案。',
            target,
          }),
        );
      }
      if (type === 'http' && /^basic$/i.test(entry.scheme ?? '')) {
        if (servers.some((s) => s.plainHttp)) {
          findings.push(
            finding({
              title: '[basic-auth-plain-http] Basic 认证配合明文 HTTP 服务器',
              severity: 'medium',
              description: '规范同时声明 HTTP Basic 认证与 http:// 服务器，Base64 凭据会在明文链路中泄露。',
              verification: 'observed',
              method: 'openapi-security-schemes-review',
              cwe: 'CWE-319',
              remediation: '服务器改用 HTTPS；Basic/Bearer 凭据不得经明文信道传输。',
              target,
            }),
          );
        }
      }
      for (const flow of entry.flows) {
        if (flow === 'implicit' || flow === 'password') {
          findings.push(
            finding({
              title: `[oauth2-weak-flow] OAuth2 使用 ${flow} 流程`,
              severity: 'medium',
              description: `安全方案 “${entry.name}” 声明 ${flow} 流程：implicit 会在 URL fragment 中暴露 token，password 流程直接收集用户密码，OAuth 2.1 已废弃两者。`,
              verification: 'observed',
              method: 'openapi-security-schemes-review',
              cwe: 'CWE-522',
              remediation: '迁移到 authorization_code + PKCE（若需要机器凭证使用 client_credentials）。',
              target,
            }),
          );
        }
      }
      if (type === 'oauth2' && entry.flows.length === 0) {
        findings.push(
          finding({
            title: '[oauth2-no-flow] OAuth2 安全方案未声明流程',
            severity: 'low',
            description: `安全方案 “${entry.name}” 类型为 oauth2 但没有可用的 flows，客户端无法实现授权。`,
            verification: 'observed',
            method: 'openapi-security-schemes-review',
            cwe: null,
            remediation: '至少声明一个 OAuth2 flow（推荐 authorizationCode）。',
            target,
          }),
        );
      }
      if (type === 'openIdConnect' && typeof scheme.openIdConnectUrl !== 'string') {
        findings.push(
          finding({
            title: '[openid-connect-url-missing] OpenID Connect 缺少 openIdConnectUrl',
            severity: 'low',
            description: `安全方案 “${entry.name}” 未声明 openIdConnectUrl，客户端无法发现 OIDC 元数据。`,
            verification: 'observed',
            method: 'openapi-security-schemes-review',
            cwe: null,
            remediation: '补充 openIdConnectUrl（必须为 https）。',
            target,
          }),
        );
      }
    }
  }

  const globalSecurity = Array.isArray(doc.security) ? doc.security : null;
  if (!securitySchemes.length && globalSecurity === null && !swagger2) {
    findings.push(
      finding({
        title: '[openapi-no-security] 规范未声明任何认证方案',
        severity: 'medium',
        description:
          '文档既没有 components.securitySchemes，也没有全局 security 声明；除非服务端另有网关鉴权，否则所有接口默认无认证。',
        verification: 'observed',
        method: 'openapi-security-schemes-review',
        cwe: 'CWE-306',
        remediation: '为需要认证的接口声明 securitySchemes + security，并在实现端强制校验。',
        target: null,
      }),
    );
  }

  // ----- paths / operations ------------------------------------------------
  const paths = isPlainObject(doc.paths) ? doc.paths : {};
  const operations = [];
  const operationIds = new Map();
  let writeOperations = 0;
  let deprecatedCount = 0;
  const securityRequirements = new Map();

  const addSecurityRequirement = (requirements) => {
    for (const requirement of requirements) {
      if (!isPlainObject(requirement)) continue;
      for (const name of Object.keys(requirement)) {
        if (definedSchemeNames.size && !definedSchemeNames.has(name)) {
          securityRequirements.set(name, (securityRequirements.get(name) ?? 0) + 1);
        }
      }
    }
  };

  outer: for (const path of Object.keys(paths).sort()) {
    if (path.startsWith('x-')) continue;
    const pathItem = paths[path];
    if (!isPlainObject(pathItem)) continue;
    const pathParams = asArray(pathItem.parameters);
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!isPlainObject(operation)) continue;
      if (operations.length >= maxOperations) break outer;
      const location = `${method.toUpperCase()} ${clip(path, 300)}`;
      const operationId = typeof operation.operationId === 'string' ? clip(operation.operationId, 120) : null;
      if (operationId) {
        if (operationIds.has(operationId)) {
          findings.push(
            finding({
              title: '[openapi-duplicate-operation-id] operationId 重复',
              severity: 'low',
              description: `operationId “${operationId}” 被 ${operationIds.get(operationId)} 与 ${location} 重复使用，代码生成/SDK 会出现歧义。`,
              verification: 'observed',
              method: 'openapi-paths-review',
              cwe: null,
              remediation: '为每个 operation 提供全局唯一的 operationId。',
              target: location,
            }),
          );
        } else {
          operationIds.set(operationId, location);
        }
      }

      const opSecurity = Array.isArray(operation.security) ? operation.security : null;
      const effectiveSecurity = opSecurity !== null ? opSecurity : globalSecurity;
      if (effectiveSecurity) addSecurityRequirement(effectiveSecurity);

      const parameters = [...pathParams, ...asArray(operation.parameters)].filter(isPlainObject);
      const deprecated = operation.deprecated === true;
      if (deprecated) deprecatedCount += 1;
      const responses =
        isPlainObject(operation.responses) && Object.keys(operation.responses).length
          ? Object.keys(operation.responses)
              .filter((code) => !code.startsWith('x-'))
              .sort()
          : [];
      const requestBody = isPlainObject(operation.requestBody) ? operation.requestBody : null;
      const hasBodyParameter = swagger2 && parameters.some((p) => p.in === 'body');
      const hasRequestBody = Boolean(requestBody) || hasBodyParameter;
      if (WRITE_METHODS.has(method)) writeOperations += 1;

      const templateParams = [...path.matchAll(/\{([^}/]+)\}/g)].map((m) => m[1]);
      const declared = new Set(parameters.filter((p) => typeof p.name === 'string').map((p) => p.name));
      for (const param of templateParams) {
        if (!declared.has(param)) {
          findings.push(
            finding({
              title: '[openapi-path-param-undeclared] 路径模板参数未声明',
              severity: 'low',
              description: `${location} 的路径模板包含 {${param}}，但 operation/path 级 parameters 中没有对应声明（OpenAPI 3 要求路径参数必须声明）。`,
              verification: 'observed',
              method: 'openapi-paths-review',
              cwe: 'CWE-20',
              remediation: '在 parameters 中声明该 path 参数（required: true）及 schema。',
              target: location,
            }),
          );
        }
      }

      let parametersWithoutSchema = 0;
      for (const parameter of parameters) {
        const paramName = typeof parameter.name === 'string' ? clip(parameter.name, 80) : '(unnamed)';
        const hasSchema =
          isPlainObject(parameter.schema) ||
          (swagger2 && typeof parameter.type === 'string') ||
          (isPlainObject(parameter.content) && Object.keys(parameter.content).length > 0);
        if (!hasSchema) {
          parametersWithoutSchema += 1;
          findings.push(
            finding({
              title: '[openapi-param-no-schema] 参数缺少 schema 约束',
              severity: 'low',
              description: `${location} 的参数 “${paramName}” 没有 schema/type 声明，服务端校验契约不明确（类型、长度、枚举均无法约束）。`,
              verification: 'observed',
              method: 'openapi-parameters-review',
              cwe: 'CWE-20',
              remediation: '为每个参数补充 schema（type/format/maxLength/pattern/enum）。',
              target: location,
            }),
          );
        }
      }

      if (requestBody && !isPlainObject(requestBody.content)) {
        findings.push(
          finding({
            title: '[openapi-requestbody-no-content] requestBody 缺少 content',
            severity: 'low',
            description: `${location} 声明了 requestBody 但没有 content（媒体类型 + schema），请求体契约不可校验。`,
            verification: 'observed',
            method: 'openapi-request-body-review',
            cwe: 'CWE-20',
            remediation: '为 requestBody 补充 content（如 application/json + schema）。',
            target: location,
          }),
        );
      }

      if (!responses.length) {
        findings.push(
          finding({
            title: '[openapi-no-responses] operation 未声明响应',
            severity: 'low',
            description: `${location} 没有 responses 定义，无法生成客户端类型，也无法核对错误处理契约。`,
            verification: 'observed',
            method: 'openapi-responses-review',
            cwe: null,
            remediation: '至少声明成功响应与 4xx/5xx 错误响应。',
            target: location,
          }),
        );
      }

      if (deprecated) {
        findings.push(
          finding({
            title: '[openapi-deprecated] 已废弃的 operation',
            severity: 'info',
            description: `${location} 标记为 deprecated，仍在文档/客户端中暴露。`,
            verification: 'observed',
            method: 'openapi-paths-review',
            cwe: null,
            remediation: '规划下线并给出替代接口；保留期限内的废弃接口应限制访问。',
            target: location,
          }),
        );
      }

      const publicPath = PUBLIC_PATH_RE.test(path);
      const authRequired = effectiveSecurity === null ? null : effectiveSecurity.length > 0;
      if (authRequired === null && !publicPath) {
        findings.push(
          finding({
            title: '[openapi-no-auth] 非公开操作未声明认证要求',
            severity: 'medium',
            description:
              `${location} 既没有 operation.security，文档也没有全局 security，且路径不属于常见的公开端点。` +
              ' 若服务端未额外强制鉴权，该操作将匿名可调用（需结合实现代码/网关确认）。',
            verification: 'observed',
            method: 'openapi-auth-review',
            cwe: 'CWE-306',
            remediation: '为操作声明 security（或设置全局 security），并在实现端强制校验。',
            target: location,
          }),
        );
      } else if (authRequired === false && !publicPath) {
        findings.push(
          finding({
            title: '[openapi-explicit-no-auth] 非公开操作显式关闭认证',
            severity: 'info',
            description: `${location} 显式声明 security: []，即匿名可调用；请确认这是有意为之。`,
            verification: 'observed',
            method: 'openapi-auth-review',
            cwe: null,
            remediation: '确认该接口确实应公开；否则移除 security: [] 并声明认证要求。',
            target: location,
          }),
        );
      }

      operations.push({
        path: clip(path, 300),
        method,
        operationId,
        deprecated,
        tagCount: asArray(operation.tags).length,
        parameters: parameters.length,
        parametersWithoutSchema,
        hasRequestBody,
        responseCodes: responses,
        security: effectiveSecurity ? effectiveSecurity.length : null,
        publicPath,
      });
    }
  }

  for (const [name, count] of [...securityRequirements.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    findings.push(
      finding({
        title: '[openapi-unknown-security-scheme] operation 引用了未定义的安全方案',
        severity: 'low',
        description: `security 中引用 “${name}”（共 ${count} 处），但 components.securitySchemes/SecurityDefinitions 未定义该方案。`,
        verification: 'observed',
        method: 'openapi-security-schemes-review',
        cwe: null,
        remediation: '在安全方案集合中定义该名称，或修正 operation.security 引用。',
        target: null,
      }),
    );
  }

  if (!title || !apiVersion) {
    findings.push(
      finding({
        title: '[openapi-info-incomplete] info 元数据不完整',
        severity: 'low',
        description: `document.info 缺少 ${[!title ? 'title' : null, !apiVersion ? 'version' : null]
          .filter(Boolean)
          .join(' / ')}，影响 SDK/文档生成与版本追踪。`,
        verification: 'observed',
        method: 'openapi-metadata-review',
        cwe: null,
        remediation: '补充 info.title 与 info.version（建议同时提供 description/contact）。',
        target: null,
      }),
    );
  }
  if (!servers.length) {
    findings.push(
      finding({
        title: '[openapi-no-servers] 未声明 servers',
        severity: 'info',
        description: '文档没有 servers 声明，客户端需硬编码 base URL，且无法审计协议是否强制 HTTPS。',
        verification: 'observed',
        method: 'openapi-servers-review',
        cwe: null,
        remediation: '声明至少一个 servers URL，并优先使用 https。',
        target: null,
      }),
    );
  }

  const sorted = sortFindings(findings);
  const finalFindings = sorted.slice(0, maxFindings);
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of finalFindings) severityCounts[f.severity] += 1;

  const data = {
    format: swagger2 ? 'Swagger 2.0' : 'OpenAPI 3.x',
    specVersion,
    title,
    apiVersion,
    servers,
    securitySchemes,
    globalSecurity: globalSecurity ? globalSecurity.length : null,
    paths: operations.slice(0, maxItems),
    stats: {
      pathCount: Object.keys(paths).filter((p) => !p.startsWith('x-')).length,
      operationCount: operations.length,
      deprecatedCount,
      writeOperations,
      unauthenticatedOperations: operations.filter((op) => op.security === 0 || (op.security === null && !op.publicPath)).length,
      publicOperations: operations.filter((op) => op.publicPath).length,
      parametersWithoutSchema: operations.reduce((sum, op) => sum + op.parametersWithoutSchema, 0),
    },
    severityCounts,
    truncated: {
      operations: operations.length >= maxOperations,
      paths: operations.length > maxItems,
      findings: sorted.length > finalFindings.length,
    },
  };

  const evidence = [
    {
      title: '规范概览',
      kind: 'openapi-summary',
      excerpt: compact(
        [
          `${swagger2 ? 'Swagger' : 'OpenAPI'} ${specVersion} — ${title ?? '(no title)'} ${apiVersion ?? ''}`.trim(),
          `servers: ${servers.map((s) => s.url).join(', ') || '(none)'}`,
          `securitySchemes: ${securitySchemes.map((s) => `${s.name}(${s.type})`).join(', ') || '(none)'}`,
          `paths: ${data.stats.pathCount}；operations: ${operations.length}；deprecated: ${deprecatedCount}`,
        ].join('\n'),
        2000,
      ),
      meta: { specVersion, serverCount: servers.length, operationCount: operations.length },
    },
  ];

  const summaryText = compact(
    `${swagger2 ? 'Swagger' : 'OpenAPI'} ${specVersion} “${title ?? '(未命名)'}” ${apiVersion ?? ''}：` +
      `${data.stats.pathCount} 条路径 / ${data.stats.operationCount} 个操作 / ${securitySchemes.length} 个安全方案 / ` +
      `${servers.length} 个服务器。发现 ${finalFindings.length} 条问题：critical ${severityCounts.critical} / ` +
      `high ${severityCounts.high} / medium ${severityCounts.medium} / low ${severityCounts.low} / info ${severityCounts.info}。`,
    4000,
  );

  return {
    summary: summaryText,
    findings: finalFindings,
    evidence,
    data,
    meta: {
      format: swagger2 ? 'swagger2' : 'openapi3',
      specVersion,
      operationsAnalyzed: operations.length,
      operationsTruncated: operations.length >= maxOperations,
      findingsTruncated: sorted.length > finalFindings.length,
    },
  };
}
