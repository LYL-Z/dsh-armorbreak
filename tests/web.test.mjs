// ArmorBreak web domain tests — pure synthetic fixtures, real field assertions.
import test from 'node:test';
import assert from 'node:assert/strict';

import webManifest from '../lib/analyzers/web/manifest.js';
import { analyzeHar, parseHarDocument } from '../lib/analyzers/web/har.js';
import { auditHeaders, parseHeaderSet } from '../lib/analyzers/web/headers.js';
import { analyzeHttpMessage, parseHttpMessage } from '../lib/analyzers/web/httpmsg.js';
import { analyzeOpenApi, parseOpenApiDocument } from '../lib/analyzers/web/openapi.js';
import { parseYamlLite } from '../lib/analyzers/web/yaml-lite.js';

const CAPS = new Map(webManifest.capabilities.map((capability) => [capability.id, capability]));
const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function defaults(overrides = {}) {
  return {
    targetPath: null,
    buffer: null,
    text: null,
    options: {},
    limits: { maxBytes: 1024 * 1024, maxFindings: 100, maxItems: 200 },
    env: {},
    ...overrides,
  };
}

async function runCapability(id, overrides = {}) {
  const capability = CAPS.get(id);
  assert.ok(capability, `capability ${id} must exist`);
  return capability.run(defaults(overrides));
}

function assertFindingShape(finding) {
  assert.equal(typeof finding.title, 'string');
  assert.ok(finding.title.length > 0);
  assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity));
  assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(finding.verification));
  assert.ok(finding.cwe === null || /^CWE-\d+$/.test(finding.cwe));
  assert.ok(Array.isArray(finding.evidence));
}

const SECRET_TOKEN = 'S3cr3tTokenValue123';
const COOKIE_SECRET = 'SuperSecretCookieValue';

function makeHar() {
  return {
    log: {
      version: '1.2',
      creator: { name: 'armorbreak-test', version: '1.0' },
      pages: [{ id: 'page_1', title: 'https://example.com/' }],
      entries: [
        {
          pageref: 'page_1',
          request: {
            method: 'GET',
            url: `https://example.com/login?token=${SECRET_TOKEN}&q=1`,
            headers: [{ name: 'Origin', value: 'https://evil.example' }],
            queryString: [
              { name: 'token', value: SECRET_TOKEN },
              { name: 'q', value: '1' },
            ],
          },
          response: {
            status: 200,
            headers: [
              { name: 'Content-Type', value: 'text/html; charset=utf-8' },
              { name: 'Access-Control-Allow-Origin', value: '*' },
              { name: 'Access-Control-Allow-Credentials', value: 'true' },
              { name: 'Set-Cookie', value: `session=${COOKIE_SECRET}; Path=/; HttpOnly` },
              { name: 'Server', value: 'nginx/1.18.0' },
            ],
            content: { mimeType: 'text/html', size: 100 },
          },
        },
        {
          pageref: 'page_1',
          request: { method: 'GET', url: 'http://example.com/app.js', headers: [] },
          response: {
            status: 200,
            headers: [{ name: 'Content-Type', value: 'application/javascript' }],
            content: { mimeType: 'application/javascript' },
          },
        },
      ],
    },
  };
}

test('web manifest shape: 4 offline capabilities with closed JSON-Schema params', () => {
  assert.equal(webManifest.domain, 'web');
  assert.deepEqual(
    webManifest.capabilities.map((capability) => capability.id),
    ['web.har', 'web.openapi', 'web.headers', 'web.http_message'],
  );
  for (const capability of webManifest.capabilities) {
    assert.equal(capability.riskLevel, 'L0');
    assert.ok(capability.title.length > 0);
    assert.ok(capability.description.length > 20);
    assert.equal(capability.params.type, 'object');
    assert.equal(capability.params.additionalProperties, false);
    assert.equal(typeof capability.run, 'function');
  }
});

test('web.har: aggregates security findings, redacts tokens/cookies, flags mixed content', async () => {
  const document = makeHar();
  const result = await runCapability('web.har', { text: JSON.stringify(document) });

  assert.equal(result.data.format, 'HAR');
  assert.equal(result.data.summary.analyzedEntries, 2);
  assert.equal(result.data.summary.documentResponses, 1);
  assert.equal(result.data.summary.hostCount, 1);
  assert.equal(result.data.summary.byMethod.GET, 2);

  const titles = result.findings.map((finding) => finding.title);
  assert.ok(titles.some((title) => title.includes('[url-token-leak]')), 'token leak finding');
  assert.ok(titles.some((title) => title.includes('[cors-wildcard-credentials]')), 'CORS finding');
  assert.ok(titles.some((title) => title.includes('[csp]')), 'missing CSP finding');
  const mixed = result.findings.find((finding) => finding.title.includes('[mixed-content]'));
  assert.ok(mixed, 'mixed content finding');
  assert.equal(mixed.verification, 'hypothesis');

  const serialized = JSON.stringify(result.findings);
  assert.equal(serialized.includes(SECRET_TOKEN), false, 'raw URL token must not leak');
  assert.equal(serialized.includes(COOKIE_SECRET), false, 'raw cookie value must not leak');

  const cspCheck = result.data.securityHeaders.find((check) => check.id === 'csp');
  assert.ok(cspCheck && cspCheck.fail >= 1);
  const cookie = result.data.cookies.find((entry) => entry.name === 'session');
  assert.ok(cookie);
  assert.equal(cookie.secure, false);
  assert.equal(cookie.httpOnly, true);
  assert.ok(cookie.issues.includes('cookie-secure-missing'));

  assert.equal(result.data.tokenLeaks[0].param, 'token');
  assert.match(result.data.tokenLeaks[0].redactedValue, /^S3cr\*\*\*$/);
  for (let i = 1; i < result.findings.length; i += 1) {
    assert.ok(
      RANK[result.findings[i - 1].severity] >= RANK[result.findings[i].severity],
      'findings must be severity-sorted',
    );
  }
  result.findings.forEach(assertFindingShape);
});

test('web.har: malformed / empty / invalid-structure inputs raise actionable errors', async () => {
  await assert.rejects(() => runCapability('web.har', { text: '' }), /为空/);
  await assert.rejects(() => runCapability('web.har', { text: '{oops' }), /HAR 不是合法 JSON/);
  assert.throws(() => parseHarDocument(''), /HAR 输入为空/);
  await assert.rejects(() => runCapability('web.har', { text: '{"foo":1}' }), /缺少顶层 log/);
  await assert.rejects(
    () => runCapability('web.har', { text: '{"log":{"version":"1.2","entries":"nope"}}' }),
    /log\.entries 必须是数组/,
  );
  assert.throws(() => parseHarDocument('[]'), /缺少顶层 log/);
});

test('web.har: honours maxEntries/maxFindings bounds and stays deterministic', async () => {
  const text = JSON.stringify(makeHar());
  const first = await runCapability('web.har', {
    text,
    options: { maxEntries: 1 },
    limits: { maxBytes: 1024 * 1024, maxFindings: 2, maxItems: 10 },
  });
  assert.equal(first.data.summary.analyzedEntries, 1);
  assert.equal(first.data.truncated.entries, true);
  assert.ok(first.findings.length <= 2);

  const second = await runCapability('web.har', {
    text: JSON.stringify(makeHar()),
    options: { maxEntries: 2 },
    limits: { maxBytes: 1024 * 1024, maxFindings: 100, maxItems: 200 },
  });
  const third = await runCapability('web.har', {
    text: JSON.stringify(makeHar()),
    options: { maxEntries: 2 },
    limits: { maxBytes: 1024 * 1024, maxFindings: 100, maxItems: 200 },
  });
  assert.deepEqual(second.data, third.data);
  assert.deepEqual(
    second.findings.map((finding) => finding.title),
    third.findings.map((finding) => finding.title),
  );
});

const OPENAPI_YAML = `openapi: 3.0.3
info:
  title: Demo API
  version: 1.2.3
servers:
  - url: http://api.example.com/v1
    description: prod
components:
  securitySchemes:
    apiKeyAuth:
      type: apiKey
      in: query
      name: api_key
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        "200":
          description: ok
    post:
      operationId: createUser
      deprecated: true
      responses:
        "201":
          description: created
  /health:
    get:
      responses:
        "200":
          description: ok
`;

test('web.openapi: parses YAML subset and reports servers/auth/paths', async () => {
  const parsed = parseOpenApiDocument(OPENAPI_YAML);
  assert.equal(parsed.specVersion, '3.0.3');
  assert.equal(parsed.swagger2, false);

  const yamlValue = parseYamlLite('a:\n  b: 1\nlist:\n  - x\n  - y: 2\n    z: 3\nq: "hello: world"\n');
  assert.deepEqual(yamlValue, { a: { b: 1 }, list: ['x', { y: 2, z: 3 }], q: 'hello: world' });

  const result = await runCapability('web.openapi', { text: OPENAPI_YAML });
  assert.equal(result.data.specVersion, '3.0.3');
  assert.equal(result.data.servers[0].plainHttp, true);
  assert.equal(result.data.securitySchemes[0].name, 'apiKeyAuth');
  assert.equal(result.data.securitySchemes[0].type, 'apiKey');
  assert.equal(result.data.securitySchemes[0].in, 'query');
  assert.equal(result.data.stats.pathCount, 2);
  assert.equal(result.data.stats.operationCount, 3);
  assert.equal(result.data.stats.deprecatedCount, 1);

  const titles = result.findings.map((finding) => finding.title);
  assert.ok(titles.some((title) => title.includes('[server-plain-http]')));
  assert.ok(titles.some((title) => title.includes('[apikey-in-query]')));
  assert.ok(titles.some((title) => title.includes('[openapi-no-auth]')));
  assert.ok(titles.some((title) => title.includes('[openapi-deprecated]')));
  assert.equal(
    result.findings.filter((finding) => finding.title.includes('[openapi-no-auth]')).length,
    2,
    'both /users operations lack auth; /health is public',
  );
  result.findings.forEach(assertFindingShape);
});

test('web.openapi: accepts JSON specs and rejects unsupported input with actionable errors', async () => {
  const jsonSpec = JSON.stringify({
    openapi: '3.1.0',
    info: { title: 'Pets', version: '1.0.0' },
    servers: [{ url: 'https://api.example.com' }],
    components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } },
    security: [{ bearerAuth: [] }],
    paths: {
      '/pets': {
        get: {
          operationId: 'listPets',
          responses: { 200: { description: 'ok' } },
        },
      },
    },
  });
  const result = await runCapability('web.openapi', { text: jsonSpec });
  assert.equal(result.data.globalSecurity, 1);
  assert.equal(result.data.securitySchemes[0].type, 'http');
  assert.equal(result.findings.some((finding) => finding.title.includes('[server-plain-http]')), false);
  assert.equal(result.findings.some((finding) => finding.title.includes('[openapi-no-auth]')), false);

  await assert.rejects(() => runCapability('web.openapi', { text: '' }), /为空/);
  await assert.rejects(
    () => runCapability('web.openapi', { text: '{"openapi":"2.0"}' }),
    /不支持的 OpenAPI 版本/,
  );
  await assert.rejects(
    () => runCapability('web.openapi', { text: 'openapi: 3.0.3\ninfo: &meta {title: X}\n' }),
    /锚点/,
  );
  await assert.rejects(
    () => runCapability('web.openapi', { text: '[]' }),
    /根节点必须是对象/,
  );
});

const GOOD_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'content-security-policy':
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};

test('web.headers: clean header set passes, weak header set yields actionable findings', async () => {
  const clean = await runCapability('web.headers', {
    text: JSON.stringify(GOOD_HEADERS),
    options: { url: 'https://example.com/' },
  });
  assert.equal(clean.data.https, true);
  assert.equal(clean.data.documentContext, true);
  assert.equal(clean.data.statusCounts.fail, 0);
  assert.equal(clean.findings.length, 0);

  const weak = await runCapability('web.headers', {
    text: JSON.stringify({
      'content-type': 'text/html',
      'set-cookie': ['session=SuperSecretCookieValue; Path=/'],
      server: 'Apache/2.4.1',
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    }),
    options: { url: 'https://example.com/login' },
  });
  const titles = weak.findings.map((finding) => finding.title);
  for (const expected of [
    '[csp]',
    '[hsts]',
    '[xfo]',
    '[xcto]',
    '[cors-wildcard-credentials]',
    '[cookie-secure-missing]',
    '[cache-control-missing]',
  ]) {
    assert.ok(titles.some((title) => title.includes(expected)), `expected ${expected}`);
  }
  assert.ok(weak.data.statusCounts.fail >= 3);
  assert.equal(JSON.stringify(weak).includes('SuperSecretCookieValue'), false);
  assert.equal(weak.data.cookies[0].issues.includes('cookie-secure-missing'), true);
  weak.findings.forEach(assertFindingShape);

  const parsed = parseHeaderSet('Content-Type: text/html\nX-Test: yes\n');
  assert.equal(parsed.pairs.length, 2);
  assert.equal(parsed.pairs[1].name, 'X-Test');
  assert.throws(() => parseHeaderSet('Not-A-Header'), /不是合法 HTTP 头/);
  assert.throws(() => parseHeaderSet(''), /为空/);

  const audit = auditHeaders(GOOD_HEADERS, { url: 'https://example.com/' });
  assert.equal(audit.checks.find((check) => check.id === 'hsts').status, 'pass');
  assert.equal(audit.findings.length, 0);
});

test('web.headers: maxFindings bound is honoured', async () => {
  const result = await runCapability('web.headers', {
    text: JSON.stringify({
      'content-type': 'text/html',
      'set-cookie': ['a=secretA; Path=/', 'b=secretB; Path=/'],
    }),
    options: { url: 'https://example.com/login' },
    limits: { maxBytes: 1024 * 1024, maxFindings: 2, maxItems: 50 },
  });
  assert.ok(result.findings.length <= 2);
  assert.equal(result.data.truncated.findings, true);
});

test('web.http_message: parses request, redacts credentials, detects token leak + TE/CL', async () => {
  const raw =
    'POST /submit?access_token=TopSecretToken123 HTTP/1.1\r\n' +
    'Host: example.com\r\n' +
    'Authorization: Bearer topsecretbearer\r\n' +
    'Cookie: session=secretcookie\r\n' +
    'Content-Type: application/json\r\n' +
    'Transfer-Encoding: chunked\r\n' +
    'Content-Length: 999\r\n' +
    '\r\n' +
    '{"password":"hunter2"}';
  const message = parseHttpMessage(raw);
  assert.equal(message.type, 'request');
  assert.equal(message.method, 'POST');
  assert.equal(message.version, '1.1');
  assert.equal(message.headers.length, 6);

  const result = await runCapability('web.http_message', { text: raw });
  assert.equal(result.data.messageType, 'request');
  const titles = result.findings.map((finding) => finding.title);
  assert.ok(titles.some((title) => title.includes('[http-query-token]')));
  const smuggling = result.findings.find((finding) => finding.title.includes('[http-te-cl-conflict]'));
  assert.ok(smuggling);
  assert.equal(smuggling.verification, 'hypothesis');

  const serialized = JSON.stringify(result);
  for (const rawSecret of ['TopSecretToken123', 'topsecretbearer', 'secretcookie', 'hunter2']) {
    assert.equal(serialized.includes(rawSecret), false, `must not echo ${rawSecret}`);
  }
  const authHeader = result.data.headers.find((header) => header.name.toLowerCase() === 'authorization');
  assert.equal(authHeader.value, 'Bearer ••••');
  const cookieHeader = result.data.headers.find((header) => header.name.toLowerCase() === 'cookie');
  assert.equal(cookieHeader.value, 'cookie=••••');
  assert.deepEqual(result.data.body.sensitiveFields, ['password']);
  assert.equal(result.data.body.contentLength, '999');

  await assert.rejects(() => runCapability('web.http_message', { text: 'GARBAGE LINE' }), /HTTP 起始行无法识别/);
  await assert.rejects(() => runCapability('web.http_message', { text: '' }), /为空/);
});

test('web.http_message: response header audit redacts Set-Cookie values', async () => {
  const raw =
    'HTTP/1.1 200 OK\r\n' +
    'Content-Type: text/html\r\n' +
    'Set-Cookie: sid=VerySecretSession; HttpOnly\r\n' +
    'Content-Length: 2\r\n' +
    '\r\n' +
    'hi';
  const result = await runCapability('web.http_message', { text: raw });
  assert.equal(result.data.messageType, 'response');
  assert.equal(result.data.status, 200);
  assert.ok(result.findings.some((finding) => finding.title.includes('[csp]')));
  assert.equal(JSON.stringify(result).includes('VerySecretSession'), false);
  const setCookie = result.data.headers.find((header) => header.name.toLowerCase() === 'set-cookie');
  assert.ok(setCookie.value.includes('sid=••••'));
  assert.equal(result.data.body.size, 2);
  result.findings.forEach(assertFindingShape);
});

test('web helpers: analyzeHar/analyzeOpenApi/analyzeHttpMessage are deterministic', () => {
  const harDocument = parseHarDocument(JSON.stringify(makeHar()));
  const first = analyzeHar(harDocument, { maxEntries: 10, maxFindings: 50, maxItems: 50 });
  const second = analyzeHar(harDocument, { maxEntries: 10, maxFindings: 50, maxItems: 50 });
  assert.deepEqual(first.data, second.data);

  const spec = parseOpenApiDocument(OPENAPI_YAML);
  const specFirst = analyzeOpenApi(spec, { maxFindings: 50, maxItems: 50 });
  const specSecond = analyzeOpenApi(spec, { maxFindings: 50, maxItems: 50 });
  assert.deepEqual(specFirst.data, specSecond.data);

  const message = parseHttpMessage('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
  const msgFirst = analyzeHttpMessage(message, { maxFindings: 20 });
  const msgSecond = analyzeHttpMessage(message, { maxFindings: 20 });
  assert.deepEqual(msgFirst.data, msgSecond.data);
  assert.equal(msgFirst.findings.length, 0, 'clean GET request has no structural findings');
});
