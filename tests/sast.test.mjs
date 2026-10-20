// ArmorBreak SAST domain tests — synthetic project trees via a fake env.
import test from 'node:test';
import assert from 'node:assert/strict';

import sastManifest from '../lib/analyzers/sast/manifest.js';
import { compareVersions, classifyVersion } from '../lib/analyzers/sast/deps.js';
import { RULES } from '../lib/analyzers/sast/rules.js';
import { shannonEntropy } from '../lib/analyzers/sast/common.js';

const CAPS = new Map(sastManifest.capabilities.map((capability) => [capability.id, capability]));
const PROJECT = 'C:/virtual/project';
const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function makeEnv(files) {
  return {
    signal: { aborted: false },
    workspaceRoot: PROJECT,
    nowIso: '2026-10-20T00:00:00.000Z',
    log: () => {},
    listFiles: async (dir, opts) =>
      Object.keys(files)
        .filter((filePath) => filePath.startsWith(dir))
        .slice(0, opts?.maxFiles ?? 10000),
    readFile: async (filePath, maxBytes) => {
      const buffer = Buffer.isBuffer(files[filePath])
        ? files[filePath]
        : Buffer.from(files[filePath] ?? '', 'utf8');
      return typeof maxBytes === 'number' ? buffer.subarray(0, maxBytes) : buffer;
    },
  };
}

function defaults(overrides = {}) {
  return {
    targetPath: PROJECT,
    buffer: null,
    text: null,
    options: {},
    limits: { maxBytes: 1024 * 1024, maxFindings: 100, maxItems: 200 },
    env: makeEnv({}),
    ...overrides,
  };
}

async function runCapability(id, overrides = {}) {
  const capability = CAPS.get(id);
  assert.ok(capability, `capability ${id} must exist`);
  return capability.run(defaults(overrides));
}

function listTitles(result) {
  return result.findings.map((finding) => finding.title);
}

function assertFindingShape(finding) {
  assert.equal(typeof finding.title, 'string');
  assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity));
  assert.ok(['observed', 'corroborated', 'hypothesis', 'unverified'].includes(finding.verification));
  assert.ok(finding.cwe === null || /^CWE-\d+$/.test(finding.cwe));
  assert.ok(Array.isArray(finding.evidence));
  assert.equal(typeof finding.description, 'string');
}

const CODE_FILES = {
  [`${PROJECT}/src/app.js`]: [
    "const cp = require('child_process');",
    'cp.exec("ls " + req.query.dir);',
    'eval(req.body.code);',
    '',
  ].join('\n'),
  [`${PROJECT}/src/db.py`]: [
    'import pickle',
    'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
    'pickle.loads(request.data)',
    '',
  ].join('\n'),
  [`${PROJECT}/node_modules/pkg/index.js`]: 'eval(maliciousInput);\n',
  [`${PROJECT}/README.md`]: '# docs\n',
  [`${PROJECT}/asset.bin`]: Buffer.from([0, 1, 2, 3, 255]),
};

test('sast manifest shape: 8 offline capabilities with closed params schemas', () => {
  assert.equal(sastManifest.domain, 'sast');
  assert.deepEqual(
    sastManifest.capabilities.map((capability) => capability.id),
    ['sast.scan', 'sast.secrets', 'sast.deps', 'sast.sbom', 'sast.patch_suggestion', 'sast.semgrep', 'sast.trivy', 'sast.syft'],
  );
  for (const capability of sastManifest.capabilities) {
    assert.equal(capability.riskLevel, 'L0');
    assert.ok(capability.title.length > 0);
    assert.ok(capability.description.length > 20);
    assert.equal(capability.params.type, 'object');
    assert.equal(capability.params.additionalProperties, false);
    assert.equal(typeof capability.run, 'function');
  }
  assert.ok(RULES.length >= 40, 'rule set should be substantive');
  assert.ok(RULES.every((rule) => /^CWE-\d+$/.test(rule.cwe)));
  assert.ok(RULES.every((rule) => Array.isArray(rule.languages) && rule.languages.length > 0));
});

test('sast.scan: finds multi-language sinks, maps CWE, sorts and stays deterministic', async () => {
  const result = await runCapability('sast.scan', { env: makeEnv(CODE_FILES) });

  assert.equal(result.data.filesScanned, 2, 'only source files under non-excluded dirs are read');
  assert.equal(result.data.filesSkippedBinary, 0);
  const hitIds = result.data.ruleHits.map((hit) => hit.id);
  for (const ruleId of ['js-exec-dynamic', 'js-eval', 'py-sql-format', 'py-pickle']) {
    assert.ok(hitIds.includes(ruleId), `expected rule hit ${ruleId}`);
  }
  assert.equal(result.data.byLanguage.javascript, 1);
  assert.equal(result.data.byLanguage.python, 1);

  const evalFinding = result.findings.find((finding) => finding.title.includes('[js-eval]'));
  assert.ok(evalFinding);
  assert.equal(evalFinding.cwe, 'CWE-95');
  assert.equal(evalFinding.verification, 'hypothesis');
  assert.match(evalFinding.target, /src\/app\.js:3$/);
  assert.ok(evalFinding.evidence[0].excerpt.includes('eval(req.body.code)'));

  const sqlFinding = result.findings.find((finding) => finding.title.includes('[py-sql-format]'));
  assert.ok(sqlFinding);
  assert.equal(sqlFinding.cwe, 'CWE-89');
  assert.match(sqlFinding.target, /db\.py:2$/);

  result.findings.forEach(assertFindingShape);
  for (let i = 1; i < result.findings.length; i += 1) {
    assert.ok(RANK[result.findings[i - 1].severity] >= RANK[result.findings[i].severity]);
  }

  const again = await runCapability('sast.scan', { env: makeEnv(CODE_FILES) });
  assert.deepEqual(result.data, again.data);
  assert.deepEqual(listTitles(result), listTitles(again));
});

test('sast.scan: maxFiles/maxFindings bounds, excludeDirs override, binary skip', async () => {
  const bounded = await runCapability('sast.scan', {
    env: makeEnv(CODE_FILES),
    options: { maxFiles: 1 },
    limits: { maxBytes: 1024 * 1024, maxFindings: 1, maxItems: 200 },
  });
  assert.equal(bounded.data.filesScanned, 1);
  assert.equal(bounded.findings.length, 1, 'maxFindings must cap findings');
  assert.equal(bounded.data.truncated.findings, true);

  const excludedSrc = await runCapability('sast.scan', {
    env: makeEnv(CODE_FILES),
    options: { excludeDirs: ['src'] },
  });
  assert.equal(excludedSrc.data.filesScanned, 1);
  assert.match(excludedSrc.data.files[0].path, /node_modules/);

  const binaryFiles = {
    [`${PROJECT}/src/generated.js`]: Buffer.from([0x00, 0x01, 0x02, 0x65, 0x76, 0x61, 0x6c, 0x00]),
    [`${PROJECT}/src/ok.js`]: 'eval(x);\n',
  };
  const binaryResult = await runCapability('sast.scan', { env: makeEnv(binaryFiles) });
  assert.equal(binaryResult.data.filesScanned, 1);
  assert.equal(binaryResult.data.filesSkippedBinary, 1);
});

test('sast.scan: actionable errors for missing target/unknown rule/empty source tree', async () => {
  await assert.rejects(
    () => runCapability('sast.scan', { targetPath: PROJECT, env: {} }),
    /env\.listFiles|目标内容为空|未提供可分析/,
  );
  await assert.rejects(
    () => runCapability('sast.scan', { env: makeEnv(CODE_FILES), options: { rules: ['mystery-rule'] } }),
    /未知规则 id/,
  );
  await assert.rejects(
    () => runCapability('sast.scan', { env: makeEnv({ [`${PROJECT}/README.md`]: '# docs' }) }),
    /未发现可扫描的源代码文件/,
  );
  await assert.rejects(
    () => runCapability('sast.scan', {
      env: { ...makeEnv({}), listFiles: async () => [] },
    }),
    /未发现可扫描的源代码文件/,
  );
  // Single-file fallback works without env helpers.
  const single = await runCapability('sast.scan', {
    targetPath: `${PROJECT}/src/app.js`,
    buffer: Buffer.from('eval(userInput);\n', 'utf8'),
    env: {},
  });
  assert.equal(single.data.filesScanned, 1);
  assert.ok(listTitles(single).some((title) => title.includes('[js-eval]')));
});

test('sast.secrets: detects real formats, redacts values, allowlists placeholders', async () => {
  const files = {
    [`${PROJECT}/config/env.js`]: [
      "const awsKey = 'AKIAIOSFODNN7EXAMPLE';",
      "const password = 'S3cr3tP@ssw0rd!Value';",
      'const placeholder = "changeme";',
      '',
    ].join('\n'),
    [`${PROJECT}/keys/id_rsa`]: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n',
    [`${PROJECT}/README.md`]: 'Example: PASSWORD=changeme\n',
    [`${PROJECT}/node_modules/pkg/creds.js`]: "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789AB';\n",
  };
  const result = await runCapability('sast.secrets', { env: makeEnv(files) });
  assert.ok(result.data.uniqueSecrets >= 3);
  assert.ok(result.data.byType['aws-access-key'] >= 1);
  assert.ok(result.data.byType['private-key-block'] >= 1);
  assert.ok(result.data.byType['generic-credential-assignment'] >= 1);

  const aws = result.data.secrets.find((secret) => secret.type === 'aws-access-key');
  assert.equal(aws.redacted, 'AKIA***');
  assert.equal(aws.length, 20);

  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes('AKIAIOSFODNN7EXAMPLE'), false);
  assert.equal(serialized.includes('S3cr3tP@ssw0rd!Value'), false);
  assert.equal(serialized.includes('MIIEowIBAAKCAQEA'), false);
  assert.equal(serialized.includes('ghp_abcdefghijklmnopqrstuvwxyz0123456789AB'), false);
  assert.equal(result.data.secrets.some((secret) => secret.redacted.includes('chan')), false, 'placeholders allowlisted');
  assert.ok(listTitles(result).every((title) => title.startsWith('[secret:')));
  result.findings.forEach(assertFindingShape);

  const single = await runCapability('sast.secrets', {
    targetPath: `${PROJECT}/config/env.js`,
    buffer: Buffer.from(files[`${PROJECT}/config/env.js`], 'utf8'),
    env: {},
  });
  assert.ok(single.data.uniqueSecrets >= 2);
  assert.equal(JSON.stringify(single).includes('S3cr3tP@ssw0rd!Value'), false);

  await assert.rejects(
    () => runCapability('sast.secrets', { targetPath: null, env: {} }),
    /未提供可分析的目标|未提供可分析/,
  );
});

const DEP_FILES = {
  [`${PROJECT}/package.json`]: JSON.stringify({
    name: 'demo',
    version: '1.0.0',
    scripts: { postinstall: 'node scripts/install.js' },
    dependencies: { lodash: '4.17.20', axios: '*', '@scope/pkg': '1.0.0' },
    devDependencies: { minimist: '1.2.5' },
  }),
  [`${PROJECT}/requirements.txt`]: 'pyyaml==5.3\nflask>=2.0\n--index-url http://pypi.internal/simple\n',
  [`${PROJECT}/go.mod`]: 'module example.com/demo\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/text v0.3.6\n)\n',
  [`${PROJECT}/pom.xml`]:
    '<project><artifactId>demo</artifactId><version>1.0.0</version><dependencies>' +
    '<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>' +
    '</dependencies></project>',
  [`${PROJECT}/README.md`]: '# demo\n',
};

test('sast.deps: inventories manifests, heuristics labelled hypothesis, no fake CVE claims', async () => {
  assert.equal(compareVersions('4.17.20', '4.17.21'), -1);
  assert.equal(compareVersions('2.17.1', '2.17.1'), 0);
  assert.equal(classifyVersion('npm', { version: '*' }).kind, 'unpinned');
  assert.equal(classifyVersion('npm', { version: '4.17.20' }).kind, 'pinned');
  assert.equal(classifyVersion('pip', { version: '==1.2.3', specifier: '==' }).kind, 'pinned');

  const result = await runCapability('sast.deps', { env: makeEnv(DEP_FILES) });
  assert.equal(result.data.manifests.length, 4);
  assert.equal(result.data.summary.dependencyCount, 8);
  assert.equal(result.data.summary.unpinnedCount, 1, 'only axios "*" is unpinned');
  const riskyNames = result.data.riskMatches.map((match) => match.name);
  for (const expected of ['lodash', 'minimist', 'pyyaml', 'golang.org/x/text', 'org.apache.logging.log4j:log4j-core']) {
    assert.ok(riskyNames.includes(expected), `expected risky match ${expected}`);
  }
  const npmManifest = result.data.manifests.find((manifest) => manifest.path.endsWith('package.json'));
  assert.equal(npmManifest.unpinnedCount, 1);
  assert.equal(npmManifest.lockfilePresent, false);

  const riskyFinding = result.findings.find((finding) => finding.title.includes('[deps-known-risky]'));
  assert.ok(riskyFinding);
  assert.equal(riskyFinding.verification, 'hypothesis');
  assert.match(riskyFinding.description, /未查询实时漏洞库/);
  assert.equal(riskyFinding.cwe, 'CWE-1395');

  const titles = listTitles(result);
  for (const expected of ['[deps-unpinned]', '[deps-install-script]', '[deps-insecure-index]', '[deps-no-lockfile]']) {
    assert.ok(titles.some((title) => title.includes(expected)), `expected ${expected}`);
  }
  result.findings.forEach(assertFindingShape);

  await assert.rejects(
    () => runCapability('sast.deps', { env: makeEnv({ [`${PROJECT}/README.md`]: '# only docs' }) }),
    /未发现依赖清单/,
  );
});

test('sast.deps: malformed manifest is recorded instead of crashing', async () => {
  const result = await runCapability('sast.deps', {
    env: makeEnv({ [`${PROJECT}/package.json`]: '{"name": }' }),
  });
  assert.equal(result.data.parseErrors.length, 1);
  assert.equal(result.data.manifests.length, 0, 'unparseable manifest has no summary entry');
  assert.ok(listTitles(result).some((title) => title.includes('[deps-manifest-unparseable]')));
  assert.match(result.data.parseErrors[0].error, /JSON|Unexpected|token/i);
});

test('sast.sbom: valid deterministic CycloneDX 1.5 with purls and artifacts', async () => {
  const result = await runCapability('sast.sbom', { env: makeEnv(DEP_FILES) });
  assert.equal(result.data.bomFormat, 'CycloneDX');
  assert.equal(result.data.specVersion, '1.5');
  assert.equal(result.data.componentCount, 8);
  assert.equal(result.data.project.name, 'demo');
  assert.equal(result.data.project.version, '1.0.0');
  assert.equal(result.artifacts.length, 1);
  assert.equal(result.artifacts[0].name, 'bom.cdx.json');
  assert.equal(result.artifacts[0].contentType, 'application/json');

  const bom = JSON.parse(result.artifacts[0].content);
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.5');
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.equal(bom.components.length, 8);
  for (const component of bom.components) {
    assert.equal(component.type, 'library');
    assert.match(component.purl, /^pkg:/);
    assert.equal(component['bom-ref'], component.purl);
  }
  const scoped = bom.components.find((component) => component.name === '@scope/pkg');
  assert.equal(scoped.purl, 'pkg:npm/%40scope/pkg@1.0.0');
  const maven = bom.components.find((component) => component.purl.startsWith('pkg:maven/'));
  assert.ok(maven.purl.includes('org.apache.logging.log4j/log4j-core@2.14.1'));

  const again = await runCapability('sast.sbom', { env: makeEnv(DEP_FILES) });
  assert.equal(result.data.serialNumber, again.data.serialNumber);
  assert.deepEqual(JSON.parse(result.artifacts[0].content), JSON.parse(again.artifacts[0].content));

  await assert.rejects(
    () => runCapability('sast.sbom', { env: makeEnv({ [`${PROJECT}/README.md`]: '# docs' }) }),
    /未发现依赖清单/,
  );
});

test('sast.patch_suggestion: builds illustrative diff + regression test, never applies', async () => {
  const finding = {
    title: '[js-exec-dynamic] child_process.exec 使用动态/拼接命令（命令注入）',
    severity: 'high',
    description: 'dynamic exec sink',
    verification: 'hypothesis',
    method: 'line-regex-source-analysis',
    cwe: 'CWE-78',
    cvss: null,
    remediation: '使用 execFile 参数数组',
    target: `${PROJECT}/src/app.js:3`,
    evidence: [{ title: 'app.js:3', excerpt: 'cp.exec("ls " + req.query.dir);' }],
  };
  const result = await runCapability('sast.patch_suggestion', { text: JSON.stringify(finding), env: {} });
  assert.equal(result.data.cwe, 'CWE-78');
  assert.equal(result.data.language, 'javascript');
  assert.equal(result.data.line, 3);
  assert.equal(result.data.illustrative, false);
  assert.match(result.data.diff, /^--- a\/C:\/virtual\/project\/src\/app\.js$/m);
  assert.match(result.data.diff, /^\+\+\+ b\//m);
  assert.match(result.data.diff, /^@@ -3,1 \+3,1 @@$/m);
  assert.match(result.data.diff, /^-cp\.exec/m);
  assert.match(result.data.regressionTest, /node:test/);
  assert.equal(result.data.applyPolicy, 'manual-only');
  assert.deepEqual(result.artifacts.map((artifact) => artifact.name), ['suggested-patch.diff', 'regression.test.mjs']);
  assert.equal(result.artifacts[0].content, result.data.diff);
  assert.equal(result.findings.length, 0, 'suggestion does not fabricate findings');

  const withoutEvidence = await runCapability('sast.patch_suggestion', {
    text: JSON.stringify({ title: '[py-eval] eval', cwe: 'CWE-95', target: 'app.py:7', evidence: [] }),
    env: {},
  });
  assert.equal(withoutEvidence.data.illustrative, true);
  assert.match(withoutEvidence.data.diff, /未携带源码/);
  assert.equal(withoutEvidence.data.cwe, 'CWE-95');

  const viaOptions = await runCapability('sast.patch_suggestion', {
    buffer: null,
    options: { finding: { title: '[x] t', cwe: 'CWE-89', target: 'db.py:9' } },
    env: {},
  });
  assert.equal(viaOptions.data.cwe, 'CWE-89');
  assert.match(viaOptions.data.regressionTest, /pytest/);

  await assert.rejects(
    () => runCapability('sast.patch_suggestion', { text: '', env: {} }),
    /未提供 finding/,
  );
  await assert.rejects(
    () => runCapability('sast.patch_suggestion', { text: '{bad json', env: {} }),
    /不是合法 JSON/,
  );
});

test('sast helpers: entropy is bounded and deterministic', () => {
  assert.equal(shannonEntropy(''), 0);
  assert.ok(shannonEntropy('aaaaaaaa') < shannonEntropy('abcdefgh'));
  assert.ok(shannonEntropy('abcdefgh') <= 3.0001);
  assert.ok(shannonEntropy(Buffer.from([0, 1, 2, 3])) <= 2.0001);
});

test('sast.scan excludePaths removes rule/fixture noise from the file set', async () => {
  const files = {
    [`${PROJECT}/lib/analyzers/sast/rules.js`]: "export const RULES = [{ title: 'eval(' }];\nconst ruleProbe = eval(input)\n",
    [`${PROJECT}/tests/fixture.js`]: 'const fixtureProbe = eval(input)\n',
    [`${PROJECT}/src/app.js`]: 'export function run(userInput) { return eval(userInput) }\n',
  };
  const unfiltered = await runCapability('sast.scan', { env: makeEnv(files) });
  const allTargets = unfiltered.findings.map((finding) => finding.target ?? '');
  assert.ok(allTargets.some((target) => target.includes('rules.js')), 'baseline scan must see the rules file');
  assert.ok(allTargets.some((target) => target.includes('tests/fixture.js')), 'baseline scan must see the fixture');

  const filtered = await runCapability('sast.scan', {
    env: makeEnv(files),
    options: { excludePaths: ['lib/analyzers/sast/rules.js', 'tests/'] },
  });
  const filteredTargets = filtered.findings.map((finding) => finding.target ?? '');
  assert.equal(filteredTargets.some((target) => target.includes('rules.js')), false, 'excluded rule file must not be scanned');
  assert.equal(filteredTargets.some((target) => target.includes('tests/fixture.js')), false, 'excluded test fixture must not be scanned');
  assert.ok(filteredTargets.some((target) => target.includes('src/app.js')), 'real source file must still be scanned');
});
