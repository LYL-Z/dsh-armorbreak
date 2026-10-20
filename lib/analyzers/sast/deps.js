// ArmorBreak SAST domain — dependency manifest inventory + heuristic supply-chain audit.
//
// Honest scope: NO vulnerability database is queried. The analyzer reports
// inventory (name/version/spec), pinning/transport/install-script heuristics, and
// a small curated list of "version below known fix" advisories. Those advisory
// matches are labelled verification="hypothesis" with an explicit instruction to
// confirm against the upstream advisory — never "CVE confirmed".

import {
  baseName,
  clip,
  compact,
  finding,
  parentDir,
  sortFindings,
} from './common.js';

export const MANIFEST_KINDS = Object.freeze({
  npm: { label: 'npm package.json', lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json'] },
  pip: { label: 'Python requirements.txt', lockfiles: ['poetry.lock', 'Pipfile.lock', 'requirements.lock'] },
  go: { label: 'Go go.mod', lockfiles: ['go.sum'] },
  maven: { label: 'Maven pom.xml', lockfiles: ['gradle.lockfile'] },
});

export function manifestKindForFile(filePath) {
  const base = baseName(filePath).toLowerCase();
  if (base === 'package.json') return 'npm';
  if (/^requirements(?:[-_.][a-z0-9_-]+)?\.txt$/.test(base)) return 'pip';
  if (base === 'go.mod') return 'go';
  if (base === 'pom.xml') return 'maven';
  return null;
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

function parseVersion(value) {
  const clean = String(value ?? '')
    .trim()
    .replace(/^[vV=]+/, '')
    .replace(/^[~^<>]=?\s*/, '');
  const match = /^(\d+(?:\.\d+)*)(?:[-+](.+))?/.exec(clean);
  if (!match) return null;
  return {
    numbers: match[1].split('.').map((n) => Number(n)),
    pre: match[2] ? match[2].toLowerCase() : null,
  };
}

/** Numeric-aware version compare. Returns -1|0|1, or null when not comparable. */
export function compareVersions(a, b) {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return null;
  const length = Math.max(left.numbers.length, right.numbers.length);
  for (let i = 0; i < length; i += 1) {
    const x = left.numbers[i] ?? 0;
    const y = right.numbers[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  if (left.pre === right.pre) return 0;
  if (!left.pre) return 1;
  if (!right.pre) return -1;
  return left.pre < right.pre ? -1 : 1;
}

/** Classify a dependency version spec: pinned | range | unpinned | unresolved | url | none. */
export function classifyVersion(ecosystem, dependency) {
  const raw = String(dependency?.version ?? '').trim();
  if (!raw) return { kind: 'none', raw };
  if (/^(?:git\+|git:|file:|https?:\/\/|link:)/i.test(raw)) return { kind: 'url', raw };
  if (ecosystem === 'npm') {
    if (/^(?:\*|latest|next|x)$/i.test(raw) || /^>=\s*0(?:\.0)*$/i.test(raw) || /^>\s*0/i.test(raw)) {
      return { kind: 'unpinned', raw };
    }
    if (/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(raw)) return { kind: 'pinned', raw, exact: raw };
    return { kind: 'range', raw };
  }
  if (ecosystem === 'pip') {
    const specifier = dependency.specifier ?? (/^(===?|>=|<=|~=|!=|>|<)/.exec(raw)?.[1] ?? null);
    if (specifier === '==' || specifier === '===') {
      const exact = raw.replace(/^===?/, '').trim();
      if (/^\d+(?:\.\d+)*(?:[a-zA-Z0-9.+!_-]*)$/.test(exact)) return { kind: 'pinned', raw, exact };
    }
    if (!specifier) return { kind: 'unpinned', raw };
    return { kind: 'range', raw };
  }
  if (ecosystem === 'go') {
    if (/^v?\d+\.\d+\.\d+/.test(raw)) return { kind: 'pinned', raw, exact: raw };
    if (/^latest$/i.test(raw)) return { kind: 'unpinned', raw };
    return { kind: 'range', raw };
  }
  if (ecosystem === 'maven') {
    if (/\$\{/.test(raw)) return { kind: 'unresolved', raw };
    if (/^(?:LATEST|RELEASE)$/i.test(raw)) return { kind: 'unpinned', raw };
    if (/^[\[(]/.test(raw)) return { kind: 'range', raw };
    if (/^\d+(?:\.\d+)*(?:[-.][A-Za-z0-9._-]+)?$/.test(raw)) return { kind: 'pinned', raw, exact: raw };
    return { kind: 'range', raw };
  }
  return { kind: 'unknown', raw };
}

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

function parsePackageJson(text) {
  const pkg = JSON.parse(text);
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    throw new Error('package.json 根节点必须是 JSON 对象');
  }
  const dependencies = [];
  for (const scope of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const group = pkg[scope];
    if (!group || typeof group !== 'object' || Array.isArray(group)) continue;
    for (const [name, version] of Object.entries(group)) {
      dependencies.push({ name: clip(String(name), 200), version: clip(String(version ?? ''), 120), scope });
    }
  }
  return {
    name: typeof pkg.name === 'string' ? clip(pkg.name, 200) : null,
    version: typeof pkg.version === 'string' ? clip(pkg.version, 80) : null,
    dependencies,
    extras: {
      scripts: pkg.scripts && typeof pkg.scripts === 'object' ? Object.keys(pkg.scripts).sort() : [],
      installScripts: ['preinstall', 'install', 'postinstall', 'prepare'].filter(
        (s) => pkg.scripts && typeof pkg.scripts === 'object' && typeof pkg.scripts[s] === 'string',
      ),
      registry: typeof pkg.publishConfig === 'object' && pkg.publishConfig?.registry ? clip(String(pkg.publishConfig.registry), 200) : null,
    },
  };
}

function parseRequirements(text) {
  const dependencies = [];
  const indexUrls = [];
  for (const rawLine of String(text).split('\n')) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const line = trimmed.split(/\s+#/)[0].trim();
    if (/^--(?:extra-)?index-url\s+/i.test(line)) {
      indexUrls.push(clip(line.split(/\s+/)[1] ?? '', 300));
      continue;
    }
    if (/^--trusted-host\s+/i.test(line)) {
      indexUrls.push(`trusted-host ${clip(line.split(/\s+/)[1] ?? '', 200)}`);
      continue;
    }
    if (line.startsWith('-')) {
      if (/^-e\s+/.test(line) || /^-r\s+/.test(line)) {
        dependencies.push({ name: clip(line, 160), version: '', scope: 'option', specifier: null });
      }
      continue;
    }
    const match = /^([A-Za-z0-9_.\-]+)(?:\[[A-Za-z0-9_,.\-]+\])?\s*(===|==|>=|<=|~=|!=|>|<)?\s*([^\s;]+)?/.exec(line);
    if (!match) continue;
    dependencies.push({
      name: clip(match[1], 200),
      version: match[3] ? `${match[2] ?? ''}${match[3]}` : '',
      specifier: match[2] ?? null,
      scope: 'runtime',
    });
  }
  return { name: null, version: null, dependencies, extras: { indexUrls } };
}

function parseGoMod(text) {
  const dependencies = [];
  const replaces = [];
  const excludes = [];
  let name = null;
  let goVersion = null;
  let inRequireBlock = false;
  for (const rawLine of String(text).split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('//')) continue;
    if (line.startsWith('module ')) {
      name = clip(line.slice(7).trim(), 300);
      continue;
    }
    if (line.startsWith('go ')) {
      goVersion = clip(line.slice(3).trim(), 40);
      continue;
    }
    if (line.startsWith('require (')) {
      inRequireBlock = true;
      continue;
    }
    if (inRequireBlock && line === ')') {
      inRequireBlock = false;
      continue;
    }
    if (inRequireBlock || line.startsWith('require ')) {
      const body = (line.startsWith('require ') ? line.slice(8) : line).split('//')[0].trim();
      const parts = body.split(/\s+/);
      if (parts.length >= 2) {
        dependencies.push({ name: clip(parts[0], 300), version: clip(parts[1], 80), specifier: null, scope: 'require' });
      }
      continue;
    }
    if (line.startsWith('replace ')) {
      replaces.push(clip(line, 300));
      continue;
    }
    if (line.startsWith('exclude ')) excludes.push(clip(line, 300));
  }
  return {
    name,
    version: goVersion,
    dependencies,
    extras: { replaces, excludes, goVersion },
  };
}

function xmlTag(block, tagName) {
  const match = new RegExp(`<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)</${tagName}>`).exec(block);
  return match ? match[1].trim() : null;
}

function parsePomXml(text) {
  const source = String(text);
  const dependencies = [];
  const blocks = source.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];
  for (const block of blocks.slice(0, 2000)) {
    const groupId = xmlTag(block, 'groupId');
    const artifactId = xmlTag(block, 'artifactId');
    if (!artifactId) continue;
    const version = xmlTag(block, 'version');
    const scope = xmlTag(block, 'scope');
    dependencies.push({
      name: clip(`${groupId ?? ''}:${artifactId}`, 300),
      version: version ? clip(version, 120) : '',
      specifier: null,
      scope: scope ?? 'compile',
      groupId: clip(groupId ?? '', 200),
      artifactId: clip(artifactId, 200),
    });
  }
  const projectPart = source.replace(/<parent>[\s\S]*?<\/parent>/, '');
  return {
    name: xmlTag(projectPart, 'artifactId') ? clip(xmlTag(projectPart, 'artifactId'), 200) : null,
    version: xmlTag(projectPart, 'version') ? clip(xmlTag(projectPart, 'version'), 80) : null,
    dependencies,
    extras: { parentPresent: /<parent>/.test(source) },
  };
}

/** Parse one manifest source. Throws on malformed content. */
export function parseManifest(kind, text) {
  if (kind === 'npm') return parsePackageJson(text);
  if (kind === 'pip') return parseRequirements(text);
  if (kind === 'go') return parseGoMod(text);
  if (kind === 'maven') return parsePomXml(text);
  throw new Error(`不支持的清单类型 “${kind}”：支持 npm package.json / requirements.txt / go.mod / pom.xml。`);
}

/**
 * Parse every manifest among the collected sources.
 * @returns {{manifests:object[], parseErrors:object[]}}
 */
export function collectManifests(sources, opts = {}) {
  const maxDepsPerManifest = Number.isFinite(opts.maxDepsPerManifest)
    ? Math.max(1, Math.min(5000, Math.trunc(opts.maxDepsPerManifest)))
    : 500;
  const maxManifests = Number.isFinite(opts.maxManifests) ? Math.max(1, Math.trunc(opts.maxManifests)) : 50;
  const manifests = [];
  const parseErrors = [];

  for (const source of sources) {
    const kind = manifestKindForFile(source.path);
    if (!kind) continue;
    if (manifests.length + parseErrors.length >= maxManifests) break;
    const text = source.buffer.toString('utf8');
    try {
      const parsed = parseManifest(kind, text);
      const dependencies = parsed.dependencies.slice(0, maxDepsPerManifest);
      manifests.push({
        path: clip(source.path, 400),
        ecosystem: kind,
        parseOk: true,
        name: parsed.name,
        version: parsed.version,
        dependencyCount: parsed.dependencies.length,
        dependencies,
        extras: parsed.extras,
        truncatedDependencies: parsed.dependencies.length > dependencies.length,
      });
    } catch (error) {
      parseErrors.push({ path: clip(source.path, 400), ecosystem: kind, error: compact(error?.message ?? error, 300) });
      manifests.push({
        path: clip(source.path, 400),
        ecosystem: kind,
        parseOk: false,
        error: compact(error?.message ?? error, 300),
      });
    }
  }
  return { manifests, parseErrors };
}

// ---------------------------------------------------------------------------
// Curated "version below known fix" advisories (NO live vuln DB!)
// ---------------------------------------------------------------------------

export const KNOWN_RISKY = Object.freeze([
  { ecosystem: 'npm', name: 'lodash', below: '4.17.21', advisory: '原型污染等修复（CVE-2021-23337 等）', severity: 'high' },
  { ecosystem: 'npm', name: 'minimist', below: '1.2.6', advisory: 'CVE-2021-44906 原型污染', severity: 'high' },
  { ecosystem: 'npm', name: 'node-fetch', below: '2.6.7', advisory: 'CVE-2022-0235 凭据泄露', severity: 'medium' },
  { ecosystem: 'npm', name: 'axios', below: '0.21.2', advisory: 'CVE-2021-3749 SSRF/ReDoS', severity: 'medium' },
  { ecosystem: 'npm', name: 'json5', below: '2.2.2', advisory: 'CVE-2022-46175 原型污染', severity: 'high' },
  { ecosystem: 'npm', name: 'ejs', below: '3.1.7', advisory: 'CVE-2022-29078 服务端模板注入 RCE', severity: 'high' },
  { ecosystem: 'npm', name: 'express', below: '4.17.3', advisory: '多个修复（以官方 advisory 为准）', severity: 'medium' },
  { ecosystem: 'pip', name: 'pyyaml', below: '5.4', advisory: 'CVE-2020-14343 反序列化', severity: 'high' },
  { ecosystem: 'pip', name: 'jinja2', below: '3.1.3', advisory: 'CVE-2024-22195 等模板安全修复', severity: 'medium' },
  { ecosystem: 'pip', name: 'pillow', below: '9.5.0', advisory: '多个图像解析漏洞（以公告为准）', severity: 'medium' },
  { ecosystem: 'pip', name: 'requests', below: '2.31.0', advisory: 'CVE-2023-32681 代理凭据泄露', severity: 'medium' },
  { ecosystem: 'pip', name: 'django', below: '4.2.14', advisory: 'CVE-2023-46695 等（以官方公告为准）', severity: 'high' },
  { ecosystem: 'pip', name: 'cryptography', below: '39.0.1', advisory: 'CVE-2023-23931 等', severity: 'medium' },
  { ecosystem: 'go', name: 'golang.org/x/text', below: '0.3.8', advisory: 'CVE-2021-38561 越界读', severity: 'medium' },
  { ecosystem: 'go', name: 'golang.org/x/net', below: '0.7.0', advisory: 'CVE-2022-41723 拒绝服务', severity: 'medium' },
  { ecosystem: 'maven', name: 'org.apache.logging.log4j:log4j-core', below: '2.17.1', advisory: 'CVE-2021-44228 Log4Shell', severity: 'critical' },
  { ecosystem: 'maven', name: 'org.springframework:spring-core', below: '5.3.18', advisory: 'CVE-2022-22965 Spring4Shell', severity: 'high' },
  { ecosystem: 'maven', name: 'com.fasterxml.jackson.core:jackson-databind', below: '2.13.4.2', advisory: '多个反序列化 CVE', severity: 'high' },
]);

function normalizeDependencyName(dependency) {
  return String(dependency?.name ?? '').toLowerCase();
}

function findRiskyRule(ecosystem, dependency) {
  const name = normalizeDependencyName(dependency);
  return KNOWN_RISKY.find((rule) => rule.ecosystem === ecosystem && rule.name.toLowerCase() === name) ?? null;
}

/**
 * Audit parsed manifests. Returns findings + structured data.
 */
export function auditManifests(manifests, opts = {}) {
  const maxFindings = Number.isFinite(opts.maxFindings) ? Math.max(1, Math.trunc(opts.maxFindings)) : 100;
  const fileList = Array.isArray(opts.fileList) ? opts.fileList : [];
  const findings = [];
  const riskMatches = [];
  const manifestSummaries = [];
  const ecosystemCounts = new Map();
  const summary = {
    manifestCount: 0,
    dependencyCount: 0,
    unpinnedCount: 0,
    rangeCount: 0,
    riskyMatches: 0,
    parseErrors: opts.parseErrors?.length ?? 0,
    ecosystems: {},
  };

  const lockfileNameSet = new Set();
  for (const kind of Object.values(MANIFEST_KINDS)) for (const lock of kind.lockfiles) lockfileNameSet.add(lock.toLowerCase());

  for (const manifest of manifests) {
    if (!manifest.parseOk) {
      findings.push(
        finding({
          title: `[deps-manifest-unparseable] 依赖清单无法解析：${baseName(manifest.path)}`,
          severity: 'low',
          description:
            `无法解析 “${manifest.path}”（${manifest.ecosystem}）：${manifest.error}。` +
            ' 该清单的依赖未被审计，请修复格式后重跑。',
          verification: 'observed',
          method: 'dependency-manifest-parser',
          cwe: null,
          remediation: '修正清单语法（JSON 引号/逗号、XML 标签、requirements 行格式）后重新运行。',
          target: manifest.path,
          evidence: [{ title: '解析错误', excerpt: clip(manifest.error, 400) }],
        }),
      );
      continue;
    }
    summary.manifestCount += 1;
    ecosystemCounts.set(manifest.ecosystem, (ecosystemCounts.get(manifest.ecosystem) ?? 0) + 1);
    const issues = new Set();
    const unpinned = [];
    const ranged = [];
    const unresolved = [];
    const urlDeps = [];
    let manifestPinned = 0;

    for (const dependency of manifest.dependencies) {
      const info = classifyVersion(manifest.ecosystem, dependency);
      if (info.kind === 'unpinned') {
        unpinned.push(dependency.name);
        if (issues.size < 20) issues.add('unpinned');
      } else if (info.kind === 'range') {
        ranged.push(dependency.name);
      } else if (info.kind === 'unresolved') {
        unresolved.push(dependency.name);
      } else if (info.kind === 'url') {
        urlDeps.push(dependency.name);
        issues.add('direct-url');
      } else if (info.kind === 'pinned') {
        manifestPinned += 1;
        const risky = findRiskyRule(manifest.ecosystem, dependency);
        if (risky) {
          const comparison = compareVersions(info.exact, risky.below);
          if (comparison !== null && comparison < 0) {
            riskMatches.push({
              path: manifest.path,
              ecosystem: manifest.ecosystem,
              name: dependency.name,
              version: info.exact,
              below: risky.below,
              advisory: risky.advisory,
              severity: risky.severity,
            });
          }
        }
      }
    }

    if (unpinned.length) {
      findings.push(
        finding({
          title: `[deps-unpinned] ${unpinned.length} 个依赖未固定版本：${baseName(manifest.path)}`,
          severity: 'low',
          description:
            `${manifest.path} 中有 ${unpinned.length} 个依赖未固定版本（示例：${unpinned.slice(0, 5).join('、')}${unpinned.length > 5 ? ' 等' : ''}）。` +
            ' 缺少精确版本与锁文件时，构建/部署会随上游变化，难以复现且增加供应链风险。',
          verification: 'observed',
          method: 'dependency-pinning-heuristic',
          cwe: 'CWE-494',
          remediation: '固定精确版本（npm 用精确版本号；pip 用 ==；maven 避免 LATEST）并提交锁文件。',
          target: manifest.path,
          evidence: [{ title: '未固定依赖（前 5）', excerpt: clip(unpinned.slice(0, 5).join('\n'), 400) }],
        }),
      );
    }
    if (unresolved.length) {
      findings.push(
        finding({
          title: `[deps-unresolved-version] 版本号使用属性占位符：${baseName(manifest.path)}`,
          severity: 'low',
          description:
            `${manifest.path} 中 ${unresolved.length} 个依赖版本使用 \${...} 占位符（示例：${unresolved.slice(0, 5).join('、')}），静态审计无法确认实际解析版本。`,
          verification: 'observed',
          method: 'dependency-pinning-heuristic',
          cwe: 'CWE-1104',
          remediation: '使用 Maven Enforcer/依赖树固定并记录解析后的实际版本（dependencyManagement）。',
          target: manifest.path,
        }),
      );
    }
    if (urlDeps.length) {
      findings.push(
        finding({
          title: `[deps-direct-url] 依赖直接引用 URL/分支：${baseName(manifest.path)}`,
          severity: 'low',
          description: `${manifest.path} 中有 ${urlDeps.length} 个依赖直接引用 URL/git/本地路径（示例：${urlDeps.slice(0, 3).join('、')}），上游内容可变且缺少完整性校验。`,
          verification: 'observed',
          method: 'dependency-source-review',
          cwe: 'CWE-494',
          remediation: '使用带完整性哈希的锁定来源；避免直接引用可变分支或 http URL。',
          target: manifest.path,
        }),
      );
    }
    const indexUrlList = manifest.extras?.indexUrls ?? [];
    const insecureIndex = indexUrlList.filter((url) => /^http:\/\//i.test(url));
    if (insecureIndex.length) {
      findings.push(
        finding({
          title: `[deps-insecure-index] 依赖源使用明文 HTTP：${baseName(manifest.path)}`,
          severity: 'medium',
          description: `${manifest.path} 的 index-url 使用明文 HTTP（${insecureIndex.map((u) => clip(u, 100)).join(', ')}），依赖包可被中间人替换（供应链投毒）。`,
          verification: 'observed',
          method: 'dependency-transport-review',
          cwe: 'CWE-494',
          remediation: '改用 HTTPS 源并校验包哈希（--require-hashes / lockfile integrity）。',
          target: manifest.path,
        }),
      );
    }
    const installScripts = manifest.extras?.installScripts ?? [];
    if (installScripts.length) {
      findings.push(
        finding({
          title: `[deps-install-script] package.json 含安装期脚本：${installScripts.join('、')}`,
          severity: 'low',
          description:
            `${manifest.path} 定义了安装期脚本 ${installScripts.join('、')}；依赖安装/CI 时会自动执行，是供应链攻击的常用入口，需人工审计脚本内容。`,
          verification: 'observed',
          method: 'dependency-install-script-review',
          cwe: null,
          remediation: '审计安装期脚本；CI 使用 --ignore-scripts 或隔离环境执行 npm install。',
          target: manifest.path,
        }),
      );
    }

    const manifestDir = parentDir(manifest.path);
    const nearbyLockfile = fileList.some(
      (file) =>
        parentDir(file) === manifestDir &&
        lockfileNameSet.has(baseName(file).toLowerCase()),
    );
    if (!nearbyLockfile && (manifest.ecosystem === 'npm' || manifest.ecosystem === 'pip' || manifest.ecosystem === 'go')) {
      findings.push(
        finding({
          title: `[deps-no-lockfile] 未发现锁文件：${baseName(manifest.path)}`,
          severity: 'info',
          description: `在 ${manifest.path} 所在目录未发现锁文件（${MANIFEST_KINDS[manifest.ecosystem].lockfiles.join(' / ')}），依赖解析结果不可复现。`,
          verification: 'observed',
          method: 'dependency-pinning-heuristic',
          cwe: 'CWE-494',
          remediation: '提交锁文件并在 CI 中使用 npm ci / pip install -r 固定版本。',
          target: manifest.path,
        }),
      );
    }

    summary.dependencyCount += manifest.dependencyCount;
    summary.unpinnedCount += unpinned.length;
    summary.rangeCount += ranged.length;
    const lockPresent = nearbyLockfile;
    manifestSummaries.push({
      path: manifest.path,
      ecosystem: manifest.ecosystem,
      name: manifest.name,
      version: manifest.version,
      dependencyCount: manifest.dependencyCount,
      pinnedCount: manifestPinned,
      unpinnedCount: unpinned.length,
      rangeCount: ranged.length,
      lockfilePresent: lockPresent,
      issues: [...issues].sort(),
    });
  }

  for (const match of riskMatches) {
    summary.riskyMatches += 1;
    findings.push(
      finding({
        title: `[deps-known-risky] ${match.name} ${match.version} 低于已知修复版本 ${match.below}`,
        severity: match.severity,
        description:
          `${match.path} 中依赖 ${match.name} 固定为 ${match.version}，低于公开修复版本 ${match.below}（参考：${match.advisory}）。` +
          ' 该判定仅基于版本比较与内置版本表，未查询实时漏洞库；请以上游 advisory / SCA 工具结果为准后确认。',
        verification: 'hypothesis',
        method: 'curated-version-advisory-heuristic',
        cwe: 'CWE-1395',
        cvss: null,
        remediation: `升级 ${match.name} 到 ${match.below} 或更高版本，并回归验证兼容性。`,
        target: match.path,
        evidence: [{ title: '版本匹配', excerpt: `${match.name} ${match.version} < ${match.below}（${match.advisory}）` }],
      }),
    );
  }

  summary.ecosystems = Object.fromEntries([...ecosystemCounts.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)));

  const sorted = sortFindings(findings);
  const finalFindings = sorted.slice(0, maxFindings);

  // Bound structured output volume: 1200 dependency records ≈ well under the
  // 256 KiB data budget even with long names/versions.
  const maxDependencyRecords = Number.isFinite(opts.maxDependencyRecords)
    ? Math.max(1, Math.min(5000, Math.trunc(opts.maxDependencyRecords)))
    : 1200;
  let dependencyBudget = maxDependencyRecords;
  const dependencyData = [];
  let dependencyDataTruncated = false;
  for (const manifest of manifests.filter((item) => item.parseOk).slice(0, opts.maxManifests ?? 50)) {
    if (dependencyBudget <= 0) {
      dependencyDataTruncated = true;
      break;
    }
    const limit = Math.min(opts.maxDepsPerManifest ?? 500, dependencyBudget);
    const dependencies = manifest.dependencies.slice(0, limit);
    if (dependencies.length < manifest.dependencies.length) dependencyDataTruncated = true;
    dependencyBudget -= dependencies.length;
    dependencyData.push({
      path: manifest.path,
      ecosystem: manifest.ecosystem,
      dependencies,
      truncated: dependencies.length < manifest.dependencies.length || Boolean(manifest.truncatedDependencies),
    });
  }

  return {
    findings: finalFindings,
    riskMatches,
    data: {
      manifests: manifestSummaries,
      dependencies: dependencyData,
      summary,
      riskMatches: riskMatches.slice(0, 200),
      knownRiskyRuleCount: KNOWN_RISKY.length,
      truncated: {
        findings: sorted.length > finalFindings.length,
        manifests: manifests.length > (opts.maxManifests ?? 50),
        dependencies: dependencyDataTruncated,
        riskMatches: riskMatches.length > 200,
      },
    },
    evidence: [
      {
        title: '依赖清单概览',
        kind: 'dependency-inventory',
        excerpt: compact(
          manifests
            .filter((m) => m.parseOk)
            .map((m) => `${m.path} [${m.ecosystem}] deps=${m.dependencyCount}`)
            .join('\n'),
          2000,
        ),
      },
    ],
    summaryText: compact(
      `依赖审计：${summary.manifestCount} 个清单（${Object.entries(summary.ecosystems)
        .map(([k, v]) => `${k}=${v}`)
        .join(', ')}），共 ${summary.dependencyCount} 个依赖；` +
        `未固定 ${summary.unpinnedCount}、范围 ${summary.rangeCount}、已知风险版本匹配 ${summary.riskyMatches}，` +
        `清单解析错误 ${summary.parseErrors}。发现 ${finalFindings.length} 条问题。`,
      4000,
    ),
  };
}
