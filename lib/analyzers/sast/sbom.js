// ArmorBreak SAST domain — CycloneDX 1.5 SBOM generation from dependency manifests.
//
// Deterministic by construction: components are sorted by bom-ref and the serial
// number is derived from SHA-256 of the sorted bom-refs (no randomness, no
// wall-clock fields except the caller-provided env.nowIso timestamp).

import { createHash } from 'node:crypto';
import { baseName, clip } from './common.js';
import { collectManifests, manifestKindForFile } from './deps.js';

const TOOL = Object.freeze({ vendor: 'ArmorBreak', name: 'armorbreak-sast-sbom', version: '1.0.0' });

function exactVersion(version) {
  const raw = String(version ?? '')
    .trim()
    .replace(/^[vV=]+/, '')
    .replace(/^(===?|>=|<=|~=|!=|>|<)\s*/, '');
  const match = /^(\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?)$/.exec(raw);
  return match ? match[1] : null;
}

function purlFor(ecosystem, dependency) {
  const name = String(dependency?.name ?? '').trim();
  if (!name) return null;
  const version = exactVersion(dependency.version);
  const suffix = version ? `@${version}` : '';
  if (ecosystem === 'npm') {
    const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : name;
    return `pkg:npm/${encoded}${suffix}`;
  }
  if (ecosystem === 'pip') {
    const normalized = name.toLowerCase().replace(/_/g, '-');
    return `pkg:pypi/${normalized}${suffix}`;
  }
  if (ecosystem === 'go') {
    return `pkg:golang/${name}${suffix}`;
  }
  if (ecosystem === 'maven') {
    const [group, artifact] = name.includes(':') ? name.split(':') : ['', name];
    return `pkg:maven/${group || '_'}/${artifact}${suffix}`;
  }
  return null;
}

function componentFor(ecosystem, dependency) {
  const purl = purlFor(ecosystem, dependency);
  if (!purl) return null;
  const version = exactVersion(dependency.version);
  return {
    type: 'library',
    name: String(dependency.name),
    ...(version ? { version } : {}),
    purl,
    'bom-ref': purl,
  };
}

/**
 * Build a CycloneDX 1.5 BOM object.
 * @returns {{bom:object, components:object[], ecosystemCounts:object, truncated:boolean}}
 */
export function buildSbom(manifests, opts = {}) {
  const maxComponents = Number.isFinite(opts.maxComponents)
    ? Math.max(1, Math.min(20000, Math.trunc(opts.maxComponents)))
    : 5000;
  const components = [];
  const seenRefs = new Set();
  const ecosystemCounts = new Map();
  let truncated = false;
  let firstProject = null;
  let npmProject = null;

  for (const manifest of manifests) {
    if (!manifest.parseOk) continue;
    if (manifest.ecosystem === 'npm' && manifest.name && !npmProject) {
      npmProject = { name: clip(manifest.name, 200), version: clip(manifest.version ?? '0.0.0', 80) };
    }
    if (!firstProject && manifest.name) {
      firstProject = { name: clip(manifest.name, 200), version: clip(manifest.version ?? '0.0.0', 80) };
    }
    for (const dependency of manifest.dependencies) {
      if (components.length >= maxComponents) {
        truncated = true;
        break;
      }
      const component = componentFor(manifest.ecosystem, dependency);
      if (!component) continue;
      if (seenRefs.has(component['bom-ref'])) continue;
      seenRefs.add(component['bom-ref']);
      components.push(component);
      ecosystemCounts.set(manifest.ecosystem, (ecosystemCounts.get(manifest.ecosystem) ?? 0) + 1);
    }
    if (truncated) break;
  }

  components.sort((a, b) => (a['bom-ref'] < b['bom-ref'] ? -1 : a['bom-ref'] > b['bom-ref'] ? 1 : 0));

  const canonical = components.map((c) => c['bom-ref']).join('\n');
  const digest = createHash('sha256').update(canonical).digest('hex');
  // Deterministic UUID-shaped serial (version 4 layout, content-derived).
  const serialNumber = `urn:uuid:${digest.slice(0, 8)}-${digest.slice(8, 12)}-${digest.slice(12, 16)}-${digest.slice(16, 20)}-${digest.slice(20, 32)}`;

  const projectName = opts.projectName ? clip(String(opts.projectName), 200) : npmProject?.name || firstProject?.name || 'armorbreak-sbom-input';
  const projectVersion = opts.projectVersion
    ? clip(String(opts.projectVersion), 80)
    : npmProject?.version || firstProject?.version || '0.0.0';

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      ...(opts.timestamp ? { timestamp: clip(String(opts.timestamp), 60) } : {}),
      tools: [{ vendor: TOOL.vendor, name: TOOL.name, version: TOOL.version }],
      component: { type: 'application', name: projectName, version: projectVersion },
    },
    components,
  };

  return {
    bom,
    components,
    ecosystemCounts: Object.fromEntries([...ecosystemCounts.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
    truncated,
    project: { name: projectName, version: projectVersion },
  };
}

/**
 * Parse manifests from collected sources and build an SBOM.
 * Throws an actionable error when no dependency manifest is present.
 */
export function buildSbomFromSources(sources, opts = {}) {
  const { manifests, parseErrors } = collectManifests(sources, {
    maxDepsPerManifest: opts.maxDepsPerManifest,
    maxManifests: opts.maxManifests,
  });
  if (!manifests.some((m) => m.parseOk)) {
    throw new Error(
      '未发现可解析的依赖清单：SBOM 需要 package.json / requirements.txt / go.mod / pom.xml 之一。' +
        ` 已检查 ${sources.length} 个文件` +
        (parseErrors.length ? `（其中 ${parseErrors.length} 个解析失败）` : '') +
        '。请确认 targetPath 指向项目根目录，或核心的 env.listFiles 覆盖了项目文件。',
    );
  }
  const result = buildSbom(manifests, opts);
  return { ...result, manifests, parseErrors };
}

/** True when the path looks like a dependency manifest (no content read). */
export function isManifestPath(filePath) {
  return manifestKindForFile(filePath) !== null;
}

export { baseName };
