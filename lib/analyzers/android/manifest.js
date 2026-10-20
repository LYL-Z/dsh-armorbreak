// ArmorBreak - android 域能力清单（离线 APK/DEX/签名分析）
// 契约见 docs/CONTRACT.md：run(input) -> { summary, findings?, evidence?, data, meta? }
import {
  parseZip,
  readEntryData,
  findEntry,
  crc32,
  METHOD_STORE,
  METHOD_DEFLATE,
} from './zip.js';
import {
  parseAxml,
  findElements,
  attr,
  attrString,
  attrBool,
  attrInt,
  TYPE_STRING,
} from './axml.js';
import { parseDex } from './dex.js';
import { analyzeSigning } from './signature.js';
import {
  optionsOf,
  requireBuffer,
  limitsOf,
  limitOf,
  sanitizeText,
  clip,
  humanBytes,
  hexOf,
  makeResult,
  checkAbort,
  looksLikeXml,
} from './util.js';

const ZIP_MAGIC_LOCAL = 0x04034b50;
const ZIP_MAGIC_EOCD = 0x06054b50;
const DEX_MAGIC = Buffer.from('dex\n', 'latin1');

// ---------------------------------------------------------------------------
// 输入/容器辅助
// ---------------------------------------------------------------------------

function isZipBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4) return false;
  const sig = buffer.readUInt32LE(0);
  return sig === ZIP_MAGIC_LOCAL || sig === ZIP_MAGIC_EOCD;
}

function isDexBuffer(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 8 && buffer.subarray(0, 4).equals(DEX_MAGIC);
}

/** 读取 ZIP 容器（受 maxEntries 控制）。 */
function openZip(input, options) {
  const buffer = requireBuffer(input, 'android');
  const limits = limitsOf(input);
  const maxEntries = limitOf(options.maxEntries, Math.min(limits.maxItems * 5, 20000), 1, 200000);
  const zip = parseZip(buffer, { maxEntries, maxBytes: limits.maxBytes });
  return { buffer, zip, limits };
}

/** 提取 AndroidManifest.xml 并解析为统一元素树。 */
function loadManifestTree(buffer, zip, options, limits) {
  const entry = findEntry(zip, 'AndroidManifest.xml');
  if (!entry) {
    throw new Error(
      'APK 中缺少 AndroidManifest.xml：无法解析包名、权限与组件。' +
        '请确认目标为完整 APK（可用 `unzip -l app.apk` 检查）；如果是拆分 APK，AndroidManifest 位于 base.apk。',
    );
  }
  const maxManifestBytes = Math.min(limits.maxBytes, 16 * 1024 * 1024);
  const extracted = extractWithCrc(buffer, entry, maxManifestBytes);
  const warnings = [];
  const manifestBuffer = extracted.data;
  const textFallback = options.textManifestFallback !== false && looksLikeXml(manifestBuffer);
  let tree;
  let format;
  let axmlStats = null;
  if (textFallback) {
    format = 'text-xml';
    tree = parseTextXml(manifestBuffer.toString('utf8'), limits);
  } else {
    format = 'binary-axml';
    const parsed = parseAxml(manifestBuffer, {
      maxElements: Math.min(limits.maxItems * 20, 5000),
      maxStrings: limits.maxStrings,
    });
    tree = parsed.root;
    axmlStats = {
      stringCount: parsed.stringCount,
      elementCount: parsed.elementCount,
      namespaceCount: parsed.namespaceCount,
      resourceMapSize: parsed.resourceMapSize,
      utf8: parsed.utf8,
      truncated: parsed.truncated,
    };
    warnings.push(...parsed.warnings);
    if (!tree) throw new Error('AndroidManifest.xml AXML 解析后没有根元素，文件损坏。');
  }
  if (!extracted.crcOk) {
    warnings.push(`AndroidManifest.xml CRC32 校验不匹配（期望 ${entry.crc32.toString(16)}，实际 ${extracted.actualCrc32.toString(16)}），文件可能被篡改或损坏。`);
  }
  return { tree, format, axmlStats, warnings, entry, size: manifestBuffer.length };
}

function extractWithCrc(buffer, entry, maxBytes) {
  const data = readEntryData(buffer, entry, { maxBytes });
  const actualCrc32 = crc32(data);
  return { data, crcOk: actualCrc32 === (entry.crc32 >>> 0), actualCrc32 };
}

/** 极简文本 XML 解析（用于非 AXML 的 AndroidManifest.xml 回退；有界、无实体展开攻击面）。 */
export function parseTextXml(text, limits) {
  const maxElements = Math.min(limits.maxItems * 20, 20000);
  const elements = [];
  const rootHolder = { children: [] };
  const stack = [rootHolder];
  const tagRe = /<([^<>]{1,4000})>/g;
  let match;
  let tagCount = 0;
  while ((match = tagRe.exec(text)) !== null) {
    if (++tagCount > maxElements * 3) break;
    const raw = match[1].trim();
    if (raw.startsWith('!--') || raw.startsWith('![') || raw.startsWith('?') || raw.startsWith('!')) continue;
    if (raw.startsWith('/')) {
      if (stack.length > 1) stack.pop();
      continue;
    }
    const selfClosing = raw.endsWith('/');
    const body = selfClosing ? raw.slice(0, -1) : raw;
    const nameMatch = /^([:\w.-]+)/.exec(body);
    if (!nameMatch) continue;
    const fullName = nameMatch[1];
    const localName = fullName.includes(':') ? fullName.split(':').pop() : fullName;
    const attributes = [];
    const attrRe = /([:\w.-]+)\s*=\s*"([^"]*)"/g;
    let am;
    while ((am = attrRe.exec(body)) !== null) {
      const attrFull = am[1];
      const ns = attrFull.startsWith('android:') ? 'http://schemas.android.com/apk/res/android' : null;
      const local = attrFull.includes(':') ? attrFull.split(':').pop() : attrFull;
      const value = decodeXmlEntities(am[2]);
      attributes.push({
        ns,
        name: local,
        rawValue: value,
        raw: value,
        type: TYPE_STRING,
        data: 0,
        value,
        kind: 'string',
        resourceId: null,
      });
    }
    const node = { type: 'element', name: localName, ns: null, attributes, children: [], lineNumber: 0 };
    const parent = stack[stack.length - 1];
    parent.children.push(node);
    if (elements.length < maxElements) elements.push(node);
    if (!selfClosing) {
      if (stack.length > 256) break;
      stack.push(node);
    }
  }
  // 由扁平栈结构恢复：rootHolder.children 的第一个元素即根
  const root = rootHolder.children.find((c) => c.type === 'element') || null;
  return root;
}

function decodeXmlEntities(value) {
  return value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => safeCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => safeCodePoint(parseInt(d, 10)))
    .replace(/&amp;/g, '&');
}

function safeCodePoint(n) {
  if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) return '';
  try {
    return String.fromCodePoint(n);
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Manifest 模型提取
// ---------------------------------------------------------------------------

function childElements(node) {
  return (node && node.children ? node.children : []).filter((c) => c && c.type === 'element');
}

function elementByName(root, name) {
  return findElements(root, (n) => n.name === name);
}

function intOrNullAttr(node, name) {
  const a = attr(node, name);
  if (!a) return null;
  if (typeof a.value === 'number') return a.value | 0;
  if (typeof a.data === 'number' && a.type === 0x10) return a.data | 0;
  if (typeof a.value === 'string' && /^-?\d+$/.test(a.value)) return parseInt(a.value, 10);
  if (typeof a.raw === 'string' && /^-?\d+$/.test(a.raw)) return parseInt(a.raw, 10);
  return null;
}

function intentFilterModel(node) {
  const actions = [];
  const categories = [];
  const data = [];
  for (const child of childElements(node)) {
    if (child.name === 'action') {
      const n = attrString(child, 'name');
      if (n) actions.push(n);
    } else if (child.name === 'category') {
      const n = attrString(child, 'name');
      if (n) categories.push(n);
    } else if (child.name === 'data') {
      const d = {};
      for (const key of ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'pathAdvancedPattern', 'mimeType', 'ssp', 'sspPrefix', 'sspPattern']) {
        const v = attrString(child, key);
        if (v !== null) d[key] = v;
      }
      if (Object.keys(d).length > 0) data.push(d);
    }
  }
  return {
    actions,
    categories,
    data,
    priority: intOrNullAttr(node, 'priority'),
    implicit: actions.length > 0 && (!categories.includes('android.intent.category.LAUNCHER') || actions[0] !== 'android.intent.action.MAIN'),
  };
}

function componentModel(kind, node, targetSdk, includeIntentFilters, limits) {
  const name = attrString(node, 'name');
  const exportedRaw = attrBool(node, 'exported');
  const enabled = attrBool(node, 'enabled');
  const filters = childElements(node).filter((c) => c.name === 'intent-filter');
  const hasIntentFilter = filters.length > 0;
  let exportedEffective;
  let exportDefaultReason = null;
  if (exportedRaw !== null) {
    exportedEffective = exportedRaw;
  } else if (kind === 'provider') {
    exportedEffective = targetSdk === null || targetSdk >= 17 ? false : true;
    exportDefaultReason = targetSdk === null || targetSdk >= 17 ? 'provider 默认 exported=false（targetSdk>=17 或未声明）' : 'provider 默认 exported=true（targetSdk<17）';
  } else {
    exportedEffective = hasIntentFilter;
    exportDefaultReason = hasIntentFilter ? '未显式声明 exported，但存在 intent-filter（旧平台默认导出）' : '未显式声明 exported，且无 intent-filter，默认不导出';
  }
  const model = {
    kind,
    name,
    exported: exportedEffective,
    exportedExplicit: exportedRaw,
    exportDefaultReason,
    enabled,
    permission: attrString(node, 'permission'),
    process: attrString(node, 'process'),
    taskAffinity: attrString(node, 'taskAffinity'),
    directBootAware: attrBool(node, 'directBootAware'),
    hasIntentFilter,
    intentFilterCount: filters.length,
    launchable: filters.some(
      (f) =>
        childElements(f).some((c) => c.name === 'action' && attrString(c, 'name') === 'android.intent.action.MAIN') &&
        childElements(f).some((c) => c.name === 'category' && attrString(c, 'name') === 'android.intent.category.LAUNCHER'),
    ),
    intentFilters: includeIntentFilters
      ? filters.slice(0, Math.min(limits.maxItems, 10)).map(intentFilterModel)
      : [],
  };
  if (kind === 'activity-alias') model.targetActivity = attrString(node, 'targetActivity');
  if (kind === 'provider') {
    model.authorities = attrString(node, 'authorities');
    model.grantUriPermissions = attrBool(node, 'grantUriPermissions');
    model.readPermission = attrString(node, 'readPermission');
    model.writePermission = attrString(node, 'writePermission');
    model.exportedExplicitPermission = model.readPermission || model.writePermission || model.permission;
  }
  if (kind === 'service') {
    model.foregroundServiceType = attrString(node, 'foregroundServiceType');
  }
  return model;
}

/**
 * 从 AXML/文本元素树提取结构化 manifest 模型。
 * @param {object} root
 * @param {{maxItems:number, includeIntentFilters:boolean}} opts
 */
export function extractManifestModel(root, opts) {
  const limits = { maxItems: opts.maxItems ?? 200 };
  const includeIntentFilters = opts.includeIntentFilters !== false;
  if (!root || root.name !== 'manifest') {
    throw new Error(
      `AndroidManifest.xml 根元素不是 <manifest>（实际为 <${root ? root.name : 'null'}>），不是有效的 Android 清单。`,
    );
  }
  const manifest = root;
  const usesSdk = childElements(manifest).find((c) => c.name === 'uses-sdk');
  const application = childElements(manifest).find((c) => c.name === 'application');
  const minSdk = usesSdk ? intOrNullAttr(usesSdk, 'minSdkVersion') : null;
  const targetSdk = usesSdk ? intOrNullAttr(usesSdk, 'targetSdkVersion') : null;
  const maxSdk = usesSdk ? intOrNullAttr(usesSdk, 'maxSdkVersion') : null;

  const permissions = [];
  const customPermissions = [];
  for (const node of childElements(manifest)) {
    if (node.name === 'uses-permission' || node.name === 'uses-permission-sdk-23' || node.name === 'uses-permission-sdk-m') {
      const name = attrString(node, 'name');
      if (name) permissions.push({ name, maxSdkVersion: intOrNullAttr(node, 'maxSdkVersion') });
    } else if (node.name === 'permission') {
      const name = attrString(node, 'name');
      if (name) {
        customPermissions.push({
          name,
          protectionLevel: attrString(node, 'protectionLevel'),
          permissionGroup: attrString(node, 'permissionGroup'),
          label: attrString(node, 'label'),
        });
      }
    }
  }

  const componentsByKind = { activity: [], 'activity-alias': [], service: [], receiver: [], provider: [] };
  if (application) {
    for (const node of childElements(application)) {
      if (node.name in componentsByKind) {
        componentsByKind[node.name].push(componentModel(node.name, node, targetSdk, includeIntentFilters, limits));
      }
    }
  }
  // activity-alias 与 activity 合并展示，但保留 kind
  const activities = [...componentsByKind.activity, ...componentsByKind['activity-alias']].slice(0, limits.maxItems);
  const services = componentsByKind.service.slice(0, limits.maxItems);
  const receivers = componentsByKind.receiver.slice(0, limits.maxItems);
  const providers = componentsByKind.provider.slice(0, limits.maxItems);
  const allComponents = [...activities, ...services, ...receivers, ...providers];

  const applicationModel = application
    ? {
        label: attrString(application, 'label'),
        icon: attrString(application, 'icon'),
        debuggable: attrBool(application, 'debuggable'),
        allowBackup: attrBool(application, 'allowBackup'),
        usesCleartextTraffic: attrBool(application, 'usesCleartextTraffic'),
        networkSecurityConfig: attrString(application, 'networkSecurityConfig'),
        testOnly: attrBool(application, 'testOnly'),
        extractNativeLibs: attrBool(application, 'extractNativeLibs'),
        requestLegacyExternalStorage: attrBool(application, 'requestLegacyExternalStorage'),
        allowClearUserData: attrBool(application, 'allowClearUserData'),
        usesNonSdkApi: attrBool(application, 'usesNonSdkApi'),
        fullBackupContent: attrBool(application, 'fullBackupContent') ?? attrString(application, 'fullBackupContent'),
        dataExtractionRules: attrString(application, 'dataExtractionRules'),
        backupAgent: attrString(application, 'backupAgent'),
        process: attrString(application, 'process'),
        theme: attrString(application, 'theme'),
        hasBackupAgent: !!attrString(application, 'backupAgent'),
      }
    : null;

  const features = [];
  for (const node of childElements(manifest).filter((c) => c.name === 'uses-feature')) {
    const name = attrString(node, 'name') || attrString(node, 'glEsVersion');
    if (name) features.push({ name, required: attrBool(node, 'required') ?? true, glEsVersion: attrString(node, 'glEsVersion') });
  }

  const metaData = [];
  if (application) {
    for (const node of childElements(application).filter((c) => c.name === 'meta-data')) {
      const name = attrString(node, 'name');
      if (!name) continue;
      metaData.push({
        name,
        value: attrString(node, 'value'),
        resource: attrString(node, 'resource'),
      });
      if (metaData.length >= limits.maxItems) break;
    }
  }

  const queries = [];
  for (const q of childElements(manifest).filter((c) => c.name === 'queries')) {
    for (const child of childElements(q)) {
      if (child.name === 'package') {
        const name = attrString(child, 'name');
        if (name) queries.push({ type: 'package', name });
      } else if (child.name === 'intent') {
        queries.push({ type: 'intent', actions: childElements(child).filter((c) => c.name === 'action').map((c) => attrString(c, 'name')).filter(Boolean) });
      }
      if (queries.length >= limits.maxItems) break;
    }
  }

  // 汇总统计
  const exportedComponents = allComponents.filter((c) => c.exported === true && c.enabled !== false);
  const exportedWithoutPermission = exportedComponents.filter(
    (c) => !c.permission && !(c.kind === 'provider' && (c.readPermission || c.writePermission)),
  );
  const deepLinks = [];
  const launches = [];
  for (const comp of allComponents) {
    if (comp.launchable) launches.push(comp.name);
    for (const filter of comp.intentFilters) {
      const isView = filter.actions.includes('android.intent.action.VIEW');
      for (const d of filter.data) {
        if (isView && (d.scheme || d.host)) {
          deepLinks.push({
            component: comp.name,
            scheme: d.scheme ?? null,
            host: d.host ?? null,
            path: d.path ?? d.pathPrefix ?? d.pathPattern ?? null,
            browsable: filter.categories.includes('android.intent.category.BROWSABLE'),
          });
        }
      }
    }
  }

  const stats = {
    componentCount: allComponents.length,
    activityCount: activities.length,
    serviceCount: services.length,
    receiverCount: receivers.length,
    providerCount: providers.length,
    exportedCount: exportedComponents.length,
    exportedWithoutPermissionCount: exportedWithoutPermission.length,
    intentFilterCount: allComponents.reduce((n, c) => n + c.intentFilterCount, 0),
    permissionCount: permissions.length,
    customPermissionCount: customPermissions.length,
    featureCount: features.length,
    metaDataCount: metaData.length,
    deepLinkCount: deepLinks.length,
  };

  return {
    package: attrString(manifest, 'package'),
    versionName: attrString(manifest, 'versionName'),
    versionCode: intOrNullAttr(manifest, 'versionCode'),
    versionCodeMajor: intOrNullAttr(manifest, 'versionCodeMajor'),
    sharedUserId: attrString(manifest, 'sharedUserId'),
    installLocation: attrString(manifest, 'installLocation'),
    compileSdkVersion: attrString(manifest, 'compileSdkVersion'),
    compileSdkVersionCodename: attrString(manifest, 'compileSdkVersionCodename'),
    platformBuildVersionCode: attrString(manifest, 'platformBuildVersionCode'),
    platformBuildVersionName: attrString(manifest, 'platformBuildVersionName'),
    minSdkVersion: minSdk,
    targetSdkVersion: targetSdk,
    maxSdkVersion: maxSdk,
    application: applicationModel,
    permissions: permissions.slice(0, limits.maxItems),
    customPermissions: customPermissions.slice(0, limits.maxItems),
    features: features.slice(0, limits.maxItems),
    metaData,
    queries: queries.slice(0, limits.maxItems),
    components: { activities, services, receivers, providers },
    exportedComponents: exportedComponents.map((c) => ({ kind: c.kind, name: c.name, permission: c.permission ?? null })),
    exportedWithoutPermission: exportedWithoutPermission.map((c) => ({ kind: c.kind, name: c.name })),
    deepLinks: deepLinks.slice(0, limits.maxItems),
    launches: launches.slice(0, limits.maxItems),
    stats,
    warnings: [],
  };
}

// ---------------------------------------------------------------------------
// APK 结构模型
// ---------------------------------------------------------------------------

function classifyEntry(entry) {
  const name = entry.name;
  if (/^classes\d*\.dex$/i.test(name)) return 'dex';
  if (name === 'resources.arsc') return 'resource-table';
  if (name === 'AndroidManifest.xml') return 'manifest';
  if (/^lib\//.test(name)) return 'native-lib';
  if (/^assets\//.test(name)) return 'asset';
  if (/^META-INF\//.test(name)) return 'meta-inf';
  if (/^res\//.test(name)) return 'resource';
  if (/^kotlin\//.test(name) || /^okhttp3\//.test(name)) return 'third-party-code';
  return 'other';
}

/** 收集 APK 结构（zip 级，不解压全部条目）。 */
export function analyzeZipStructure(buffer, zip, options, limits) {
  const maxEntries = limitOf(options.maxEntries, limits.maxItems, 1, 200000);
  const includeEntries = options.includeEntries === true;
  const dexFiles = [];
  const abis = new Set();
  const signatureFiles = [];
  const suspiciousNames = [];
  const unsupported = [];
  const duplicates = new Map();
  const byClass = new Map();
  const extCounts = new Map();
  let assetsCount = 0;
  let assetsBytes = 0;
  let totalCompressed = 0;
  let totalUncompressed = 0;
  let encryptedEntries = 0;
  let hasResourcesArsc = false;
  let resourcesArscSize = 0;

  for (const entry of zip.entries) {
    totalCompressed += entry.compressedSize;
    totalUncompressed += entry.uncompressedSize;
    byClass.set(classifyEntry(entry), (byClass.get(classifyEntry(entry)) || 0) + 1);
    if (entry.encrypted) encryptedEntries++;
    if (entry.method !== METHOD_STORE && entry.method !== METHOD_DEFLATE) {
      if (unsupported.length < 20) unsupported.push({ name: entry.name, method: entry.method, methodName: entry.methodName });
    }
    duplicates.set(entry.name, (duplicates.get(entry.name) || 0) + 1);
    const ext = entry.name.includes('.') ? entry.name.slice(entry.name.lastIndexOf('.') + 1).toLowerCase() : '(none)';
    extCounts.set(ext, (extCounts.get(ext) || 0) + 1);
    if (/^classes\d*\.dex$/i.test(entry.name)) dexFiles.push({ name: sanitizeText(entry.name, 200), uncompressedSize: entry.uncompressedSize, compressedSize: entry.compressedSize, method: entry.method });
    if (entry.name === 'resources.arsc') {
      hasResourcesArsc = true;
      resourcesArscSize = entry.uncompressedSize;
    }
    if (/^lib\/[^/]+\//.test(entry.name)) abis.add(sanitizeText(entry.name.split('/')[1], 64));
    if (/^assets\//.test(entry.name)) {
      assetsCount++;
      assetsBytes += entry.uncompressedSize;
    }
    if (/^META-INF\//.test(entry.name)) signatureFiles.push(sanitizeText(entry.name, 200));
    if (
      entry.name.includes('..') ||
      entry.name.startsWith('/') ||
      entry.name.includes('\\') ||
      entry.name.includes('\u0000')
    ) {
      if (suspiciousNames.length < 20) suspiciousNames.push(sanitizeText(entry.name, 200));
    }
  }
  const duplicateNames = [...duplicates.entries()]
    .filter(([, n]) => n > 1)
    .map(([name, count]) => ({ name: sanitizeText(name, 200), count }));
  const topLevelOf = (name) => (name.includes('/') ? `${name.split('/')[0]}/` : '(root)');
  const rawTopLevels = [...new Set(zip.entries.map((e) => topLevelOf(e.name)))].sort();
  const topLevelCounts = new Map();
  for (const entry of zip.entries) {
    const top = topLevelOf(entry.name);
    topLevelCounts.set(top, (topLevelCounts.get(top) || 0) + 1);
  }
  const topLevel = rawTopLevels.map((top) => ({ name: sanitizeText(top, 120), count: topLevelCounts.get(top) }));

  const entryList = includeEntries
    ? {
        ...clip(
          zip.entries.map((e) => ({
            name: sanitizeText(e.name, 400),
            method: e.method,
            methodName: e.methodName,
            compressedSize: e.compressedSize,
            uncompressedSize: e.uncompressedSize,
            encrypted: e.encrypted,
            dataDescriptor: e.dataDescriptor,
            class: classifyEntry(e),
          })),
          maxEntries,
        ),
      }
    : null;

  return {
    isApk: dexFiles.length > 0 || !!findEntry(zip, 'AndroidManifest.xml'),
    hasAndroidManifest: !!findEntry(zip, 'AndroidManifest.xml'),
    entryCount: zip.entries.length,
    declaredEntryCount: zip.declaredEntryCount,
    totalCompressedSize: totalCompressed,
    totalUncompressedSize: totalUncompressed,
    zip64: zip.zip64,
    comment: sanitizeText(zip.comment, 200),
    dexFiles,
    abis: [...abis].sort(),
    hasResourcesArsc,
    resourcesArscSize,
    assets: { count: assetsCount, uncompressedSize: assetsBytes },
    metaInf: {
      entryCount: byClass.get('meta-inf') || 0,
      signatureFiles: signatureFiles.filter((n) => /\.(RSA|DSA|EC)$/i.test(n)),
      hasManifestMf: signatureFiles.includes('META-INF/MANIFEST.MF'),
    },
    encryptedEntryCount: encryptedEntries,
    unsupportedCompression: unsupported.map((item) => ({ ...item, name: sanitizeText(item.name, 200) })),
    duplicateNames: duplicateNames.slice(0, 20),
    duplicateNameCount: duplicateNames.length,
    suspiciousNames,
    classesByType: [...byClass.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([type, count]) => ({ type, count })),
    topLevel,
    extensionCounts: [...extCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 15)
      .map(([ext, count]) => ({ ext: sanitizeText(ext, 40), count })),
    entries: entryList ? entryList.items : undefined,
    entriesTruncated: entryList ? entryList.truncated || zip.declaredEntryCount > zip.entries.length || zip.truncated : false,
  };
}

function summarizeStructure(structure) {
  const parts = [
    structure.isApk ? 'APK' : 'ZIP（非 APK：缺少 AndroidManifest.xml/classes.dex）',
    `${structure.entryCount} 个条目`,
    `解压 ${humanBytes(structure.totalUncompressedSize)} / 压缩 ${humanBytes(structure.totalCompressedSize)}`,
  ];
  if (structure.dexFiles.length > 0) parts.push(`DEX ${structure.dexFiles.length} 个（${structure.dexFiles.map((d) => d.name).join(', ')}）`);
  if (structure.abis.length > 0) parts.push(`ABI ${structure.abis.join('/')}`);
  if (structure.hasResourcesArsc) parts.push(`resources.arsc ${humanBytes(structure.resourcesArscSize)}`);
  if (structure.metaInf.signatureFiles.length > 0) parts.push(`v1 签名文件 ${structure.metaInf.signatureFiles.length} 个`);
  if (structure.assets.count > 0) parts.push(`assets ${structure.assets.count} 个`);
  if (structure.encryptedEntryCount > 0) parts.push(`加密条目 ${structure.encryptedEntryCount} 个`);
  if (structure.duplicateNameCount > 0) parts.push(`重名条目 ${structure.duplicateNameCount} 个`);
  if (structure.suspiciousNames.length > 0) parts.push(`可疑路径 ${structure.suspiciousNames.length} 个`);
  return parts.join('；');
}

// ---------------------------------------------------------------------------
// Findings 推导
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const DANGEROUS_PERMISSIONS = new Set([
  'android.permission.CAMERA',
  'android.permission.RECORD_AUDIO',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.READ_SMS',
  'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_CALL_LOG',
  'android.permission.CALL_PHONE',
  'android.permission.READ_PHONE_STATE',
  'android.permission.READ_PHONE_NUMBERS',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.MANAGE_EXTERNAL_STORAGE',
  'android.permission.BODY_SENSORS',
  'android.permission.ACTIVITY_RECOGNITION',
  'android.permission.BLUETOOTH_SCAN',
  'android.permission.BLUETOOTH_CONNECT',
  'android.permission.POST_NOTIFICATIONS',
  'android.permission.READ_MEDIA_IMAGES',
  'android.permission.READ_MEDIA_VIDEO',
  'android.permission.READ_MEDIA_AUDIO',
  'android.permission.GET_ACCOUNTS',
  'android.permission.READ_CALENDAR',
  'android.permission.WRITE_CALENDAR',
]);

const SPECIAL_PERMISSIONS = new Set([
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.PACKAGE_USAGE_STATS',
  'android.permission.MANAGE_EXTERNAL_STORAGE',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.BIND_DEVICE_ADMIN',
  'android.permission.WRITE_SETTINGS',
  'android.permission.READ_LOGS',
  'android.permission.DUMP',
  'android.permission.READ_FRAME_BUFFER',
]);

function finding({ title, severity, description, verification, method, cwe = null, remediation, target = null, evidence = [] }) {
  return {
    title: sanitizeText(title, 160),
    severity,
    description: sanitizeText(description, 2000),
    verification,
    method,
    cwe,
    cvss: null,
    remediation: sanitizeText(remediation, 600),
    target: target ? sanitizeText(target, 300) : null,
    evidence: evidence.slice(0, 6).map((e) => ({
      title: sanitizeText(e.title || '证据', 120),
      excerpt: sanitizeText(e.excerpt || '', 2000),
      ...(e.meta && typeof e.meta === 'object' ? { meta: e.meta } : {}),
    })),
  };
}

function componentTargetPath(model) {
  return model.name || '(未命名组件)';
}

/**
 * 根据 manifest 模型、APK 结构、签名推导 findings。
 * verification 语义：observed=直接读取到的配置；corroborated=多来源一致；hypothesis=启发式推断。
 */
export function deriveFindings({ model, structure, signing, manifestError }) {
  const findings = [];
  const app = model?.application || null;

  if (manifestError) {
    findings.push(
      finding({
        title: 'AndroidManifest.xml 无法解析，组件与权限风险未知',
        severity: 'medium',
        description: `清单解析失败：${manifestError}。这意味着导出组件、调试开关、明文流量等风险无法通过清单确认，后续结论缺失关键输入。`,
        verification: 'observed',
        method: 'AXML/文本清单解析失败',
        remediation: '确认 APK 完整、清单未被加固/加密；可尝试 `apktool d` 或 `aapt2 dump xmltree --file AndroidManifest.xml app.apk` 后重新分析。',
        evidence: [{ title: '解析错误', excerpt: sanitizeText(manifestError, 2000) }],
      }),
    );
  }

  if (model && app) {
    if (app.debuggable === true) {
      findings.push(
        finding({
          title: '发布包可调试（android:debuggable="true"）',
          severity: 'high',
          description:
            '清单声明 debuggable=true，允许通过 adb/jdwp 附加调试进程，可能读取内存、调用内部方法、绕过部分运行时校验。若非测试包，属于发布配置错误。',
          verification: 'observed',
          method: 'AXML application 元素 android:debuggable 属性',
          cwe: 'CWE-489',
          remediation: '在 release 构建中移除 android:debuggable 或设置 android:debuggable="false"，并确认 CI 产物未混入 debug 清单。',
          target: 'AndroidManifest.xml#application',
          evidence: [{ title: '清单属性', excerpt: '<application android:debuggable="true">' }],
        }),
      );
    }
    if (app.allowBackup === true) {
      findings.push(
        finding({
          title: '允许应用数据备份（android:allowBackup="true"）',
          severity: 'low',
          description:
            'allowBackup=true 时，在未设置备份规则的情况下用户数据可通过 adb backup/云备份导出，可能包含 token、缓存或数据库内容。需结合 fullBackupContent/dataExtractionRules 判断。',
          verification: 'observed',
          method: 'AXML application 元素 android:allowBackup 属性',
          cwe: 'CWE-200',
          remediation: '设置 android:allowBackup="false"，或提供 fullBackupContent/dataExtractionRules 显式排除敏感文件。',
          target: 'AndroidManifest.xml#application',
          evidence: [{ title: '清单属性', excerpt: '<application android:allowBackup="true">' }],
        }),
      );
    }
    if (app.testOnly === true) {
      findings.push(
        finding({
          title: '测试专用包（android:testOnly="true"）',
          severity: 'low',
          description: 'testOnly=true 的 APK 不能通过常规安装渠道上架/安装（只能 adb install -t），说明这是测试构建，不应作为生产基线。',
          verification: 'observed',
          method: 'AXML application 元素 android:testOnly 属性',
          remediation: '使用正式 release 签名与构建流程重新出包。',
          target: 'AndroidManifest.xml#application',
          evidence: [{ title: '清单属性', excerpt: '<application android:testOnly="true">' }],
        }),
      );
    }

    const cleartextExplicit = app.usesCleartextTraffic;
    const targetSdk = model.targetSdkVersion;
    if (cleartextExplicit === true) {
      findings.push(
        finding({
          title: '显式允许明文（HTTP）流量',
          severity: 'medium',
          description:
            'android:usesCleartextTraffic="true" 明确允许 HTTP 等明文传输，登录凭据、token 与业务数据可能被同网段攻击者嗅探/劫持。',
          verification: 'observed',
          method: 'AXML application 元素 android:usesCleartextTraffic 属性',
          cwe: 'CWE-319',
          remediation:
            '移除 usesCleartextTraffic 或设为 false；如确有 HTTP 兼容需求，使用 network_security_config 仅对特定域放行，并尽快迁移 HTTPS。',
          target: 'AndroidManifest.xml#application',
          evidence: [{ title: '清单属性', excerpt: '<application android:usesCleartextTraffic="true">' }],
        }),
      );
    } else if (cleartextExplicit === null && (targetSdk === null || targetSdk < 28) && !app.networkSecurityConfig) {
      findings.push(
        finding({
          title: 'targetSdk<28 且未限制明文流量（推断）',
          severity: 'low',
          description:
            `targetSdkVersion=${targetSdk ?? '未声明'}，且未设置 usesCleartextTraffic/networkSecurityConfig；按平台默认策略明文 HTTP 未被禁止。这是基于平台默认值的推断，需结合动态流量确认。`,
          verification: 'hypothesis',
          method: 'targetSdkVersion 与网络安全配置默认值推断',
          cwe: 'CWE-319',
          remediation: '将 targetSdkVersion 提升到 28+，或显式配置 network_security_config 禁止 cleartext。',
          target: 'AndroidManifest.xml#uses-sdk',
          evidence: [{ title: 'uses-sdk', excerpt: `targetSdkVersion=${targetSdk ?? '（未声明）'}；usesCleartextTraffic 未声明` }],
        }),
      );
    }

    const exportedServices = model.components.services.filter((c) => c.exported && c.enabled !== false);
    const exportedReceivers = model.components.receivers.filter((c) => c.exported && c.enabled !== false);
    const exportedProviders = model.components.providers.filter((c) => c.exported && c.enabled !== false);
    const noPermission = (list) => list.filter((c) => !c.permission);
    const riskyReceivers = noPermission(exportedReceivers);
    const riskyServices = noPermission(exportedServices);
    const riskyProviders = noPermission(exportedProviders);
    if (riskyProviders.length > 0) {
      const names = riskyProviders.map((c) => c.name || '(未命名)');
      findings.push(
        finding({
          title: `导出的 ContentProvider 未设权限（${riskyProviders.length} 个）`,
          severity: 'medium',
          description:
            `以下 ContentProvider 可被其他应用访问且未声明 android:permission：${names.join(', ')}。` +
            '若其读写 URI 无内部校验，可能造成数据泄露或篡改（需结合 provider 实现确认实际影响）。',
          verification: 'observed',
          method: 'AXML application/*/provider exported 与 permission 属性',
          cwe: 'CWE-926',
          remediation: '为 provider 设置 android:permission（signature 级），或显式 android:exported="false"；检查 URI 权限与输入校验。',
          target: names.join(', '),
          evidence: names.slice(0, 4).map((n) => ({ title: '导出 provider', excerpt: `<provider android:name="${n}" android:exported="true">（无 permission）` })),
        }),
      );
    }
    if (riskyReceivers.length > 0 || riskyServices.length > 0) {
      const names = [...riskyReceivers, ...riskyServices].map((c) => `${c.kind}:${c.name || '(未命名)'}`);
      findings.push(
        finding({
          title: `导出的 service/receiver 未设权限（${names.length} 个）`,
          severity: 'low',
          description:
            `以下组件 exported=true 且未声明 android:permission：${names.join(', ')}。` +
            '其它应用可向其发送 Intent；若处理逻辑缺少校验，可能存在越权触发风险（需人工复核 onStartCommand/onReceive 实现）。',
          verification: 'observed',
          method: 'AXML application/*/service|receiver exported 与 permission 属性',
          cwe: 'CWE-926',
          remediation: '对无需外部访问的组件设置 android:exported="false"；确需导出时设置 signature 级 permission 并校验调用方。',
          target: names.join(', '),
          evidence: names.slice(0, 4).map((n) => ({ title: '导出组件', excerpt: n })),
        }),
      );
    }
    const exportedActivitiesWithoutPermission = model.components.activities.filter(
      (c) => c.exported && c.enabled !== false && !c.permission && !c.launchable,
    );
    if (exportedActivitiesWithoutPermission.length > 0) {
      const names = exportedActivitiesWithoutPermission.map((c) => c.name || '(未命名)');
      findings.push(
        finding({
          title: `非启动器 Activity 被导出（${names.length} 个）`,
          severity: 'info',
          description:
            `以下 Activity 可被其它应用直接启动且未声明权限：${names.join(', ')}。` +
            '如果承载敏感页面（设置、支付回调、WebView），可能被恶意应用拉起并接受外部参数。',
          verification: 'observed',
          method: 'AXML activity exported 与 intent-filter 分析',
          cwe: 'CWE-926',
          remediation: '对内部页面设置 android:exported="false"；确需导出的入口校验调用方与参数。',
          target: names.join(', '),
          evidence: names.slice(0, 4).map((n) => ({ title: '导出 Activity', excerpt: n })),
        }),
      );
    }

    const permissionNames = new Set(model.permissions.map((p) => p.name));
    const dangerous = [...permissionNames].filter((p) => DANGEROUS_PERMISSIONS.has(p));
    if (dangerous.length > 0) {
      findings.push(
        finding({
          title: `申请 ${dangerous.length} 项运行时危险权限`,
          severity: 'info',
          description: `清单申请了危险权限：${dangerous.join(', ')}。权限本身合法，仅提示攻击面与合规审查重点；需结合实际功能判断是否过度申请。`,
          verification: 'observed',
          method: 'AXML uses-permission 与 Android 危险权限列表比对',
          remediation: '按最小权限原则裁剪；对敏感权限做运行时说明与降级处理。',
          target: 'AndroidManifest.xml#permissions',
          evidence: [{ title: '危险权限', excerpt: dangerous.join('\n') }],
        }),
      );
    }
    const special = [...permissionNames].filter((p) => SPECIAL_PERMISSIONS.has(p));
    if (special.length > 0) {
      findings.push(
        finding({
          title: `申请 ${special.length} 项特殊/高影响权限`,
          severity: 'low',
          description: `清单申请了特殊权限：${special.join(', ')}。这些权限通常需要用户在系统设置中单独授权，且能力较强（悬浮窗、安装包、无障碍、设备管理等）。`,
          verification: 'observed',
          method: 'AXML uses-permission 与特殊权限列表比对',
          remediation: '确认业务必要性与用户告知；审核对应代码路径的输入校验与权限滥用风险。',
          target: 'AndroidManifest.xml#permissions',
          evidence: [{ title: '特殊权限', excerpt: special.join('\n') }],
        }),
      );
    }
    const runtimePermissions = model.permissions
      .filter((p) => p.maxSdkVersion !== null && p.maxSdkVersion < (model.targetSdkVersion ?? 0))
      .map((p) => p.name);
    if (runtimePermissions.length > 0) {
      findings.push(
        finding({
          title: '存在 maxSdkVersion 限制的权限声明',
          severity: 'info',
          description: `以下权限通过 maxSdkVersion 限制在新系统上不生效：${runtimePermissions.join(', ')}。在更高版本设备上相关能力可能由替代机制接管，需核对兼容性。`,
          verification: 'observed',
          method: 'AXML uses-permission maxSdkVersion 分析',
          remediation: '核对 targetSdk 升级后的权限模型差异（如存储权限拆分）。',
          target: 'AndroidManifest.xml#permissions',
          evidence: [{ title: 'maxSdkVersion 权限', excerpt: runtimePermissions.join('\n') }],
        }),
      );
    }
    if (model.sharedUserId) {
      findings.push(
        finding({
          title: `使用共享 UID（sharedUserId=${model.sharedUserId}）`,
          severity: 'low',
          description:
            'sharedUserId 让多个 APK 共享同一 Linux UID 与数据目录，签名为同一密钥的应用可互相访问数据；一旦同 UID 包被替换，影响面扩大。',
          verification: 'observed',
          method: 'AXML manifest sharedUserId 属性',
          cwe: 'CWE-269',
          remediation: '新应用避免使用 sharedUserId；如必须使用，严格保护签名密钥并审计同 UID 应用。',
          target: 'AndroidManifest.xml#manifest',
          evidence: [{ title: '清单属性', excerpt: `sharedUserId="${model.sharedUserId}"` }],
        }),
      );
    }
    if (model.stats.deepLinkCount > 0) {
      const browsable = model.deepLinks.filter((d) => d.browsable);
      findings.push(
        finding({
          title: `声明 ${model.stats.deepLinkCount} 条 deep link 路由`,
          severity: browsable.length > 0 ? 'low' : 'info',
          description:
            `清单含 ${model.stats.deepLinkCount} 条 VIEW/data 路由（其中 ${browsable.length} 条带 BROWSABLE 可被浏览器/外部应用打开）。` +
            '自定义 scheme 存在被其它应用抢注劫持的风险；需要验证参数校验与 intent 重定向逻辑。',
          verification: 'observed',
          method: 'AXML intent-filter action/category/data 分析',
          cwe: 'CWE-939',
          remediation: '优先使用 Android App Links（autoVerify + https host）；对传入 URI 做严格校验，避免直接用于 WebView 加载或内部跳转。',
          target: 'AndroidManifest.xml#intent-filters',
          evidence: model.deepLinks.slice(0, 5).map((d) => ({
            title: 'deep link',
            excerpt: `${d.scheme ?? ''}://${d.host ?? ''}${d.path ?? ''} -> ${d.component ?? '(未命名)'}`,
          })),
        }),
      );
    }
  }

  if (structure) {
    if (structure.duplicateNameCount > 0) {
      findings.push(
        finding({
          title: `ZIP 内存在 ${structure.duplicateNameCount} 组重名条目`,
          severity: 'low',
          description:
            '中央目录中出现重复文件名，常见于签名替换/重打包工具或畸形 APK；不同解析器可能读取不同副本（Zip 混淆），影响签名校验一致性。',
          verification: 'observed',
          method: 'ZIP 中央目录文件名重复检测',
          remediation: '用 apksigner verify 检查签名完整性，并重新构建 APK 消除重复条目。',
          target: structure.duplicateNames.slice(0, 5).map((d) => d.name).join(', '),
          evidence: [{ title: '重复条目', excerpt: structure.duplicateNames.slice(0, 5).map((d) => `${d.name} x${d.count}`).join('\n') }],
        }),
      );
    }
    if (structure.suspiciousNames.length > 0) {
      findings.push(
        finding({
          title: 'ZIP 条目存在可疑路径（穿越/绝对路径/反斜杠）',
          severity: 'medium',
          description: `发现 ${structure.suspiciousNames.length} 个可疑条目名，可能在解包时造成路径穿越或解析器差异：${structure.suspiciousNames.slice(0, 5).join(', ')}`,
          verification: 'observed',
          method: 'ZIP 条目名路径安全检查',
          cwe: 'CWE-22',
          remediation: '不要用有漏洞的解包器处理该 APK；确认来源并在隔离环境分析。',
          target: 'APK#entries',
          evidence: [{ title: '可疑条目名', excerpt: structure.suspiciousNames.join('\n') }],
        }),
      );
    }
    if (structure.encryptedEntryCount > 0) {
      findings.push(
        finding({
          title: `ZIP 含 ${structure.encryptedEntryCount} 个加密条目`,
          severity: 'info',
          description: '标准 APK 不应包含 ZIP 传统加密条目；这可能是加固/壳或非标准打包产物，静态解析能力受限。',
          verification: 'observed',
          method: 'ZIP flag bit0 检测',
          remediation: '如为加固包，需在授权范围内使用对应脱壳/动态方案；否则重新打包为明文条目。',
          target: 'APK#entries',
          evidence: [{ title: '条目数', excerpt: `encryptedEntryCount=${structure.encryptedEntryCount}` }],
        }),
      );
    }
    if (structure.unsupportedCompression.length > 0) {
      findings.push(
        finding({
          title: '存在不支持的 ZIP 压缩方法',
          severity: 'info',
          description: `以下条目使用非 store/deflate 压缩，离线解析器无法读取：${structure.unsupportedCompression.map((e) => `${e.name}(${e.methodName})`).slice(0, 5).join(', ')}。`,
          verification: 'observed',
          method: 'ZIP 中央目录压缩方法字段',
          remediation: '用支持该算法的解包工具提取后单独分析。',
          target: 'APK#entries',
        }),
      );
    }
  }

  if (signing) {
    if (!signing.hasV1 && !signing.hasV2 && !signing.hasV3) {
      findings.push(
        finding({
          title: '未检测到 APK 签名（v1/v2/v3）',
          severity: 'medium',
          description:
            'APK 中未发现 META-INF v1 签名文件或 v2/v3 APK Signing Block。可能未签名、签名被剥离或仅使用 v4（.idsig 在 APK 外）。未签名/被重签名 APK 无法保证来源与完整性。',
          verification: 'observed',
          method: 'APK Signing Block magic + META-INF/*.RSA|DSA|EC 检测',
          cwe: 'CWE-345',
          remediation: '使用 apksigner verify --print-certs 校验；从官方渠道获取签名一致的 APK。',
          target: 'APK#signing',
          evidence: [{ title: '签名检测', excerpt: 'v1=false, v2=false, v3=false' }],
        }),
      );
    }
    if (signing.hasV1 && !signing.hasV2 && !signing.hasV3) {
      findings.push(
        finding({
          title: '仅使用 v1（JAR）签名',
          severity: 'low',
          description:
            '仅检测到 v1 签名：v1 只校验 ZIP 条目摘要，无法覆盖 ZIP 结构本身；Android 7.0+ 的系统安装器优先使用 v2/v3，v1-only 包更易被篡改或重打包。',
          verification: 'observed',
          method: 'APK Signing Block 与 META-INF 签名文件检测',
          cwe: 'CWE-345',
          remediation: '使用 apksigner 以 --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true 重新签名发布。',
          target: 'APK#signing',
          evidence: [{ title: '签名方案', excerpt: 'v1=true, v2=false, v3=false' }],
        }),
      );
    }
    if (signing.debugCertHint) {
      const details = signing.debugCertDetails || [];
      findings.push(
        finding({
          title: '使用 Android Debug 证书签名',
          severity: 'medium',
          description:
            '签名证书主体/签发者包含 "Android Debug" 字样，通常意味着该 APK 由 debug keystore 签名（开发构建）。debug 证书私钥不在受控密钥库中，任何人都能签出同证书的应用，无法作为可信来源凭据。' +
            (details.length > 0 ? ` 命中证书 SHA-256：${details.map((d) => d.sha256).join(', ')}。` : ''),
          verification: 'observed',
          method: 'v1/v2/v3 证书 subject/issuer 字符串匹配 "Android Debug"',
          cwe: 'CWE-489',
          remediation: '发布包必须使用受控 release keystore 签名；将 debug 证书从发布流程中排除。',
          target: 'APK#signing',
          evidence: details.slice(0, 3).map((d) => ({ title: '调试证书', excerpt: `${d.scheme} SHA-256=${d.sha256}` })),
        }),
      );
    }
    if (signing.certificateCount === 0 && (signing.hasV1 || signing.hasV2 || signing.hasV3)) {
      findings.push(
        finding({
          title: '签名结构存在但未能提取证书',
          severity: 'info',
          description: '检测到签名容器，但证书 DER 解析失败或结构非标准，无法确认签名主体；需用 apksigner 或 openssl 复核。',
          verification: 'observed',
          method: '签名块证书解析结果',
          remediation: '使用 `apksigner verify --print-certs app.apk` 或 `openssl pkcs7 -inform DER` 复核证书。',
          target: 'APK#signing',
        }),
      );
    }
    if (signing.certificateCount > 1) {
      findings.push(
        finding({
          title: `检测到 ${signing.certificateCount} 个不同签名证书`,
          severity: 'info',
          description: '多个不同证书可能来自签名轮换（v3 proof-of-rotation）或重打包；需确认签名血缘是否可信。',
          verification: 'observed',
          method: '签名块证书 SHA-256 去重',
          remediation: '核对证书指纹与发布记录；对轮换签名确认 lineage 正确。',
          target: 'APK#signing',
          evidence: signing.certificates.slice(0, 5).map((c) => ({ title: `${c.scheme} 证书`, excerpt: `sha256=${c.sha256}` })),
        }),
      );
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// 能力实现
// ---------------------------------------------------------------------------

export const capabilities = [
  {
    id: 'android.apk_structure',
    title: 'APK/ZIP 容器结构分析',
    description:
      '离线解析 APK 的 ZIP 中央目录：条目清单、压缩方式、dex/resources.arsc/ABI/assets/META-INF、重名与可疑路径、加密条目；不落盘、不解压全部内容。用于快速确认包结构、加固迹象与签名文件存在性。',
    riskLevel: 'L0',
    params: {
      type: 'object',
      properties: {
        maxEntries: { type: 'integer', minimum: 1, maximum: 200000, description: '最多解析并返回的条目数上限' },
        includeEntries: { type: 'boolean', description: '是否在 data.entries 中返回完整条目清单（体积较大）' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const buffer = requireBuffer(input, 'android.apk_structure');
      if (!isZipBuffer(buffer)) {
        throw new Error(
          `android.apk_structure 需要 ZIP/APK 容器：文件头为 ${hexOf(buffer, 8)}，不是 PK 开头。` +
            'APK 本质是 ZIP；若目标是 .dex/.so 请改用对应 capability，若 APK 被加固为自解压格式请先确认容器类型。',
        );
      }
      const zip = parseZip(buffer, {
        maxEntries: limitOf(options.maxEntries, limits.maxItems, 1, 200000),
        maxBytes: limits.maxBytes,
      });
      checkAbort(input);
      const structure = analyzeZipStructure(buffer, zip, options, limits);
      const summary = `容器结构：${summarizeStructure(structure)}。`;
      return makeResult({
        summary,
        data: structure,
        meta: {
          format: 'zip',
          bufferBytes: buffer.length,
          truncated: zip.truncated,
          zip64: zip.zip64,
          warnings: [...zip.warnings].slice(0, 20),
          limitHit: structure.entriesTruncated,
        },
      });
    },
  },

  {
    id: 'android.manifest',
    title: 'AndroidManifest.xml 解析',
    description:
      '解码 APK 内二进制 AndroidManifest.xml（AXML）或文本清单：package/version、minSdk/targetSdk、权限、导出组件与 intent-filter、debuggable/allowBackup/usesCleartextTraffic/networkSecurityConfig 等安全相关开关。用于分析组件暴露面与发布配置。',
    riskLevel: 'L0',
    params: {
      type: 'object',
      properties: {
        includeIntentFilters: { type: 'boolean', description: '是否返回组件 intent-filter 详情（默认 true）' },
        maxComponents: { type: 'integer', minimum: 1, maximum: 2000, description: '每类组件最多返回数量' },
        maxPermissions: { type: 'integer', minimum: 1, maximum: 2000, description: '最多返回的权限数量' },
        textManifestFallback: { type: 'boolean', description: '当清单是纯文本 XML（非 AXML）时是否回退解析（默认 true）' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const { buffer, zip } = openZip(input, options);
      const manifest = loadManifestTree(buffer, zip, options, limits);
      checkAbort(input);
      const model = extractManifestModel(manifest.tree, {
        maxItems: limitOf(options.maxComponents ?? options.maxPermissions, Math.min(limits.maxItems, 500), 1, 2000),
        includeIntentFilters: options.includeIntentFilters !== false,
      });
      const app = model.application;
      const summaryParts = [];
      if (model.package) summaryParts.push(`包名 ${model.package}`);
      const ver = [model.versionName, model.versionCode !== null ? `versionCode=${model.versionCode}` : null].filter(Boolean).join(' ');
      if (ver) summaryParts.push(ver);
      summaryParts.push(`minSdk=${model.minSdkVersion ?? '未声明'} / targetSdk=${model.targetSdkVersion ?? '未声明'}`);
      summaryParts.push(`权限 ${model.stats.permissionCount} 项（危险 ${model.permissions.filter((p) => DANGEROUS_PERMISSIONS.has(p.name)).length} 项）`);
      summaryParts.push(
        `组件 ${model.stats.componentCount} 个（导出 ${model.stats.exportedCount}，导出且无权限 ${model.stats.exportedWithoutPermissionCount}）`,
      );
      if (app) {
        summaryParts.push(`debuggable=${app.debuggable === null ? '未声明' : app.debuggable}`);
        summaryParts.push(`allowBackup=${app.allowBackup === null ? '未声明' : app.allowBackup}`);
        summaryParts.push(`usesCleartextTraffic=${app.usesCleartextTraffic === null ? '未声明' : app.usesCleartextTraffic}`);
      }
      if (model.stats.deepLinkCount > 0) summaryParts.push(`deep link ${model.stats.deepLinkCount} 条`);
      const data = {
        format: manifest.format,
        ...model,
        axml: manifest.axmlStats,
      };
      return makeResult({
        summary: `Android 清单：${summaryParts.join('；')}。`,
        data,
        meta: {
          manifestSize: manifest.size,
          format: manifest.format,
          compressed: manifest.entry.method === METHOD_DEFLATE,
          truncated: Boolean(manifest.axmlStats && manifest.axmlStats.truncated),
          warnings: manifest.warnings.slice(0, 20),
        },
      });
    },
  },

  {
    id: 'android.dex',
    title: 'DEX 结构与字符串摘要',
    description:
      '解析 classes*.dex：magic/版本、string_ids/type_ids/class_defs 计数、类描述符与字符串样本、第三方库与加解密/反调试特征命中、混淆启发式比例。用于判断代码规模、技术栈与加固/混淆迹象；不反编译方法体。',
    riskLevel: 'L0',
    params: {
      type: 'object',
      properties: {
        maxStrings: { type: 'integer', minimum: 1, maximum: 20000, description: '每个 DEX 最多解析的字符串数' },
        maxClassDefs: { type: 'integer', minimum: 1, maximum: 5000, description: '每个 DEX 最多解析的 class_defs 数' },
        maxDexFiles: { type: 'integer', minimum: 1, maximum: 64, description: '最多解析的 DEX 文件数' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const buffer = requireBuffer(input, 'android.dex');
      const maxDexFiles = limitOf(options.maxDexFiles, 8, 1, 64);
      const perDex = {
        maxStrings: limitOf(options.maxStrings, Math.min(limits.maxStrings, 400), 1, 20000),
        maxClassDefs: limitOf(options.maxClassDefs, Math.min(limits.maxItems, 200), 1, 5000),
      };
      const dexResults = [];
      let truncatedAny = false;
      if (isDexBuffer(buffer)) {
        const parsed = parseDex(buffer, { ...perDex, maxScan: perDex.maxStrings * 4 });
        truncatedAny = parsed.truncated;
        dexResults.push({ name: '(直接读取 .dex)', ...parsed });
      } else if (isZipBuffer(buffer)) {
        const zip = parseZip(buffer, { maxEntries: limits.maxItems * 5, maxBytes: limits.maxBytes });
        const dexEntries = zip.entries.filter((e) => /^classes\d*\.dex$/i.test(e.name));
        if (dexEntries.length === 0) {
          throw new Error(
            'APK 内未找到 classes*.dex：目标可能是仅含资源/native 库的 APK、split APK（代码在 base.apk），或经过加固把 DEX 隐藏。' +
              '请提供包含 classes.dex 的 base APK，或先脱壳后按 .dex 文件分析。',
          );
        }
        for (const entry of dexEntries.slice(0, maxDexFiles)) {
          checkAbort(input);
          try {
            const data = readEntryData(buffer, entry, { maxBytes: Math.min(limits.maxBytes, 64 * 1024 * 1024) });
            const parsed = parseDex(data, { ...perDex, maxScan: perDex.maxStrings * 4 });
            truncatedAny = truncatedAny || parsed.truncated;
            dexResults.push({ name: entry.name, compressedSize: entry.compressedSize, ...parsed });
          } catch (err) {
            dexResults.push({ name: entry.name, error: sanitizeText(err.message, 500) });
          }
        }
        if (dexEntries.length > maxDexFiles) truncatedAny = true;
      } else {
        throw new Error(
          'android.dex 需要 .dex 文件或含 classes*.dex 的 APK/ZIP：当前 buffer 头不是 DEX magic 也不是 PK。' +
            '请确认目标类型（可用 android.apk_structure 先判断容器结构）。',
        );
      }

      // 聚合库特征
      const hintMap = new Map();
      for (const dex of dexResults) {
        for (const hint of dex.libraryHints || []) {
          const prev = hintMap.get(hint.category) || { category: hint.category, label: hint.label, matchCount: 0, samples: [] };
          prev.matchCount += hint.matchCount;
          for (const s of hint.samples) if (prev.samples.length < 5 && !prev.samples.includes(s)) prev.samples.push(s);
          hintMap.set(hint.category, prev);
        }
      }
      const aggregate = {
        dexFileCount: dexResults.length,
        parsedDexCount: dexResults.filter((d) => !d.error).length,
        totalStringIds: dexResults.reduce((n, d) => n + (d.counts ? d.counts.stringIds : 0), 0),
        totalMethodIds: dexResults.reduce((n, d) => n + (d.counts ? d.counts.methodIds : 0), 0),
        totalClassDefs: dexResults.reduce((n, d) => n + (d.counts ? d.counts.classDefs : 0), 0),
        versions: [...new Set(dexResults.filter((d) => d.version).map((d) => d.version))].sort(),
        libraryHints: [...hintMap.values()].sort((a, b) => a.category.localeCompare(b.category)),
        obfuscationSampleRatio:
          dexResults.length > 0
            ? Number(
                (
                  dexResults.filter((d) => d.obfuscation).reduce((n, d) => n + d.obfuscation.singleLetterClassRatio, 0) /
                  Math.max(1, dexResults.filter((d) => d.obfuscation).length)
                ).toFixed(3),
              )
            : 0,
      };
      const first = dexResults.find((d) => !d.error);
      const summary = [
        `DEX ${aggregate.dexFileCount} 个（成功解析 ${aggregate.parsedDexCount}）`,
        first ? `主 DEX 版本 ${first.version}，字符串 ${first.counts.stringIds}、方法 ${first.counts.methodIds}、类定义 ${first.counts.classDefs}` : '无可解析 DEX',
        aggregate.libraryHints.length > 0 ? `特征命中：${aggregate.libraryHints.map((h) => h.label).join('、')}` : '未命中已知库特征',
        aggregate.obfuscationSampleRatio > 0.3 ? `混淆启发：短类名比例 ${aggregate.obfuscationSampleRatio}` : null,
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        data: {
          ...aggregate,
          dexFiles: dexResults.map((d) => ({
            name: d.name,
            error: d.error,
            version: d.version,
            fileSize: d.fileSize,
            counts: d.counts,
            strings: d.strings ? d.strings.slice(0, Math.min(perDex.maxStrings, 100)) : [],
            stringCountScanned: d.stringCountScanned,
            classDescriptors: d.classDescriptors ? d.classDescriptors.slice(0, 100) : [],
            classDescriptorCount: d.classDescriptorCount,
            classDefs: d.classDefs ? d.classDefs.slice(0, 50) : [],
            libraryHints: d.libraryHints,
            obfuscation: d.obfuscation,
            truncated: d.truncated,
            warnings: d.warnings,
          })),
        },
        meta: {
          truncated: truncatedAny,
          stringsPerDex: perDex.maxStrings,
          classDefsPerDex: perDex.maxClassDefs,
          maxDexFiles,
        },
      });
    },
  },

  {
    id: 'android.signing',
    title: 'APK 签名方案与证书摘要',
    description:
      '检测 v1（META-INF/*.RSA|DSA|EC）、v2/v3/v3.1（APK Signing Block）签名，提取证书 DER 的 SHA-256、subject/issuer、有效期与调试证书特征。仅解析结构，不做密码学验签；用于判断来源可信度与重打包风险。',
    riskLevel: 'L0',
    params: {
      type: 'object',
      properties: {
        maxCerts: { type: 'integer', minimum: 1, maximum: 64, description: '最多解析的证书数量' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const buffer = requireBuffer(input, 'android.signing');
      if (!isZipBuffer(buffer)) {
        throw new Error('android.signing 需要 APK/ZIP 容器来定位签名块与 META-INF；当前文件不是 ZIP。');
      }
      const zip = parseZip(buffer, { maxEntries: limits.maxItems * 5, maxBytes: limits.maxBytes });
      checkAbort(input);
      const signing = analyzeSigning(buffer, zip, {
        maxCerts: limitOf(options.maxCerts, 16, 1, 64),
        maxEntryBytes: Math.min(limits.maxBytes, 8 * 1024 * 1024),
      });
      const schemeParts = [];
      if (signing.hasV1) schemeParts.push('v1');
      if (signing.hasV2) schemeParts.push('v2');
      if (signing.hasV3) schemeParts.push('v3');
      const cert = signing.certificates[0] || null;
      const subject = cert ? [cert.subject?.CN, cert.subject?.O].filter(Boolean).join(', ') : null;
      const summary = [
        schemeParts.length > 0 ? `检测到签名方案：${schemeParts.join('+')}` : '未检测到 v1/v2/v3 签名',
        cert ? `证书 SHA-256=${cert.sha256.slice(0, 16)}…（${subject || '无主体信息'}）` : null,
        signing.debugCertHint ? '存在 Android Debug 证书迹象' : null,
        '未执行密码学验签',
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `APK 签名：${summary}。`,
        data: {
          hasV1: signing.hasV1,
          hasV2: signing.hasV2,
          hasV3: signing.hasV3,
          schemes: signing.schemes,
          certificateCount: signing.certificateCount,
          certificates: signing.certificates,
          firstCertSha256: signing.firstCertSha256,
          debugCertHint: signing.debugCertHint,
          debugCertDetails: signing.debugCertDetails,
          signingBlock: signing.signingBlock,
          verifyingPolicy: signing.verifyingPolicy,
        },
        meta: {
          bufferBytes: buffer.length,
          warnings: signing.warnings.slice(0, 20),
        },
      });
    },
  },

  {
    id: 'android.findings',
    title: 'Android 配置风险与加固迹象汇总',
    description:
      '综合清单、APK 结构、签名推导风险 findings：debuggable、allowBackup、明文流量、导出组件/provider、危险/特殊权限、deep link、重名/可疑 ZIP 条目、签名方案与调试证书。每条 finding 标注 observed/hypothesis 验证等级，不做未经验证的漏洞断言。',
    riskLevel: 'L0',
    params: {
      type: 'object',
      properties: {
        maxFindings: { type: 'integer', minimum: 1, maximum: 100, description: '最多返回的 findings 数量' },
        includeInfo: { type: 'boolean', description: '是否包含 info 级提示（默认 true）' },
      },
      additionalProperties: false,
    },
    async run(input) {
      const options = optionsOf(input);
      const limits = limitsOf(input);
      checkAbort(input);
      const buffer = requireBuffer(input, 'android.findings');
      const maxFindings = limitOf(options.maxFindings, Math.min(limits.maxFindings, 50), 1, 100);
      if (!isZipBuffer(buffer) && !isDexBuffer(buffer)) {
        throw new Error(
          'android.findings 需要 APK/ZIP（或 .dex）：当前文件头既不是 PK 也不是 dex magic。请确认目标类型。',
        );
      }
      if (!isZipBuffer(buffer)) {
        throw new Error(
          'android.findings 需要完整 APK 容器：仅 .dex 文件没有清单/签名信息，无法推导配置风险。请提供 APK。',
        );
      }
      const zip = parseZip(buffer, { maxEntries: limits.maxItems * 5, maxBytes: limits.maxBytes });
      checkAbort(input);
      const structure = analyzeZipStructure(buffer, zip, {}, limits);
      let model = null;
      let manifestError = null;
      let manifestMeta = null;
      try {
        const manifest = loadManifestTree(buffer, zip, options, limits);
        manifestMeta = { format: manifest.format, warnings: manifest.warnings };
        model = extractManifestModel(manifest.tree, {
          maxItems: Math.min(limits.maxItems, 500),
          includeIntentFilters: true,
        });
      } catch (err) {
        manifestError = sanitizeText(err.message, 1000);
      }
      let signing = null;
      let signingError = null;
      try {
        signing = analyzeSigning(buffer, zip, { maxCerts: 16, maxEntryBytes: Math.min(limits.maxBytes, 8 * 1024 * 1024) });
      } catch (err) {
        signingError = sanitizeText(err.message, 1000);
      }
      checkAbort(input);
      let findings = deriveFindings({ model, structure, signing, manifestError: manifestError || signingError ? manifestError || `signing: ${signingError}` : null });
      if (options.includeInfo === false) findings = findings.filter((f) => f.severity !== 'info');
      findings = findings
        .map((f) => ({ ...f }))
        .sort((a, b) => {
          const sa = SEVERITY_ORDER[a.severity] ?? 9;
          const sb = SEVERITY_ORDER[b.severity] ?? 9;
          if (sa !== sb) return sa - sb;
          return a.title.localeCompare(b.title);
        })
        .slice(0, maxFindings);
      const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      const summary = [
        `Android 风险评估：共 ${findings.length} 条 findings`,
        Object.entries(bySeverity)
          .filter(([, n]) => n > 0)
          .map(([k, n]) => `${k} ${n}`)
          .join(' / '),
        model ? `包名 ${model.package ?? '未知'}，导出组件 ${model.stats.exportedCount} 个` : '清单不可用',
        signing ? (signing.debugCertHint ? '调试证书签名' : signing.certificateCount > 0 ? '签名证书已提取' : '签名证书未提取') : '签名不可用',
        'findings 含观察项与推断项，verification 已逐条标注',
      ]
        .filter(Boolean)
        .join('；');
      return makeResult({
        summary: `${summary}。`,
        findings,
        data: {
          findingsTotal: findings.length,
          bySeverity,
          manifest: model
            ? {
                package: model.package,
                versionName: model.versionName,
                versionCode: model.versionCode,
                minSdkVersion: model.minSdkVersion,
                targetSdkVersion: model.targetSdkVersion,
                stats: model.stats,
                application: model.application,
                dangerousPermissions: model.permissions.filter((p) => DANGEROUS_PERMISSIONS.has(p.name)).map((p) => p.name),
              }
            : { error: manifestError },
          structure: {
            entryCount: structure.entryCount,
            dexFileCount: structure.dexFiles.length,
            abis: structure.abis,
            hasResourcesArsc: structure.hasResourcesArsc,
            duplicateNameCount: structure.duplicateNameCount,
            suspiciousNameCount: structure.suspiciousNames.length,
          },
          signing: signing
            ? {
                hasV1: signing.hasV1,
                hasV2: signing.hasV2,
                hasV3: signing.hasV3,
                certificateCount: signing.certificateCount,
                firstCertSha256: signing.firstCertSha256,
                debugCertHint: signing.debugCertHint,
              }
            : { error: signingError },
        },
        meta: {
          truncated: zip.truncated,
          maxFindings,
          includeInfo: options.includeInfo !== false,
          warnings: [...zip.warnings, ...(manifestMeta?.warnings || [])].slice(0, 20),
        },
      });
    },
  },
];

export default {
  domain: 'android',
  capabilities,
};
