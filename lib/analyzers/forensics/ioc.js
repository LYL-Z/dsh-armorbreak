/**
 * Forensics — IOC extraction from bytes: IPv4/IPv6, domains, URLs, e-mails, file hashes,
 * registry keys and absolute file paths. Counts + first offsets are deterministic.
 * Extraction is observed; maliciousness of any indicator is NOT evaluated here.
 */
import { extractAsciiStrings, extractUtf16Strings, sanitizeText } from '../binary/util.js';

const TLD = new Set([
  'com', 'net', 'org', 'info', 'biz', 'xyz', 'top', 'site', 'online', 'club', 'shop',
  'cn', 'ru', 'io', 'co', 'uk', 'de', 'fr', 'jp', 'kr', 'in', 'br', 'nl', 'eu', 'us',
  'ca', 'au', 'es', 'it', 'pl', 'ch', 'se', 'no', 'fi', 'dk', 'cz', 'tr', 'ua', 'vn',
  'ir', 'il', 'ae', 'sa', 'mx', 'ar', 'cl', 'id', 'my', 'sg', 'th', 'ph', 'tw', 'hk',
  'app', 'dev', 'cloud', 'tech', 'store', 'live', 'pro', 'link', 'click', 'work',
  'space', 'website', 'fun', 'icu', 'cyou', 'monster', 'quest', 'rest', 'bar', 'su',
]);
const FILE_EXT = new Set([
  'exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'drv', 'bin', 'dat', 'tmp', 'log', 'txt',
  'cfg', 'ini', 'xml', 'json', 'html', 'htm', 'js', 'css', 'jpg', 'jpeg', 'png', 'gif',
  'bmp', 'ico', 'svg', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar',
  '7z', 'gz', 'tar', 'bz2', 'xz', 'msi', 'cab', 'iso', 'vbs', 'ps1', 'bat', 'cmd',
  'py', 'rb', 'php', 'asp', 'aspx', 'jsp', 'cgi', 'so', 'dylib', 'node', 'wasm',
]);

const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>`|\u0000-\u001f]{1,512}/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;
const REGISTRY_RE = /(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>|\u0000-\u001f]{1,512}/gi;
const WINDOWS_PATH_RE = /[A-Za-z]:\\(?:[^\\/:*?"<>|\u0000-\u001f]{1,200}\\){0,12}[^\\/:*?"<>|\u0000-\u001f]{1,200}/g;
const UNIX_PATH_RE = /(?:^|[\s"'=])(\/(?:etc|tmp|var|usr|opt|home|root|dev|proc|bin|sbin|lib)\/[^\s"'<>|\u0000-\u001f]{1,240})/g;
const MD5_RE = /(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])/g;
const SHA1_RE = /(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])/g;
const SHA256_RE = /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g;
const SHA512_RE = /(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])/g;
const IPV6_RE = /(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,8}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])/g;

export const IOC_CATEGORIES = Object.freeze(['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'sha512', 'registryKey', 'windowsPath', 'unixPath']);

function ipv4Flags(value) {
  const [a, b] = value.split('.').map(Number);
  const flags = {};
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) flags.private = true;
  if (a === 127) flags.loopback = true;
  if (a === 169 && b === 254) flags.linkLocal = true;
  if (a >= 224 && a <= 239) flags.multicast = true;
  if (a === 0) flags.unspecified = true;
  if (a === 255) flags.broadcast = true;
  if ((a === 192 && b === 0 && Number(value.split('.')[2]) === 2) || (a === 198 && b === 51 && Number(value.split('.')[2]) === 100) || (a === 203 && b === 0 && Number(value.split('.')[2]) === 113)) flags.documentation = true;
  return flags;
}

function validIpv6(candidate) {
  if (candidate.length > 45) return false;
  if ((candidate.match(/:/g) || []).length < 2) return false;
  const hasCompression = candidate.includes('::');
  const parts = candidate.split(':');
  if (!hasCompression && parts.length !== 8) return false;
  if (hasCompression) {
    if (candidate.indexOf('::') !== candidate.lastIndexOf('::')) return false;
    const nonEmpty = parts.filter((p) => p.length > 0);
    if (nonEmpty.length > 7) return false;
  }
  for (const part of parts) {
    if (part.length === 0) continue;
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
  }
  return true;
}

function validDomain(candidate) {
  if (candidate.length > 253) return false;
  const lower = candidate.toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(lower)) return false;
  const parts = lower.split('.');
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1];
  if (!TLD.has(tld) || FILE_EXT.has(tld)) return false;
  for (const part of parts) {
    if (!part || part.length > 63) return false;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)) return false;
  }
  return true;
}

function cleanValue(value, maxLen = 512) {
  return sanitizeText(value, maxLen);
}

/**
 * @returns {{data:object, summary:string, warnings:string[]}}
 */
export function extractIocs(buffer, limits, options = {}) {
  const includePrivate = options.includePrivateIps !== false;
  const requestedCategories = Array.isArray(options.categories) && options.categories.length > 0
    ? options.categories.filter((c) => IOC_CATEGORIES.includes(c))
    : IOC_CATEGORIES;
  const enabled = new Set(requestedCategories);
  const maxStrings = Math.min(limits.maxStrings, 4000);
  const ascii = extractAsciiStrings(buffer, { minLen: 4, max: maxStrings });
  const utf16 = extractUtf16Strings(buffer, { minLen: 4, max: Math.min(maxStrings, 1500), endian: 'le' });
  const strings = [
    ...ascii.strings.map((s) => ({ ...s, encoding: 'ascii' })),
    ...utf16.strings.map((s) => ({ ...s, encoding: 'utf16le' })),
  ].sort((a, b) => a.offset - b.offset || a.encoding.localeCompare(b.encoding));
  const collection = new Map();
  const add = (category, value, absOffset, extraFlags = {}) => {
    if (!enabled.has(category)) return;
    const cleaned = cleanValue(value, category === 'url' ? 1024 : 512);
    if (!cleaned) return;
    const key = `${category}\u0000${cleaned}`;
    const existing = collection.get(key);
    if (existing) {
      existing.count += 1;
      return;
    }
    collection.set(key, { category, value: cleaned, count: 1, firstOffset: absOffset, flags: extraFlags });
  };
  const runRegex = (text, re, category, baseOffset, validate, extraFlags = {}) => {
    re.lastIndex = 0;
    let m;
    let guard = 0;
    while ((m = re.exec(text)) !== null && guard < 64) {
      guard += 1;
      const value = m[1] !== undefined ? m[1] : m[0];
      if (validate && !validate(value)) {
        if (m.index === re.lastIndex) re.lastIndex += 1;
        continue;
      }
      add(category, value, baseOffset + m.index, typeof extraFlags === 'function' ? extraFlags(value) : extraFlags);
      if (m.index === re.lastIndex) re.lastIndex += 1;
    }
  };

  for (const item of strings) {
    const text = item.value;
    const base = item.offset;
    // URLs (extract host as domain too)
    URL_RE.lastIndex = 0;
    let um;
    let uGuard = 0;
    while ((um = URL_RE.exec(text)) !== null && uGuard < 16) {
      uGuard += 1;
      const url = um[0].replace(/[.,;:!?)\]}'"]+$/, '');
      add('url', url, base + um.index);
      try {
        const host = new URL(url).hostname;
        if (host && validDomain(host)) add('domain', host, base + um.index, { fromUrl: true });
      } catch {
        // non-standard URL form: skip host derivation
      }
      if (um.index === URL_RE.lastIndex) URL_RE.lastIndex += 1;
    }
    runRegex(text, IPV4_RE, 'ipv4', base, (v) => v.split('.').every((p) => p.length <= 3 && Number(p) <= 255), ipv4Flags);
    runRegex(text, IPV6_RE, 'ipv6', base, validIpv6);
    runRegex(text, EMAIL_RE, 'email', base);
    runRegex(text, REGISTRY_RE, 'registryKey', base, null, (v) => {
      const flags = {};
      if (/^HKEY_LOCAL_MACHINE|^HKLM/i.test(v)) flags.hive = 'HKLM';
      else if (/^HKEY_CURRENT_USER|^HKCU/i.test(v)) flags.hive = 'HKCU';
      else if (/^HKEY_CLASSES_ROOT|^HKCR/i.test(v)) flags.hive = 'HKCR';
      else if (/^HKEY_USERS|^HKU/i.test(v)) flags.hive = 'HKU';
      else if (/^HKEY_CURRENT_CONFIG|^HKCC/i.test(v)) flags.hive = 'HKCC';
      if (/[\\/](?:Run|RunOnce|RunServices|RunServicesOnce)[\\/]/i.test(v) || /[\\/]Policies[\\/]Explorer[\\/]Run$/i.test(v)) flags.autorun = true;
      return flags;
    });
    runRegex(text, WINDOWS_PATH_RE, 'windowsPath', base);
    runRegex(text, UNIX_PATH_RE, 'unixPath', base);
    runRegex(text, SHA256_RE, 'sha256', base);
    runRegex(text, SHA512_RE, 'sha512', base);
    runRegex(text, SHA1_RE, 'sha1', base);
    runRegex(text, MD5_RE, 'md5', base);
    DOMAIN_RE.lastIndex = 0;
    let dm;
    let dGuard = 0;
    while ((dm = DOMAIN_RE.exec(text)) !== null && dGuard < 32) {
      dGuard += 1;
      const candidate = dm[0];
      if (validDomain(candidate)) {
        const prefix = text.slice(Math.max(0, dm.index - 8), dm.index);
        const fromUrl = /:\/\/(?:[^@/]*@)?$/i.test(prefix);
        add('domain', candidate.toLowerCase(), base + dm.index, fromUrl ? { fromUrl: true } : {});
      }
      if (dm.index === DOMAIN_RE.lastIndex) DOMAIN_RE.lastIndex += 1;
    }
  }

  const iocs = {};
  const counts = {};
  for (const category of IOC_CATEGORIES) {
    iocs[category] = [];
    counts[category] = { unique: 0, occurrences: 0 };
  }
  const all = [...collection.values()].sort((a, b) => {
    if (a.category !== b.category) return a.category.localeCompare(b.category);
    return b.count - a.count || a.firstOffset - b.firstOffset || a.value.localeCompare(b.value);
  });
  const perCategoryCap = Math.min(limits.maxStrings, 500);
  let filteredPrivate = 0;
  for (const record of all) {
    if (!includePrivate && record.category === 'ipv4' && record.flags && (record.flags.private || record.flags.loopback || record.flags.linkLocal)) {
      filteredPrivate += 1;
      continue;
    }
    counts[record.category].unique += 1;
    counts[record.category].occurrences += record.count;
    if (iocs[record.category].length < perCategoryCap) {
      iocs[record.category].push({
        value: record.value,
        count: record.count,
        firstOffset: record.firstOffset,
        ...(record.flags && Object.keys(record.flags).length > 0 ? { flags: record.flags } : {}),
      });
    }
  }
  const totals = Object.values(counts).reduce((acc, c) => ({ unique: acc.unique + c.unique, occurrences: acc.occurrences + c.occurrences }), { unique: 0, occurrences: 0 });
  const warnings = [];
  if (ascii.truncated || utf16.truncated) warnings.push(`字符串提取达到 maxStrings=${maxStrings} 上限，部分字节未扫描。`);
  if (filteredPrivate > 0) warnings.push(`已按 includePrivateIps=false 过滤 ${filteredPrivate} 个私有/本地 IPv4 指标。`);
  warnings.push('IOC 抽取结果是 data 层事实；指标是否恶意需外部情报与授权环境验证，本能力不做定性。');
  const summaryParts = [`从 ${buffer.length} 字节中提取 IOC：共 ${totals.unique} 个唯一指标（${totals.occurrences} 次出现）。`];
  for (const category of IOC_CATEGORIES) {
    if (counts[category].unique > 0) summaryParts.push(`${category}=${counts[category].unique}`);
  }
  return {
    summary: summaryParts.join('；'),
    data: {
      counts,
      totals,
      iocs,
      analyzedBytes: buffer.length,
      scannedStrings: strings.length,
      encoding: 'ascii+utf16le',
      includePrivateIps: includePrivate,
      categoriesScanned: requestedCategories,
      truncated: ascii.truncated || utf16.truncated,
    },
    warnings,
  };
}

/** Categories that commonly deserve a finding when present (used by manifest). */
export const HIGH_SIGNAL_CATEGORIES = Object.freeze(['url', 'domain', 'ipv4', 'registryKey']);
