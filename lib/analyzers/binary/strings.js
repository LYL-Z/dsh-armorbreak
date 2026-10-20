/**
 * Binary domain — printable string extraction + categorization.
 * Extracts ASCII and UTF-16LE strings, strips control characters, caps counts.
 */
import { extractAsciiStrings, extractUtf16Strings, sanitizeText } from './util.js';

const TLD = [
  'com', 'net', 'org', 'info', 'biz', 'xyz', 'top', 'site', 'online', 'club', 'shop',
  'cn', 'ru', 'io', 'co', 'uk', 'de', 'fr', 'jp', 'kr', 'in', 'br', 'nl', 'eu', 'us',
  'ca', 'au', 'es', 'it', 'pl', 'ch', 'se', 'no', 'fi', 'dk', 'cz', 'tr', 'ua', 'vn',
  'ir', 'il', 'ae', 'sa', 'mx', 'ar', 'cl', 'id', 'my', 'sg', 'th', 'ph', 'tw', 'hk',
  'app', 'dev', 'cloud', 'tech', 'store', 'live', 'pro', 'link', 'click', 'work',
  'space', 'website', 'fun', 'icu', 'cyou', 'monster', 'quest', 'rest', 'bar',
];
const TLD_SET = new Set(TLD);
const FILE_EXT = new Set([
  'exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'drv', 'bin', 'dat', 'tmp', 'log', 'txt',
  'cfg', 'ini', 'xml', 'json', 'html', 'htm', 'js', 'css', 'jpg', 'jpeg', 'png', 'gif',
  'bmp', 'ico', 'svg', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar',
  '7z', 'gz', 'tar', 'bz2', 'xz', 'msi', 'cab', 'iso', 'vbs', 'ps1', 'bat', 'cmd',
  'py', 'rb', 'php', 'asp', 'aspx', 'jsp', 'cgi', 'so', 'dylib', 'node', 'wasm',
]);

const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;
const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'<>`|\u0000-\u001f]{1,512}/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b/g;
const REGISTRY_RE = /(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>|\u0000-\u001f]{1,512}/gi;
const FILEPATH_RE = /(?:[A-Za-z]:\\(?:[^\\/:*?"<>|\u0000-\u001f]{1,200}\\){1,12}[^\\/:*?"<>|\u0000-\u001f]{1,200}|\/tmp\/[^\s"'<>|\u0000-\u001f]{1,200}|\/etc\/[^\s"'<>|\u0000-\u001f]{1,200}|\/var\/[^\s"'<>|\u0000-\u001f]{1,200}|\/home\/[^\s"'<>|\u0000-\u001f]{1,200}|\/(?:usr|opt|bin|sbin|lib|proc|dev|root)\/[^\s"'<>|\u0000-\u001f]{1,200})/g;
const WINAPI_RE = /\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread(?:Ex)?|CreateToolhelp32Snapshot|OpenProcess|LoadLibrary[AW]?|GetProcAddress|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|NtCreateThreadEx|RegSetValueEx[AW]?|RegCreateKeyEx[AW]?|CreateProcess[AW]?|WinExec|ShellExecute[AW]?|InternetOpen[AW]?|InternetReadFile|URLDownloadToFile[AW]?|WinHttpOpen|Crypt(?:Encrypt|Decrypt|GenKey)|FindFirstFile[AW]?|CopyFile[AW]?|MoveFile[AW]?|DeleteFile[AW]?|SetWindowsHookEx[AW]?|GetAsyncKeyState|MapViewOfFile|AdjustTokenPrivileges|LookupPrivilegeValue[AW]?|WSAStartup|socket|connect|send|recv)\b/g;
const COMMAND_RE = /\b(?:powershell(?:\.exe)?(?:\s+-[a-zA-Z]{1,10})?|pwsh(?:\.exe)?|cmd(?:\.exe)?\s+\/c|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|wmic(?:\.exe)?|schtasks(?:\.exe)?|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|cscript(?:\.exe)?|wscript(?:\.exe)?|net\s+user|net\s+localgroup|sc(?:\.exe)?\s+create|reg\s+add|whoami|ipconfig|tasklist|taskkill|Invoke-(?:Expression|WebRequest|Mimikatz|Shellcode|PowerShell)|IEX\s*\(|DownloadString|FromBase64String)\b/gi;
const CRYPTO_RE = /\b(?:AES(?:-?(?:128|192|256))?|RSA(?:-?(?:1024|2048|4096))?|ChaCha20|Salsa20|Blowfish|Twofish|3DES|DES|RC4|SHA-?(?:1|224|256|384|512)|MD5|HMAC|PBKDF2|bcrypt|EVP_(?:Encrypt|Decrypt))\b/g;
const BASE64_RE = /^[A-Za-z0-9+/]{24,}={0,2}$/;
const GUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;
const PDB_RE = /\b[^\s"'<>|]{1,512}\.pdb\b/gi;
const URL_SCHEME_RE = /\b(?:https?|ftp):\/\//i;

export const STRING_CATEGORIES = Object.freeze([
  'url', 'ipv4', 'domain', 'email', 'registryKey', 'windowsPath', 'winapi',
  'command', 'crypto', 'base64', 'guid', 'pdbPath',
]);

function validDomainCandidate(value) {
  if (value.length > 253) return false;
  const lower = value.toLowerCase();
  if (IPV4_RE.test(value)) return false;
  IPV4_RE.lastIndex = 0;
  const parts = lower.split('.');
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1];
  if (!TLD_SET.has(tld)) return false;
  if (FILE_EXT.has(tld)) return false;
  for (const part of parts) {
    if (!part || part.length > 63) return false;
    if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)) return false;
  }
  return true;
}

function collectRegex(value, re, category, out, seen) {
  re.lastIndex = 0;
  let m;
  let guard = 0;
  while ((m = re.exec(value)) !== null && guard < 16) {
    guard += 1;
    const matched = m[0];
    if (!seen.has(`${category}:${matched}`)) {
      seen.add(`${category}:${matched}`);
      out.push({ category, value: matched });
    }
    if (m.index === re.lastIndex) re.lastIndex += 1;
  }
}

/** Categorize a list of extracted strings. Deterministic: preserves input order. */
export function categorizeStrings(strings) {
  const counts = Object.fromEntries(STRING_CATEGORIES.map((c) => [c, 0]));
  const samples = Object.fromEntries(STRING_CATEGORIES.map((c) => [c, []]));
  const seen = new Set();
  const maxPerCategory = 120;
  const all = [];
  for (const item of strings) {
    const value = item.value;
    if (typeof value !== 'string' || value.length === 0) continue;
    if (URL_SCHEME_RE.test(value)) {
      collectRegex(value, URL_RE, 'url', all, seen);
      // A URL also yields its host under 'domain' below; both are useful and counted separately.
    }
    collectRegex(value, IPV4_RE, 'ipv4', all, seen);
    collectRegex(value, EMAIL_RE, 'email', all, seen);
    collectRegex(value, REGISTRY_RE, 'registryKey', all, seen);
    collectRegex(value, FILEPATH_RE, 'windowsPath', all, seen);
    collectRegex(value, WINAPI_RE, 'winapi', all, seen);
    collectRegex(value, COMMAND_RE, 'command', all, seen);
    collectRegex(value, CRYPTO_RE, 'crypto', all, seen);
    collectRegex(value, GUID_RE, 'guid', all, seen);
    collectRegex(value, PDB_RE, 'pdbPath', all, seen);
    DOMAIN_RE.lastIndex = 0;
    let dm;
    let dGuard = 0;
    while ((dm = DOMAIN_RE.exec(value)) !== null && dGuard < 8) {
      dGuard += 1;
      const candidate = dm[0];
      if (validDomainCandidate(candidate) && !seen.has(`domain:${candidate}`)) {
        seen.add(`domain:${candidate}`);
        all.push({ category: 'domain', value: candidate });
      }
      if (dm.index === DOMAIN_RE.lastIndex) DOMAIN_RE.lastIndex += 1;
    }
    const trimmed = value.trim();
    if (trimmed.length >= 24 && trimmed.length <= 8192 && BASE64_RE.test(trimmed)) {
      const decodedMarker = `${trimmed.slice(0, 24)}`;
      if (!seen.has(`base64:${decodedMarker}`)) {
        seen.add(`base64:${decodedMarker}`);
        all.push({ category: 'base64', value: trimmed, length: trimmed.length });
      }
    }
  }
  for (const item of all) {
    counts[item.category] += 1;
    if (samples[item.category].length < maxPerCategory) {
      samples[item.category].push({
        value: sanitizeText(item.value, 512),
        ...(item.length ? { length: item.length } : {}),
      });
    }
  }
  return { counts, samples, totalCategorized: all.length };
}

/**
 * Extract ASCII + UTF-16LE strings and categorize them.
 * @returns {{asciiCount:number, utf16Count:number, asciiStrings:Array, utf16Strings:Array, truncated:boolean, categories:object}}
 */
export function extractBinaryStrings(buffer, opts = {}) {
  const minLen = Math.max(4, Math.min(64, Math.floor(Number(opts.minLen) || 4)));
  const max = Math.max(1, Math.floor(Number(opts.max) || 500));
  const ascii = extractAsciiStrings(buffer, { minLen, max });
  const utf16 = extractUtf16Strings(buffer, { minLen, max, endian: 'le' });
  const tagged = [
    ...ascii.strings.map((s) => ({ ...s, encoding: 'ascii' })),
    ...utf16.strings.map((s) => ({ ...s, encoding: 'utf16le' })),
  ].sort((a, b) => a.offset - b.offset || a.encoding.localeCompare(b.encoding));
  const categories = categorizeStrings(tagged);
  return {
    asciiCount: ascii.strings.length,
    utf16Count: utf16.strings.length,
    asciiStrings: ascii.strings,
    utf16Strings: utf16.strings,
    all: tagged,
    truncated: ascii.truncated || utf16.truncated,
    categories,
  };
}

/** Interesting substrings used to build evidence (bounded, sanitized later). */
export function interestingStrings(extraction, maxItems = 12) {
  const out = [];
  for (const category of ['command', 'url', 'registryKey', 'pdbPath', 'winapi', 'crypto', 'windowsPath']) {
    const list = extraction.categories.samples[category] || [];
    for (const item of list) {
      if (out.length >= maxItems) return out;
      out.push({ category, value: item.value });
    }
  }
  return out;
}
