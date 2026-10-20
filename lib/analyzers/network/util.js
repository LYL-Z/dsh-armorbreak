// ArmorBreak - network 域共享小工具（纯 node:*）
// 不可信报文数据一律当数据处理：控制字符剥离、长度上限、稳定排序。

export function limitOf(value, def, min, max) {
  const n = Number.isInteger(value) ? value : def;
  return Math.min(max, Math.max(min, n));
}

export function sanitizeText(value, maxLen = 2000) {
  if (typeof value !== 'string') return '';
  let out = '';
  for (const ch of value) {
    const code = ch.codePointAt(0);
    if (code === 9 || code === 10) out += ch;
    else if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) out += ' ';
    else out += ch;
  }
  out = out.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
  if (out.length > maxLen) out = out.slice(0, maxLen) + '…';
  return out;
}

export function clip(value, max) {
  if (!Array.isArray(value)) return { items: [], truncated: false };
  if (value.length <= max) return { items: value, truncated: false };
  return { items: value.slice(0, max), truncated: true };
}

export function humanBytes(n) {
  if (!Number.isFinite(n) || n < 0) return '未知';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

export function optionsOf(input) {
  const o = input && typeof input === 'object' ? input.options : null;
  return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
}

export function limitsOf(input) {
  const l = (input && input.limits) || {};
  return {
    maxBytes: Number.isFinite(l.maxBytes) && l.maxBytes > 0 ? l.maxBytes : 64 * 1024 * 1024,
    maxItems: Number.isFinite(l.maxItems) && l.maxItems > 0 ? l.maxItems : 200,
    maxStrings: Number.isFinite(l.maxStrings) && l.maxStrings > 0 ? l.maxStrings : 500,
    maxFindings: Number.isFinite(l.maxFindings) && l.maxFindings > 0 ? l.maxFindings : 100,
    timeoutMs: Number.isFinite(l.timeoutMs) && l.timeoutMs > 0 ? l.timeoutMs : 30000,
  };
}

export function requireBuffer(input, capabilityLabel) {
  const buf = input && Buffer.isBuffer(input.buffer) ? input.buffer : null;
  if (!buf || buf.length === 0) {
    throw new Error(
      `缺少可分析字节：capability ${capabilityLabel} 需要 targetPath 指向 pcap/pcapng 抓包文件，且核心已读入 buffer。` +
        '请确认目标是非空文件、不是目录，或提高 limits.maxBytes 后重试。',
    );
  }
  return buf;
}

export function checkAbort(input) {
  const signal = input && input.env ? input.env.signal : null;
  if (signal && signal.aborted) {
    const err = new Error('分析已被取消（AbortSignal 已触发）。');
    err.name = 'AbortError';
    throw err;
  }
}

export function makeResult({ summary, findings = [], evidence = [], data = {}, meta = {} }) {
  return {
    summary: sanitizeText(summary, 4000),
    findings: findings.slice(0, 100),
    evidence,
    data: enforceDataBudget(data),
    meta,
  };
}

function jsonBytes(value) {
  try {
    return Buffer.byteLength(JSON.stringify(value), 'utf8');
  } catch {
    return Infinity;
  }
}

/**
 * 保证 data 序列化体积不超过契约上限（默认 256KiB）：
 * 反复把最大的数组对半裁剪，直到满足预算；裁剪过的 data 会带 dataBudget 标记。
 */
export function enforceDataBudget(data, maxBytes = 256 * 1024) {
  if (jsonBytes(data) <= maxBytes) return data;
  const trimmedPaths = [];
  let guard = 0;
  while (guard++ < 200 && jsonBytes(data) > maxBytes) {
    const candidates = [];
    const walk = (node, path) => {
      if (!node || typeof node !== 'object') return;
      if (Array.isArray(node)) {
        if (node.length > 0) candidates.push({ node, path, size: jsonBytes(node) });
        return;
      }
      for (const key of Object.keys(node)) walk(node[key], path ? `${path}.${key}` : key);
    };
    walk(data, '');
    if (candidates.length === 0) break;
    candidates.sort((a, b) => b.size - a.size);
    const target = candidates[0];
    target.node.splice(Math.max(0, Math.floor(target.node.length / 2)));
    trimmedPaths.push(target.path || '(root)');
  }
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    data.dataBudget = {
      limitBytes: maxBytes,
      truncated: true,
      trimmedPaths: [...new Set(trimmedPaths)].slice(0, 20),
    };
  }
  return data;
}

// ---------------------------------------------------------------------------
// IP 地址格式化与分类
// ---------------------------------------------------------------------------

export function formatIpv4(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 4) return null;
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

export function formatIpv6(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 16) return null;
  const bytes = buffer.subarray(0, 16);
  // IPv4-mapped: ::ffff:a.b.c.d
  let mapped = true;
  for (let i = 0; i < 10; i++) if (bytes[i] !== 0) mapped = false;
  if (mapped && bytes[10] === 0xff && bytes[11] === 0xff) {
    return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  const groups = [];
  for (let i = 0; i < 8; i++) groups.push(bytes.readUInt16BE(i * 2));
  // 最长连续 0 段压缩（RFC 5952）
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (curStart < 0) curStart = i;
    } else if (curStart >= 0) {
      const len = i - curStart;
      if (len > bestLen && len >= 2) {
        bestStart = curStart;
        bestLen = len;
      }
      curStart = -1;
    }
  }
  const hex = (n) => n.toString(16);
  if (bestStart < 0) return groups.map(hex).join(':');
  const left = groups.slice(0, bestStart).map(hex).join(':');
  const right = groups.slice(bestStart + bestLen).map(hex).join(':');
  if (left && right) return `${left}::${right}`;
  if (left) return `${left}::`;
  if (right) return `::${right}`;
  return '::';
}

/** 解析字符串 IPv4 为 u32（用于网段判断）。 */
function ipv4ToInt(ip) {
  if (typeof ip !== 'string') return null;
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const v = Number(part);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function inV4Cidr(ip, base, prefix) {
  const addr = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (addr === null || baseInt === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (addr & mask) === (baseInt & mask);
}

const CATEGORY_LABELS = {
  private: '私有地址（RFC1918）',
  loopback: '回环地址',
  'link-local': '链路本地地址',
  cgnat: '运营商级 NAT（100.64/10）',
  multicast: '多播地址',
  documentation: '文档/示例地址段',
  reserved: '保留地址',
  public: '公网地址',
  'ipv6-ula': 'IPv6 唯一本地地址（fc00::/7）',
  'ipv6-link-local': 'IPv6 链路本地地址（fe80::/10）',
  'ipv6-loopback': 'IPv6 回环地址',
  'ipv6-multicast': 'IPv6 多播地址',
  'ipv6-documentation': 'IPv6 文档地址段（2001:db8::/32）',
  unspecified: '未指定地址',
};

/** 判断 IP 地址类别（观测用途，不是威胁情报判定）。 */
export function classifyIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return { category: 'unknown', label: '未知地址', isPrivate: false, isPublic: false };
  if (!ip.includes(':')) {
    if (ip === '0.0.0.0') return { category: 'unspecified', label: CATEGORY_LABELS.unspecified, isPrivate: false, isPublic: false };
    if (inV4Cidr(ip, '127.0.0.0', 8)) return { category: 'loopback', label: CATEGORY_LABELS.loopback, isPrivate: true, isPublic: false };
    if (inV4Cidr(ip, '10.0.0.0', 8)) return { category: 'private', label: CATEGORY_LABELS.private, isPrivate: true, isPublic: false };
    if (inV4Cidr(ip, '172.16.0.0', 12)) return { category: 'private', label: CATEGORY_LABELS.private, isPrivate: true, isPublic: false };
    if (inV4Cidr(ip, '192.168.0.0', 16)) return { category: 'private', label: CATEGORY_LABELS.private, isPrivate: true, isPublic: false };
    if (inV4Cidr(ip, '169.254.0.0', 16)) return { category: 'link-local', label: CATEGORY_LABELS['link-local'], isPrivate: true, isPublic: false };
    if (inV4Cidr(ip, '100.64.0.0', 10)) return { category: 'cgnat', label: CATEGORY_LABELS.cgnat, isPrivate: true, isPublic: false };
    if (inV4Cidr(ip, '192.0.2.0', 24) || inV4Cidr(ip, '198.51.100.0', 24) || inV4Cidr(ip, '203.0.113.0', 24)) {
      return { category: 'documentation', label: CATEGORY_LABELS.documentation, isPrivate: false, isPublic: false };
    }
    if (inV4Cidr(ip, '224.0.0.0', 4)) return { category: 'multicast', label: CATEGORY_LABELS.multicast, isPrivate: false, isPublic: false };
    if (inV4Cidr(ip, '240.0.0.0', 4)) return { category: 'reserved', label: CATEGORY_LABELS.reserved, isPrivate: false, isPublic: false };
    if (inV4Cidr(ip, '0.0.0.0', 8)) return { category: 'reserved', label: CATEGORY_LABELS.reserved, isPrivate: false, isPublic: false };
    return { category: 'public', label: CATEGORY_LABELS.public, isPrivate: false, isPublic: true };
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.slice('::ffff:'.length);
    return classifyIp(v4);
  }
  if (lower === '::') return { category: 'unspecified', label: CATEGORY_LABELS.unspecified, isPrivate: false, isPublic: false };
  if (lower === '::1') return { category: 'ipv6-loopback', label: CATEGORY_LABELS['ipv6-loopback'], isPrivate: true, isPublic: false };
  const firstGroup = parseInt(lower.split(':')[0] || '0', 16);
  if ((firstGroup & 0xfe00) === 0xfc00) return { category: 'ipv6-ula', label: CATEGORY_LABELS['ipv6-ula'], isPrivate: true, isPublic: false };
  if ((firstGroup & 0xffc0) === 0xfe80) return { category: 'ipv6-link-local', label: CATEGORY_LABELS['ipv6-link-local'], isPrivate: true, isPublic: false };
  if (lower.startsWith('2001:db8')) return { category: 'ipv6-documentation', label: CATEGORY_LABELS['ipv6-documentation'], isPrivate: false, isPublic: false };
  if ((firstGroup & 0xff00) === 0xff00) return { category: 'ipv6-multicast', label: CATEGORY_LABELS['ipv6-multicast'], isPrivate: false, isPublic: false };
  return { category: 'public', label: CATEGORY_LABELS.public, isPrivate: false, isPublic: true };
}

// ---------------------------------------------------------------------------
// 端口/时间辅助
// ---------------------------------------------------------------------------

export const COMMON_PORTS = new Map([
  [20, 'ftp-data'],
  [21, 'ftp'],
  [22, 'ssh'],
  [23, 'telnet'],
  [25, 'smtp'],
  [53, 'dns'],
  [67, 'dhcp-server'],
  [68, 'dhcp-client'],
  [69, 'tftp'],
  [80, 'http'],
  [110, 'pop3'],
  [123, 'ntp'],
  [135, 'msrpc'],
  [137, 'netbios-ns'],
  [138, 'netbios-dgm'],
  [139, 'netbios-ssn'],
  [143, 'imap'],
  [161, 'snmp'],
  [162, 'snmp-trap'],
  [389, 'ldap'],
  [443, 'https'],
  [445, 'smb'],
  [465, 'smtps'],
  [500, 'isakmp'],
  [514, 'syslog'],
  [587, 'submission'],
  [636, 'ldaps'],
  [993, 'imaps'],
  [995, 'pop3s'],
  [1080, 'socks'],
  [1433, 'mssql'],
  [1521, 'oracle'],
  [1883, 'mqtt'],
  [1900, 'ssdp'],
  [3306, 'mysql'],
  [3389, 'rdp'],
  [5060, 'sip'],
  [5061, 'sips'],
  [5228, 'google-services'],
  [5353, 'mdns'],
  [5432, 'postgresql'],
  [5900, 'vnc'],
  [6379, 'redis'],
  [8080, 'http-alt'],
  [8443, 'https-alt'],
  [8888, 'http-proxy'],
  [9200, 'elasticsearch'],
  [27017, 'mongodb'],
]);

export function portService(port) {
  if (!Number.isInteger(port) || port < 0) return null;
  return COMMON_PORTS.get(port) ?? null;
}

export function isEphemeralPort(port) {
  return Number.isInteger(port) && port >= 32768 && port <= 60999;
}

/** 秒级时间戳 -> ISO 8601（确定性：不读取当前时间）。 */
export function isoTime(seconds) {
  if (!Number.isFinite(seconds)) return null;
  const ms = Math.round(seconds * 1000);
  try {
    return new Date(ms).toISOString();
  } catch {
    return null;
  }
}

/** 稳定排序：按 key 函数排序副本。 */
export function sortedCopy(items, keyFn) {
  return [...items].sort((a, b) => {
    const ka = keyFn(a);
    const kb = keyFn(b);
    if (ka < kb) return -1;
    if (ka > kb) return 1;
    return 0;
  });
}

/** Map -> 按 count 降序、键升序的数组。 */
export function mapToSortedEntries(map, limit = 100) {
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, limit);
}

export function increment(map, key, delta = 1) {
  map.set(key, (map.get(key) || 0) + delta);
}

export function hexOf(buf, maxBytes = 16) {
  if (!Buffer.isBuffer(buf)) return '';
  return buf.subarray(0, Math.min(buf.length, maxBytes)).toString('hex');
}

/** 计算分位数（用于间隔抖动判断），输入须已排序。 */
export function median(sorted) {
  if (!sorted || sorted.length === 0) return null;
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

export function mean(values) {
  if (!values || values.length === 0) return null;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

export function stdev(values) {
  if (!values || values.length < 2) return 0;
  const m = mean(values);
  const variance = values.reduce((acc, v) => acc + (v - m) * (v - m), 0) / values.length;
  return Math.sqrt(variance);
}
