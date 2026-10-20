/**
 * Forensics — "yara_lite": a declarative, bundled, string/condition rule matcher.
 * Deliberately simple and clearly labeled as heuristics: no regex engine in rules,
 * no bytecode, no external YARA dependency. Results are hypotheses for triage only.
 */

const RULESET = {
  name: 'armorbreak-yara-lite',
  version: '1.0.0',
  note: '内置声明式字符串规则集（启发式，非 YARA 兼容格式）；命中仅表示静态字符串特征，需人工复核。',
};

const S = (value, type = 'ascii', id = null) => ({ id: id || value, value, type });

export const RULES = Object.freeze([
  {
    id: 'upx-packer',
    name: 'UPX 加壳特征',
    severity: 'info',
    tags: ['packer', 'upx'],
    description: '同时出现 UPX0/UPX1/UPX! 等节名标记，典型 UPX 加壳样本特征。',
    strings: [S('UPX0'), S('UPX1'), S('UPX!')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'powershell-execution',
    name: 'PowerShell 下载/执行片段',
    severity: 'high',
    tags: ['execution', 'powershell'],
    description: '出现 PowerShell 调用与编码/下载/反射执行片段（-enc、DownloadString、IEX 等）。',
    strings: [S('powershell', 'nocase'), S('Invoke-Expression', 'nocase'), S('DownloadString', 'nocase'), S('-EncodedCommand', 'nocase'), S('FromBase64String', 'nocase')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'process-injection-apis',
    name: '进程注入 API 组合',
    severity: 'medium',
    tags: ['injection'],
    description: '同时出现远程内存分配/写入/远程线程等 API 名称组合，常见于进程注入实现。',
    strings: [S('VirtualAllocEx'), S('WriteProcessMemory'), S('CreateRemoteThread'), S('NtCreateThreadEx'), S('QueueUserAPC')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'anti-debug-apis',
    name: '反调试 API 组合',
    severity: 'low',
    tags: ['anti-analysis'],
    description: '出现 IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess 等反调试 API 组合。',
    strings: [S('IsDebuggerPresent'), S('CheckRemoteDebuggerPresent'), S('NtQueryInformationProcess'), S('OutputDebugString')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'persistence-run-key',
    name: '注册表自启动键',
    severity: 'medium',
    tags: ['persistence', 'registry'],
    description: '出现 CurrentVersion\\Run 自启动注册表路径或写入 API。',
    strings: [S('CurrentVersion\\Run', 'nocase'), S('RunOnce', 'nocase'), S('RegSetValueEx', 'nocase')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'credential-dumping',
    name: '凭据窃取工具/内存转储特征',
    severity: 'high',
    tags: ['credential-access'],
    description: '出现 mimikatz/sekurlsa/lsass/MiniDumpWriteDump 等凭据窃取与内存转储特征。',
    strings: [S('mimikatz', 'nocase'), S('sekurlsa', 'nocase'), S('lsass', 'nocase'), S('MiniDumpWriteDump', 'nocase'), S('wdigest', 'nocase')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'ransomware-indicators',
    name: '勒索软件文案/扩展名特征',
    severity: 'medium',
    tags: ['ransomware'],
    description: '出现勒索信高频措辞、加密扩展名或赎金相关词组合。',
    strings: [
      S('your files have been encrypted', 'nocase'),
      S('your files are encrypted', 'nocase'),
      S('recover your files', 'nocase'),
      S('.locked', 'nocase'),
      S('bitcoin', 'nocase'),
      S('decrypt', 'nocase'),
      S('payment', 'nocase'),
    ],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'crypto-algorithm-markers',
    name: '加密算法标识组合',
    severity: 'low',
    tags: ['crypto'],
    description: '出现多个加密算法/模式名称（常见于正常软件，也可能是勒索/通信加密实现）。',
    strings: [S('AES-256'), S('AES-128'), S('ChaCha20'), S('RSA-2048'), S('RSA'), S('CryptoAPI'), S('libcrypto')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'suspicious-network-markers',
    name: '硬编码网络通信标记',
    severity: 'info',
    tags: ['network'],
    description: '同时出现 URL 与 User-Agent/HTTP 头标记，可能为回连或正常联网功能。',
    strings: [S('http://', 'nocase'), S('https://', 'nocase'), S('User-Agent:', 'nocase'), S('Content-Type:', 'nocase'), S('Host:', 'nocase')],
    condition: { kind: 'count', min: 2 },
  },
  {
    id: 'pdb-path',
    name: 'PDB 调试路径',
    severity: 'info',
    tags: ['debug-info'],
    description: '包含 .pdb 调试符号路径，可能泄露构建环境信息（正常发布软件也可能保留）。',
    strings: [S('.pdb', 'nocase')],
    condition: { kind: 'count', min: 1 },
  },
  {
    id: 'pe-overlay-marker',
    name: '自解压/安装器标记',
    severity: 'info',
    tags: ['packaging'],
    description: '同时出现自解压/安装器相关标记字符串。',
    strings: [S('WinRAR SFX', 'nocase'), S('7-Zip SFX', 'nocase'), S('NSIS', 'nocase'), S('Inno Setup', 'nocase'), S('This installation was built with')],
    condition: { kind: 'count', min: 1 },
  },
  {
    id: 'base64-blob-marker',
    name: '长 Base64 载荷标记',
    severity: 'low',
    tags: ['obfuscation'],
    description: '出现典型长 Base64 载荷标记（如 base64,fromBase64）或大段 base64 特征词。',
    strings: [S('base64', 'nocase'), S('FromBase64', 'nocase'), S('atob('), S('btoa(')],
    condition: { kind: 'count', min: 2 },
  },
]);

const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));

function findAscii(haystack, haystackLower, needle, nocase, maxHits = 8) {
  const offsets = [];
  const target = nocase ? needle.toLowerCase() : needle;
  const source = nocase ? haystackLower : haystack;
  let pos = 0;
  let guard = 0;
  while (guard < maxHits) {
    guard += 1;
    const idx = source.indexOf(target, pos);
    if (idx === -1) break;
    offsets.push(idx);
    pos = idx + Math.max(1, target.length);
  }
  return offsets;
}

function findWide(buffer, needle, maxHits = 8) {
  const wide = Buffer.from(needle, 'utf16le');
  const offsets = [];
  let pos = 0;
  let guard = 0;
  while (guard < maxHits) {
    guard += 1;
    const idx = buffer.indexOf(wide, pos);
    if (idx === -1) break;
    offsets.push(idx);
    pos = idx + Math.max(1, wide.length);
  }
  return offsets;
}

function evaluateCondition(condition, hitsByStringId) {
  const ids = condition && Array.isArray(condition.strings) ? condition.strings : null;
  const usable = ids ? ids.filter((id) => hitsByStringId.has(id)) : [...hitsByStringId.keys()];
  const hitCount = usable.filter((id) => {
    const hit = hitsByStringId.get(id);
    return hit.offsets.length > 0 || (hit.wideOffsets && hit.wideOffsets.length > 0);
  }).length;
  const kind = condition ? condition.kind : 'any';
  if (kind === 'all') return { matched: usable.length > 0 && hitCount === usable.length, hitCount, required: usable.length, kind };
  if (kind === 'count') {
    const min = Math.max(1, Number(condition && condition.min) || 1);
    return { matched: hitCount >= min, hitCount, required: min, kind };
  }
  return { matched: hitCount >= 1, hitCount, required: 1, kind: 'any' };
}

/**
 * Run the bundled ruleset over bytes.
 * @param {Buffer} buffer
 * @param {{ruleIds?:string[], maxRuleMatches?:number}} options
 */
export function runYaraLite(buffer, options = {}) {
  const selected = Array.isArray(options.ruleIds) && options.ruleIds.length > 0
    ? [...new Set(options.ruleIds)].filter((id) => RULE_BY_ID.has(id))
    : RULES.map((r) => r.id);
  if (Array.isArray(options.ruleIds) && options.ruleIds.length > 0 && selected.length === 0) {
    throw new Error(`forensics.yara_lite: options.ruleIds 全部无效。可用规则 id: ${RULES.map((r) => r.id).join(', ')}。`);
  }
  const maxRuleMatches = Math.max(1, Math.min(RULES.length, Number.isFinite(options.maxRuleMatches) ? Math.floor(options.maxRuleMatches) : RULES.length));
  const scanCap = Math.min(buffer.length, 8 * 1024 * 1024);
  const scan = buffer.subarray(0, scanCap);
  const ascii = scan.toString('latin1');
  const asciiLower = ascii.toLowerCase();
  const warnings = [];
  if (buffer.length > scanCap) warnings.push(`仅扫描前 ${scanCap} 字节（文件 ${buffer.length} 字节），结果可能不完整。`);
  const matchedRules = [];
  for (const ruleId of selected) {
    const rule = RULE_BY_ID.get(ruleId);
    const hitsByStringId = new Map();
    for (const str of rule.strings) {
      const offsets = str.type === 'wide'
        ? findWide(scan, str.value)
        : findAscii(ascii, asciiLower, str.value, str.type === 'nocase');
      hitsByStringId.set(str.id, {
        id: str.id,
        value: str.value,
        type: str.type,
        offsets,
        wideOffsets: str.type === 'wide' ? offsets : findWide(scan, str.value),
      });
    }
    const evaluation = evaluateCondition(rule.condition, hitsByStringId);
    if (!evaluation.matched) continue;
    const matchedStrings = [...hitsByStringId.values()]
      .filter((h) => h.offsets.length > 0 || (h.wideOffsets && h.wideOffsets.length > 0))
      .map((h) => {
        const asciiOffsets = h.offsets;
        const wideOffsets = h.wideOffsets || [];
        const primary = asciiOffsets.length > 0 ? asciiOffsets : wideOffsets;
        return {
          id: h.id,
          value: h.value,
          type: h.type,
          hitCount: asciiOffsets.length + wideOffsets.length,
          firstOffsets: primary.slice(0, 5),
          ...(asciiOffsets.length > 0 && wideOffsets.length > 0 ? { wideFirstOffsets: wideOffsets.slice(0, 3) } : {}),
          ...(asciiOffsets.length === 0 && wideOffsets.length > 0 ? { matchedEncoding: 'utf16le' } : {}),
        };
      });
    matchedRules.push({
      ruleId: rule.id,
      name: rule.name,
      severity: rule.severity,
      tags: rule.tags,
      description: rule.description,
      condition: { kind: evaluation.kind, required: evaluation.required, hitCount: evaluation.hitCount, strings: rule.condition.strings || null },
      matchedStrings,
      verification: 'hypothesis',
    });
    if (matchedRules.length >= maxRuleMatches) break;
  }
  return {
    data: {
      ruleset: { ...RULESET, ruleCount: RULES.length, selectedRuleCount: selected.length },
      scannedBytes: scanCap,
      truncated: buffer.length > scanCap,
      matchedCount: matchedRules.length,
      matchedRules,
      notes: [
        '规则为内置声明式字符串匹配（启发式），不包含 YARA 语法/字节码；命中等价于 hypothesis，需人工复核。',
        '大小写敏感规则默认区分大小写（nocase 规则除外）；同时检查 ASCII 与 UTF-16LE 编码。',
      ],
    },
    warnings,
  };
}

/** Extract a byte excerpt around a matched offset for evidence (sanitized, bounded). */
export function excerptAt(buffer, offset, radius = 48) {
  const start = Math.max(0, offset - radius);
  const end = Math.min(buffer.length, offset + radius);
  const raw = buffer.subarray(start, end);
  const text = raw.toString('latin1').replace(/[^\x20-\x7e\n\t]/g, '.');
  return text.length > 200 ? text.slice(0, 200) : text;
}

export { RULE_BY_ID };
