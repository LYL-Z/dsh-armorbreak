// ArmorBreak CTF domain — hash / digest format identification.
//
// Identification is by length + charset + well-known prefixes only. Every
// candidate carries an explicit confidence; ambiguity is surfaced instead of
// guessing a single algorithm.

import { clampInt, clip, compact, finding } from './common.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-fA-F]+$/;
const BASE64ISH_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const CRYPT_RE = /^\$[A-Za-z0-9]+\$[./A-Za-z0-9$]{6,}$/;

function charsetOf(value) {
  if (UUID_RE.test(value)) return 'uuid';
  if (CRYPT_RE.test(value)) return 'crypt-format';
  if (HEX_RE.test(value)) return 'hex';
  if (BASE64ISH_RE.test(value)) return 'base64';
  if (/^[A-Za-z0-9]+$/.test(value)) return 'alnum';
  return 'other';
}

/**
 * Identify a hash-like token.
 * @returns {{token:string, length:number, charset:string, candidates:{algorithm:string,confidence:string,note:string}[], notes:string[]}}
 */
export function identifyHashToken(token) {
  const value = String(token ?? '').trim();
  const result = { token: clip(value, 300), length: value.length, charset: charsetOf(value), candidates: [], notes: [] };
  if (!value) {
    result.notes.push('空 token，无法识别');
    return result;
  }
  const add = (algorithm, confidence, note) => result.candidates.push({ algorithm, confidence, note });

  if (/^\$2[abxy]\$\d{2}\$/.test(value)) {
    const validLength = value.length === 60;
    add(
      'bcrypt',
      validLength ? 'likely' : 'possible',
      validLength
        ? 'bcrypt 格式（$2a/$2b/$2x/$2y + cost + 53 字符），不可直接逆向'
        : `bcrypt 前缀匹配，但总长度 ${value.length} 不是标准 60（可能被截断/复制不完整）`,
    );
    return result;
  }
  if (/^\$argon2(?:id|i|d)\$/.test(value)) {
    add('argon2', 'likely', 'Argon2 密码哈希格式（$argon2id/i/d）');
    return result;
  }
  if (/^\$6\$/.test(value)) {
    add('sha512crypt', 'likely', 'Unix crypt SHA-512（$6$）');
    return result;
  }
  if (/^\$5\$/.test(value)) {
    add('sha256crypt', 'likely', 'Unix crypt SHA-256（$5$）');
    return result;
  }
  if (/^\$1\$/.test(value)) {
    add('md5crypt', 'likely', 'Unix crypt MD5（$1$）');
    return result;
  }
  if (/^\$apr1\$/.test(value)) {
    add('apr1-md5', 'likely', 'Apache APR1 MD5 哈希（$apr1$）');
    return result;
  }
  if (/^\*[0-9A-Fa-f]{40}$/.test(value)) {
    add('mysql41', 'likely', 'MySQL 4.1+ 密码哈希（* + SHA1(SHA1(密码))）');
    return result;
  }
  if (UUID_RE.test(value)) {
    add('uuid', 'likely', 'UUID 标识符，不是哈希（无逆向价值，仅定位用）');
    return result;
  }
  if (/^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/.test(value)) {
    add('jwt', 'likely', 'JWT（点分三段 Base64URL），不是哈希');
    return result;
  }

  if (HEX_RE.test(value)) {
    switch (value.length) {
      case 8:
        add('crc32', 'possible', '8 位十六进制可能是 CRC32 校验值（非加密哈希）');
        add('other-32bit', 'possible', '也可能是截断的 32 位哈希/16 位两字节拼接');
        break;
      case 16:
        add('mysql323', 'possible', 'MySQL 3.23 旧密码哈希为 16 位十六进制');
        add('truncated-md5', 'possible', '可能是截断的 MD5（仅 16 位十六进制）');
        break;
      case 32:
        add('md5', 'likely', '32 位十六进制最常见的算法是 MD5（128-bit）');
        add('ntlm', 'possible', 'Windows NTLM 哈希同样为 32 位十六进制，无法仅凭格式区分');
        add('md4', 'possible', '同长度也可能是 MD4');
        break;
      case 40:
        add('sha1', 'likely', '40 位十六进制最常见的算法是 SHA-1（160-bit）');
        add('ripemd160', 'possible', 'RIPEMD-160 同为 40 位十六进制');
        break;
      case 56:
        add('sha224', 'likely', '56 位十六进制对应 SHA-224');
        add('sha3-224', 'possible', '也可能是 SHA3-224');
        break;
      case 64:
        add('sha256', 'likely', '64 位十六进制最常见的算法是 SHA-256');
        add('sha3-256', 'possible', '也可能是 SHA3-256 / Keccak-256');
        add('blake2b-256', 'possible', '也可能是 BLAKE2b-256');
        break;
      case 96:
        add('sha384', 'likely', '96 位十六进制对应 SHA-384');
        add('sha3-384', 'possible', '也可能是 SHA3-384');
        break;
      case 128:
        add('sha512', 'likely', '128 位十六进制对应 SHA-512');
        add('sha3-512', 'possible', '也可能是 SHA3-512');
        add('whirlpool', 'possible', 'Whirlpool 同为 128 位十六进制');
        break;
      default:
        result.notes.push(`十六进制串长度 ${value.length} 不对应常见摘要算法，可能是拼接/截断数据`);
        add('unknown-hex', 'unlikely', '长度不匹配常见哈希算法');
    }
    return result;
  }

  if (BASE64ISH_RE.test(value)) {
    const remainder = value.replace(/=+$/, '').length % 4;
    let decodedBytes = 0;
    try {
      decodedBytes = Buffer.from(value, 'base64').length;
    } catch {
      decodedBytes = 0;
    }
    result.notes.push('Base64 字符集且非十六进制：可能是 Base64 编码的摘要或其它数据');
    if ([16, 20, 28, 32, 48, 64].includes(decodedBytes)) {
      const mapping = {
        16: ['md5-base64', '128-bit 摘要的 Base64'],
        20: ['sha1-base64', '160-bit 摘要的 Base64'],
        28: ['sha224-base64', '224-bit 摘要的 Base64'],
        32: ['sha256-base64', '256-bit 摘要的 Base64'],
        48: ['sha384-base64', '384-bit 摘要的 Base64'],
        64: ['sha512-base64', '512-bit 摘要的 Base64'],
      };
      add(mapping[decodedBytes][0], 'possible', `${mapping[decodedBytes][1]}（解码后 ${decodedBytes} 字节）`);
    } else {
      add('base64-data', 'unlikely', `Base64 解码后 ${decodedBytes} 字节，不符合常见摘要长度`);
    }
    if (remainder) result.notes.push('Base64 长度不是 4 的倍数（缺少 padding？）');
    return result;
  }

  result.notes.push(`无法识别的字符集/格式（长度 ${value.length}），不是常见哈希形态`);
  return result;
}

const CRYPT_TOKEN_RE = /\$[A-Za-z0-9]+\$[./A-Za-z0-9$]{6,}/;
const HASH_TOKEN_RES = [
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
  /\b[0-9a-fA-F]{8,128}\b/g,
  /\b[A-Za-z0-9+/]{20,}={0,2}\b/g,
];

/** Extract hash-like tokens from free-form text. */
export function extractHashCandidates(text, opts = {}) {
  const maxItems = clampInt(opts.maxItems, 50, 1, 500);
  const source = String(text ?? '');
  if (!source.trim()) return [];
  const lines = source.split('\n').map((line) => line.trim()).filter(Boolean);
  const out = [];
  const seen = new Set();
  const add = (token) => {
    if (!token || seen.has(token)) return;
    seen.add(token);
    out.push(token);
  };
  if (lines.length === 1 && /^\S{8,300}$/.test(lines[0])) {
    add(lines[0]);
    return out.slice(0, maxItems);
  }
  for (const line of lines) {
    // Crypt-format hashes ($2b$12$..., $6$..., etc.) contain substrings that
    // other regexes would mis-split; handle them first and skip the rest.
    const cryptMatch = CRYPT_TOKEN_RE.exec(line);
    if (cryptMatch) {
      add(cryptMatch[0]);
      continue;
    }
    for (const regex of HASH_TOKEN_RES) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(line)) !== null) {
        if (match[0].length >= 8) add(match[0]);
        if (out.length >= maxItems) return out;
      }
    }
    if (out.length >= maxItems) return out;
  }
  return out.slice(0, maxItems);
}

/** Identify every hash-like token in the text. */
export function analyzeHashes(text, opts = {}) {
  const tokens = extractHashCandidates(text, opts);
  const hashes = tokens.map((token) => identifyHashToken(token));
  const confidentlyIdentified = hashes.filter((hash) =>
    hash.candidates.some((candidate) => candidate.confidence === 'likely'),
  );

  const data = {
    hashCount: hashes.length,
    confidentCount: confidentlyIdentified.length,
    hashes,
    disclaimer:
      '哈希识别仅依据长度/字符集/前缀，多个算法可能同构（如 MD5 与 NTLM）；confidence 表示格式匹配程度，不代表已破解。',
  };

  const findings = [];
  if (hashes.length) {
    const summaryParts = hashes.slice(0, 8).map((hash) => {
      const likely = hash.candidates.find((candidate) => candidate.confidence === 'likely');
      return `${clip(hash.token, 40)} → ${likely ? likely.algorithm : hash.candidates[0]?.algorithm ?? 'unknown'}`;
    });
    findings.push(
      finding({
        title: `[ctf-hash-id] 识别到 ${hashes.length} 个哈希/摘要候选（启发式）`,
        severity: 'info',
        description:
          `按长度与字符集识别：${summaryParts.join('；')}${hashes.length > 8 ? ' 等' : ''}。` +
          ' 同长度算法无法仅凭格式区分（confidence 为 likely/possible/unlikely），请结合上下文确认。',
        verification: 'hypothesis',
        method: 'hash-length-charset-prefix-identification',
        cwe: null,
        remediation: '结合题目/来源确认算法；口令哈希使用 hashcat 对应模式破解前先核对格式。',
        target: hashes[0].token.slice(0, 80),
        evidence: [
          {
            title: '哈希识别候选（前 8）',
            excerpt: compact(
              hashes
                .slice(0, 8)
                .map(
                  (hash) =>
                    `${hash.token} (len=${hash.length}, charset=${hash.charset}) → ` +
                    hash.candidates.map((c) => `${c.algorithm}:${c.confidence}`).join(', '),
                )
                .join('\n'),
              2000,
            ),
          },
        ],
      }),
    );
  }

  return {
    summary: compact(
      `哈希/摘要识别：在输入中找到 ${hashes.length} 个候选（高置信 ${confidentlyIdentified.length} 个）。` +
        (hashes.length
          ? ` 首个候选：${clip(hashes[0].token, 40)} → ${hashes[0].candidates.map((c) => `${c.algorithm}(${c.confidence})`).join(' / ') || 'unknown'}。`
          : ' 未发现符合常见哈希形态的字符串。') +
        ' 识别结果仅为格式匹配（hypothesis），不代表已破解。',
      4000,
    ),
    findings,
    data,
    evidence: [
      {
        title: '哈希识别摘要',
        kind: 'hash-identification',
        excerpt: compact(
          hashes
            .slice(0, 20)
            .map(
              (hash) =>
                `${hash.token} len=${hash.length} charset=${hash.charset} candidates=${hash.candidates
                  .map((c) => `${c.algorithm}:${c.confidence}`)
                  .join(',')}`,
            )
            .join('\n') || '(no hash-like tokens)',
          2000,
        ),
      },
    ],
  };
}
