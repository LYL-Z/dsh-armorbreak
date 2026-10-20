// ArmorBreak CTF domain — classical crypto heuristics.
//
// Everything here is a *heuristic*: letter-frequency log-likelihood + n-gram
// bonus scoring, Caesar brute force, single-byte XOR brute force, and index of
// coincidence. Candidates are labelled verification="hypothesis" and are never
// presented as a verified plaintext.

import {
  clampInt,
  clip,
  compact,
  finding,
  printableRatio,
  sortFindings,
} from './common.js';

// English letter frequencies (A-Z, %).
const ENGLISH_FREQ = [
  8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
  6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.36, 0.15, 1.974, 0.074,
];

const COMMON_NGRAMS = [
  'the', 'and', 'ing', 'her', 'ere', 'ent', 'tha', 'nth', 'was', 'eth', 'for', 'dth', 'hat',
  'she', 'ion', 'tio', 'ver', 'est', 'ers', 'thi', 'oth', 'all', 'not', 'hes', 'you', 'his',
  'wit', 'are', 'con', 'ter', 'men', 'res', 'per', 'pro', 'sta', 'day', 'tion', 'nthe', 'that',
  'ther', 'with', 'ment', 'here', 'ould', 'ight', 'have', 'hich', 'whic', 'this', 'atio',
  'ever', 'from', 'they', 'ting', 'inte', 'abou', 'eve', 'pre', 'com', 'one', 'now', 'him',
  'th ', 'he ', 'in ', 'er ', 'an ', 're ', 'on ', 'at ', 'en ', 'nd ', 'ti ', 'es ', 'or ',
  'te ', 'of ', 'ed ', 'is ', 'it ', 'al ', 'ar ', 'st ', 'to ', 'nt ', 'ng ', 'se ', 'ha ',
  'as ', 'ou ', 'io ', 'le ', 've ', 'co ', 'me ', 'de ', 'hi ', 'ri ', 'ro ', 'ic ', 'ne ',
  'ea ', 'ra ', 'ce ', 'li ', 'ch ', 'll ', 'be ', 'ma ', 'si ', 'om ', 'ur ',
];

const BIGRAMS = [
  'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd', 'ti', 'es', 'or', 'te', 'of',
  'ed', 'is', 'it', 'al', 'ar', 'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le',
  've', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea', 'ra', 'ce', 'li', 'ch', 'll',
  'be', 'ma', 'si', 'om', 'ur',
];

export { ENGLISH_FREQ };

/** Letters only (uppercase for frequency, lowercase for n-grams). */
function lettersOnly(text) {
  return String(text ?? '').replace(/[^A-Za-z]/g, '');
}

export function letterFrequency(text) {
  const letters = lettersOnly(text).toUpperCase();
  const counts = new Array(26).fill(0);
  for (const ch of letters) counts[ch.charCodeAt(0) - 65] += 1;
  const total = letters.length;
  return Array.from({ length: 26 }, (_, index) => ({
    letter: String.fromCharCode(65 + index),
    count: counts[index],
    percent: total ? Number(((counts[index] / total) * 100).toFixed(2)) : 0,
  }));
}

export function indexOfCoincidence(text) {
  const letters = lettersOnly(text).toUpperCase();
  const n = letters.length;
  if (n < 2) return { value: 0, interpretation: '样本太小，无法计算 IoC（需要 ≥2 个字母）' };
  const counts = new Map();
  for (const ch of letters) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let numerator = 0;
  for (const count of counts.values()) numerator += count * (count - 1);
  const value = Number((numerator / (n * (n - 1))).toFixed(4));
  let interpretation;
  if (value > 0.06) interpretation = '接近英文自然语言（~0.066），单表替换/凯撒类密码可能性较高';
  else if (value >= 0.045) interpretation = '介于英文与随机之间，可能是短文本或部分多表替换';
  else interpretation = '接近随机（~0.038），更可能是多表替换、异或或已压缩/加密数据';
  return { value, interpretation };
}

function countOccurrences(haystack, needle) {
  if (!needle) return 0;
  let count = 0;
  let index = 0;
  for (;;) {
    index = haystack.indexOf(needle, index);
    if (index < 0) break;
    count += 1;
    index += 1;
  }
  return count;
}

/**
 * English-likeness score (higher is more English-like; ~ -2.8 for English,
 * below ~ -4 for random bytes). Frequency log-likelihood + n-gram bonus.
 */
export function englishScore(text) {
  const letters = lettersOnly(text).toUpperCase();
  if (letters.length < 4) return -100;
  const counts = new Array(26).fill(0);
  for (const ch of letters) counts[ch.charCodeAt(0) - 65] += 1;
  let score = 0;
  for (let i = 0; i < 26; i += 1) {
    if (!counts[i]) continue;
    const observed = counts[i] / letters.length;
    const expected = ENGLISH_FREQ[i] / 100;
    score += observed * Math.log(expected);
  }
  const lower = letters.toLowerCase();
  let bonus = 0;
  for (const ngram of COMMON_NGRAMS) bonus += countOccurrences(lower, ngram.trim());
  for (const bigram of BIGRAMS) bonus += countOccurrences(lower, bigram) * 0.25;
  score += (bonus / letters.length) * 1.6;
  return Number(score.toFixed(4));
}

function shiftLetters(text, shift) {
  return String(text ?? '').replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(base + ((ch.charCodeAt(0) - base + shift + 26) % 26));
  });
}

/** Caesar brute force over shifts 1..25, sorted by English score. */
export function caesarCandidates(text, opts = {}) {
  const max = clampInt(opts.max, 5, 1, 25);
  const source = String(text ?? '');
  if (lettersOnly(source).length < 4) return { bestShift: null, candidates: [] };
  const candidates = [];
  for (let shift = 1; shift <= 25; shift += 1) {
    const decoded = shiftLetters(source, shift);
    candidates.push({
      shift,
      score: englishScore(decoded),
      preview: clip(compact(decoded, 120), 120),
    });
  }
  candidates.sort((a, b) => b.score - a.score || a.shift - b.shift);
  return { bestShift: candidates[0]?.shift ?? null, candidates: candidates.slice(0, max) };
}

/** Bonus for plaintext-like structure (flag format, spaces) used by XOR scoring. */
function textLikeness(text) {
  const source = String(text ?? '');
  let bonus = 0;
  if (/flag\{|ctf\{|htb\{|picoctf\{|flag_/i.test(source)) bonus += 3;
  const spaces = (source.match(/ /g) || []).length;
  bonus += Math.min(1.5, (spaces / Math.max(1, source.length)) * 6);
  if (/[a-z0-9]+_[a-z0-9_]+/i.test(source)) bonus += 0.5;
  return bonus;
}

/** Single-byte XOR brute force over 0..255, printable-ratio gated. */
export function xorCandidates(bytes, opts = {}) {
  const max = clampInt(opts.max, 5, 1, 10);
  const minPrintable = Number.isFinite(opts.minPrintable) ? opts.minPrintable : 0.85;
  if (!Buffer.isBuffer(bytes) || bytes.length < 4) return { bestKey: null, bestKeyHex: null, candidates: [] };
  const candidates = [];
  for (let key = 0; key <= 255; key += 1) {
    const out = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i += 1) out[i] = bytes[i] ^ key;
    const text = out.toString('latin1');
    const printable = printableRatio(text);
    if (printable < minPrintable) continue;
    const score = englishScore(text) + printable * 2 + textLikeness(text);
    candidates.push({
      key,
      keyHex: `0x${key.toString(16).padStart(2, '0')}`,
      printable: Number(printable.toFixed(3)),
      score: Number(score.toFixed(4)),
      preview: clip(compact(text, 120), 120),
    });
  }
  candidates.sort((a, b) => b.score - a.score || a.key - b.key);
  return {
    bestKey: candidates[0]?.key ?? null,
    bestKeyHex: candidates[0]?.keyHex ?? null,
    candidates: candidates.slice(0, max),
  };
}

/** Decode the user's ciphertext input (hex/base64/raw) into bytes for XOR. */
export function decodeCiphertextInput(text, encoding = 'auto') {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) return { bytes: Buffer.alloc(0), encoding: 'raw' };
  const cleaned = trimmed.replace(/\s+/g, '');
  if (encoding === 'hex' || (encoding === 'auto' && cleaned.length >= 8 && cleaned.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleaned))) {
    return { bytes: Buffer.from(cleaned, 'hex'), encoding: 'hex' };
  }
  if (
    encoding === 'base64' ||
    (encoding === 'auto' &&
      cleaned.length >= 8 &&
      cleaned.length % 4 === 0 &&
      /^[A-Za-z0-9+/]+={0,2}$/.test(cleaned) &&
      (/[0-9+/=]/.test(cleaned) || (/[a-z]/.test(cleaned) && /[A-Z]/.test(cleaned))))
  ) {
    return { bytes: Buffer.from(cleaned, 'base64'), encoding: 'base64' };
  }
  return { bytes: Buffer.from(trimmed, 'utf8'), encoding: 'raw' };
}

/**
 * Run the classical-crypto heuristics.
 * @param {{text:string, bytes:Buffer, encoding?:string, maxCandidates?:number}} input
 * @returns {{summary:string, findings:object[], data:object, evidence:object[]}}
 */
export function analyzeClassical(input) {
  const rawText = typeof input.text === 'string' ? input.text : '';
  const buffer = Buffer.isBuffer(input.bytes) ? input.bytes : Buffer.from(rawText, 'utf8');
  const encoding = input.encoding === 'hex' || input.encoding === 'base64' || input.encoding === 'raw' ? input.encoding : 'auto';
  const maxCandidates = clampInt(input.maxCandidates, 5, 1, 10);
  const sourceText = rawText.trim() ? rawText : buffer.toString('latin1');
  const { bytes: cipherBytes, encoding: usedEncoding } = decodeCiphertextInput(sourceText, encoding);

  const frequency = letterFrequency(sourceText);
  const ioc = indexOfCoincidence(sourceText);
  const caesar = caesarCandidates(sourceText, { max: maxCandidates });
  const letters = lettersOnly(sourceText).length;
  // XOR brute force applies to encoded/binary ciphertext. Skip it for prose-like
  // input (e.g. a Caesar ciphertext) to avoid reporting meaningless XOR hits.
  const proseLike =
    usedEncoding === 'raw' &&
    letters >= 8 &&
    /^[A-Za-z0-9 .,;:'"!?()\-_/\n\\]+$/.test(sourceText) &&
    letters / Math.max(1, sourceText.length) > 0.5;
  const xor = proseLike
    ? { bestKey: null, bestKeyHex: null, candidates: [] }
    : xorCandidates(cipherBytes, { max: maxCandidates });
  const xorSkipped = proseLike ? '输入近似自然语言文本（未编码），XOR 暴力破解只在 hex/base64/二进制密文上有效' : null;

  const findings = [];
  if (caesar.candidates.length) {
    const best = caesar.candidates[0];
    findings.push(
      finding({
        title: `[ctf-caesar] Caesar 暴力破解最佳位移 ROT${best.shift}（启发式评分）`,
        severity: 'info',
        description:
          `对 ${letters} 个字母做 1-25 位移暴力破解，按英文字母频率对数似然 + 常见 n-gram 加分排序，` +
          `最佳候选为 ROT${best.shift}（score=${best.score}）。候选预览：${best.preview}。` +
          ' 该结果只是统计评分排序，不构成明文确认；需要人工阅读或结合题目提示判断。',
        verification: 'hypothesis',
        method: 'caesar-bruteforce-frequency-scoring',
        cwe: null,
        remediation: '人工核对候选明文；若文本包含空格/标点，优先看可读性最高的 2-3 个候选。',
        target: `ROT${best.shift}`,
        evidence: [
          {
            title: `ROT${best.shift} 候选`,
            excerpt: clip(best.preview, 400),
          },
        ],
      }),
    );
  }
  if (xor.candidates.length) {
    const best = xor.candidates[0];
    findings.push(
      finding({
        title: `[ctf-xor] 单字节 XOR 最佳密钥 ${best.keyHex}（启发式评分）`,
        severity: 'info',
        description:
          `对 ${cipherBytes.length} 字节密文（输入按 ${usedEncoding} 解析）暴力尝试 0-255 单字节密钥，` +
          `以可打印比例 ≥0.85 过滤后按英文评分排序，最佳候选 key=${best.keyHex}（printable=${best.printable}, score=${best.score}）。` +
          ` 候选预览：${best.preview}。该结果只是统计评分排序，需人工确认。`,
        verification: 'hypothesis',
        method: 'single-byte-xor-bruteforce-scoring',
        cwe: null,
        remediation: '人工核对候选明文；若首行像英文但尾部乱码，可能是多字节 XOR 或异或了不同密钥。',
        target: `key=${best.keyHex}`,
        evidence: [{ title: `XOR ${best.keyHex} 候选`, excerpt: clip(best.preview, 400) }],
      }),
    );
  }

  const data = {
    textLength: sourceText.length,
    letterCount: letters,
    ciphertextEncoding: usedEncoding,
    ciphertextBytes: cipherBytes.length,
    frequency,
    indexOfCoincidence: ioc,
    caesar,
    xor,
    xorSkipped,
    disclaimer:
      '本能力为古典密码启发式分析：评分基于英文字母频率与常见 n-gram，不保证正确；所有候选均为 hypothesis，请人工验证。',
  };

  const summary = compact(
    `古典密码启发式分析：${sourceText.length} 字符 / ${letters} 个字母，IoC=${ioc.value}（${ioc.interpretation}）；` +
      (caesar.candidates.length ? `Caesar 最佳 ROT${caesar.candidates[0].shift}；` : 'Caesar 无候选；') +
      (xor.candidates.length
        ? `单字节 XOR 最佳 ${xor.candidates[0].keyHex}。`
        : xorSkipped
          ? '已跳过单字节 XOR（输入为普通文本）。'
          : '单字节 XOR 无通过可打印阈值的候选。') +
      ' 结果均为统计启发式，需人工确认。',
    4000,
  );

  return {
    summary,
    findings: sortFindings(findings),
    data,
    evidence: [
      {
        title: '频率与 IoC 摘要',
        kind: 'classical-crypto-analysis',
        excerpt: compact(
          [
            `letters=${letters} ioc=${ioc.value} (${ioc.interpretation})`,
            `topLetters=${frequency
              .slice()
              .sort((a, b) => b.count - a.count || (a.letter < b.letter ? -1 : 1))
              .slice(0, 8)
              .map((f) => `${f.letter}:${f.count}`)
              .join(', ')}`,
            `caesarBest=${caesar.candidates[0]?.shift ?? 'none'} xorBest=${xor.candidates[0]?.keyHex ?? 'none'}`,
          ].join('\n'),
          2000,
        ),
        meta: { ioc: ioc.value, encoding: usedEncoding },
      },
    ],
  };
}
