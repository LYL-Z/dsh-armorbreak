// ArmorBreak CTF domain — flag regex scanning + entropy anomaly candidates.
//
// Purely offline pattern/entropy analysis. Flag matches are reported as
// verification="observed" (the string was observed); entropy anomalies are
// labelled heuristic and never presented as a decoded secret.

import {
  asciiStrings,
  clampInt,
  clip,
  finding,
  isPrintableText,
  shannonEntropy,
} from './common.js';

export const FLAG_PATTERNS = Object.freeze([
  { id: 'flag-brace', label: 'flag{...}', regex: /(?:flag|FLAG|Flag)\{[^}\n]{1,200}\}/g },
  { id: 'ctf-brace', label: 'CTF{...}', regex: /\bCTF\{[^}\n]{1,200}\}/gi },
  { id: 'picoctf', label: 'picoCTF{...}', regex: /picoCTF\{[^}\n]{1,200}\}/g },
  { id: 'htb', label: 'HTB{...}', regex: /\bHTB\{[^}\n]{1,200}\}/g },
  { id: 'generic-brace', label: '<tag>{...}', regex: /\b[A-Za-z][A-Za-z0-9_]{1,24}\{[^}\n]{1,200}\}/g },
  { id: 'flag-underscore', label: 'flag_xxx', regex: /\bflag_[A-Za-z0-9_]{6,80}\b/gi },
]);

/**
 * Find flag-shaped strings in text.
 * @returns {{flag:string, patternId:string, offset:number}[]}
 */
export function scanFlagsInText(text, opts = {}) {
  const maxItems = clampInt(opts.maxItems, 50, 1, 500);
  const source = String(text ?? '');
  if (!source) return [];
  const out = [];
  const seen = new Set();
  for (const pattern of FLAG_PATTERNS) {
    if (out.length >= maxItems) break;
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(source)) !== null) {
      if (!match[0].length) {
        pattern.regex.lastIndex += 1;
        continue;
      }
      const flag = match[0];
      if (seen.has(flag)) continue;
      seen.add(flag);
      out.push({ flag: clip(flag, 300), patternId: pattern.id, offset: match.index });
      if (out.length >= maxItems) break;
    }
  }
  return out.sort((a, b) => a.offset - b.offset);
}

/** Find flag-shaped strings inside a binary buffer (printable ASCII runs). */
export function scanFlagsInBuffer(buffer, opts = {}) {
  const maxItems = clampInt(opts.maxItems, 50, 1, 500);
  const found = [];
  const seen = new Set();
  for (const candidate of asciiStrings(buffer, { minLength: 4, maxItems: 500 })) {
    for (const hit of scanFlagsInText(candidate.text, { maxItems })) {
      if (seen.has(hit.flag)) continue;
      seen.add(hit.flag);
      found.push({ ...hit, offset: candidate.offset + hit.offset });
      if (found.length >= maxItems) return found;
    }
  }
  return found;
}

/** Scan whatever input we have: text first, then binary ASCII runs. */
export function scanFlagsArtifact(artifact, opts = {}) {
  const fromText = artifact.text && isPrintableText(artifact.text, 0.4) ? scanFlagsInText(artifact.text, opts) : [];
  const fromBuffer = scanFlagsInBuffer(artifact.bytes, opts);
  const seen = new Set();
  const merged = [];
  for (const hit of [...fromText, ...fromBuffer]) {
    if (seen.has(hit.flag)) continue;
    seen.add(hit.flag);
    merged.push(hit);
  }
  return merged.sort((a, b) => a.offset - b.offset);
}

/**
 * High-entropy tokens (possible encoded/encrypted payload), bounded + deduped.
 */
export function findEntropyCandidates(text, opts = {}) {
  const minEntropy = Number.isFinite(opts.minEntropy) ? opts.minEntropy : 3.6;
  const minLength = clampInt(opts.minLength, 24, 8, 4096);
  const maxItems = clampInt(opts.maxItems, 20, 1, 200);
  const source = String(text ?? '');
  if (!source) return [];
  const regex = new RegExp(`[A-Za-z0-9+/=_-]{${minLength},}`, 'g');
  const out = [];
  const seen = new Set();
  let match;
  while ((match = regex.exec(source)) !== null) {
    if (!match[0].length) {
      regex.lastIndex += 1;
      continue;
    }
    const token = match[0];
    if (seen.has(token)) continue;
    seen.add(token);
    const entropy = Number(shannonEntropy(token).toFixed(3));
    if (entropy < minEntropy) continue;
    out.push({
      value: clip(token, 120),
      length: token.length,
      entropy,
      offset: match.index,
      note: '高熵 token，可能是编码/加密数据或随机密钥；需进一步解码验证',
    });
    if (out.length >= maxItems) break;
  }
  return out.sort((a, b) => b.entropy - a.entropy || a.offset - b.offset);
}

/** Build info findings for discovered flags (never severity above info). */
export function flagFindings(flags, method = 'regex-flag-scan') {
  return flags.map((hit) =>
    finding({
      title: `[ctf-flag] 发现 flag（${hit.patternId}）`,
      severity: 'info',
      description:
        `在输入偏移 ${hit.offset} 处匹配到 flag 形态字符串：${hit.flag}。` +
        ' 该结果是正则匹配的直接观察，不保证是题目要求的最终 flag（大小写/格式以题目为准）。',
      verification: 'observed',
      method,
      cwe: null,
      remediation: '提交前确认 flag 未被公开泄露；本能力只做离线识别。',
      target: `offset ${hit.offset}`,
      evidence: [{ title: hit.patternId, excerpt: hit.flag }],
    }),
  );
}
