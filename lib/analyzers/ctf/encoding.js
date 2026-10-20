// ArmorBreak CTF domain — bounded encoding/compression transform chain.
//
// Every transform works on a Buffer state; textual transforms require valid
// UTF-8 text (actionable error otherwise). Chains are capped by maxDepth and
// maxBytes; intermediates are returned as previews so nothing huge leaks out.

import { gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';
import {
  clampInt,
  compact,
  hexDump,
  isPrintableText,
  previewText,
  printableRatio,
  shannonEntropy,
} from './common.js';
import { scanFlagsInText } from './flagscan.js';

function makeState(bytes) {
  return { bytes };
}

function utf8Text(bytes) {
  const text = bytes.toString('utf8');
  return Buffer.from(text, 'utf8').equals(bytes) ? text : null;
}

function requireUtf8Text(state, name) {
  const text = utf8Text(state.bytes);
  if (text === null) {
    throw new Error(
      `${name} 需要 UTF-8 文本数据，但当前数据是二进制（${state.bytes.length} 字节，起始 hex: ${hexDump(state.bytes, 16)}）。` +
        ' 请先做 hex/base64/解压等变换，或确认输入编码。',
    );
  }
  if (!text.trim()) throw new Error(`${name} 的输入文本为空，无法解码。`);
  return text;
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const MORSE_TABLE = Object.freeze({
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
  '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
  '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
  '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
  '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.', '--..--': ',',
  '..--..': '?', '.----.': "'", '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
  '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-', '..--.-': '_', '.-..-.': '"',
  '...-..-': '$', '.--.-.': '@',
});

function decompressionTransform(name, decompress) {
  return {
    description: `${name} 解压`,
    apply(state) {
      if (!state.bytes.length) throw new Error(`${name} 解压失败：输入为空。`);
      try {
        return makeState(decompress(state.bytes));
      } catch (error) {
        throw new Error(
          `${name} 解压失败：${error?.message ?? error}。请确认数据确实是 ${name} 格式（可先用 ctf.classify 查看魔数）。`,
        );
      }
    },
  };
}

/** name -> {description, apply(state:{bytes}) -> {bytes}}. */
export const TRANSFORMS = Object.freeze({
  base64: {
    description: 'Base64 解码（同时接受 URL-safe 字符，自动补 padding）',
    apply(state) {
      const text = requireUtf8Text(state, 'Base64');
      const cleaned = text.replace(/\s+/g, '');
      if (!cleaned) throw new Error('Base64 解码失败：去掉空白后为空。');
      if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(cleaned)) {
        throw new Error(
          'Base64 解码失败：包含非法字符。Base64 只允许 A-Z a-z 0-9 + / =（URL-safe 允许 - _），请检查输入或改用其它变换。',
        );
      }
      let normalized = cleaned.replace(/-/g, '+').replace(/_/g, '/');
      const remainder = normalized.length % 4;
      if (remainder === 1) {
        throw new Error(`Base64 解码失败：字符数 ${normalized.length} 非法（mod 4 == 1，不可能由 Base64 产生）。`);
      }
      if (remainder) normalized += '='.repeat(4 - remainder);
      const bytes = Buffer.from(normalized, 'base64');
      if (!bytes.length) throw new Error('Base64 解码结果为空，请确认输入内容。');
      return makeState(bytes);
    },
  },
  base64url: {
    description: 'Base64URL 解码（- _ 无 padding）',
    apply(state) {
      const text = requireUtf8Text(state, 'Base64URL');
      const cleaned = text.replace(/\s+/g, '');
      if (!cleaned) throw new Error('Base64URL 解码失败：去掉空白后为空。');
      if (!/^[A-Za-z0-9_-]+={0,2}$/.test(cleaned)) {
        throw new Error('Base64URL 解码失败：只允许 A-Z a-z 0-9 - _（可带 padding =）。');
      }
      let normalized = cleaned.replace(/-/g, '+').replace(/_/g, '/');
      const remainder = normalized.length % 4;
      if (remainder === 1) throw new Error(`Base64URL 解码失败：字符数 ${normalized.length} 非法（mod 4 == 1）。`);
      if (remainder) normalized += '='.repeat(4 - remainder);
      const bytes = Buffer.from(normalized, 'base64');
      if (!bytes.length) throw new Error('Base64URL 解码结果为空。');
      return makeState(bytes);
    },
  },
  base32: {
    description: 'Base32 (RFC 4648) 解码',
    apply(state) {
      const text = requireUtf8Text(state, 'Base32');
      const cleaned = text.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
      if (!cleaned) throw new Error('Base32 解码失败：去掉空白与 padding 后为空。');
      if (!/^[A-Z2-7]+$/.test(cleaned)) {
        throw new Error('Base32 解码失败：只允许字符 A-Z 与 2-7（RFC 4648 字母表）。');
      }
      const remainder = cleaned.length % 8;
      if (![0, 2, 4, 5, 7].includes(remainder)) {
        throw new Error(`Base32 解码失败：长度 ${cleaned.length} 非法（合法 mod 8 为 0/2/4/5/7）。`);
      }
      const out = [];
      let value = 0;
      let bits = 0;
      for (const ch of cleaned) {
        const index = BASE32_ALPHABET.indexOf(ch);
        if (index < 0) throw new Error(`Base32 解码失败：非法字符 “${ch}”。`);
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
          out.push((value >>> (bits - 8)) & 0xff);
          bits -= 8;
        }
      }
      const bytes = Buffer.from(out);
      if (!bytes.length) throw new Error('Base32 解码结果为空。');
      return makeState(bytes);
    },
  },
  hex: {
    description: '十六进制解码（忽略空白/冒号/连字符）',
    apply(state) {
      const text = requireUtf8Text(state, 'Hex');
      const cleaned = text.replace(/[\s:_-]/g, '');
      if (!cleaned) throw new Error('Hex 解码失败：去掉分隔符后为空。');
      if (!/^[0-9a-fA-F]+$/.test(cleaned)) {
        throw new Error('Hex 解码失败：包含非十六进制字符（只允许 0-9 a-f A-F 及空白/冒号/连字符分隔）。');
      }
      if (cleaned.length % 2 !== 0) {
        throw new Error(`Hex 解码失败：字符数 ${cleaned.length} 为奇数，无法按字节解码。`);
      }
      return makeState(Buffer.from(cleaned, 'hex'));
    },
  },
  url: {
    description: 'URL 百分号解码（application/x-www-form-urlencoded 风格，不转换 +）',
    apply(state) {
      const text = requireUtf8Text(state, 'URL');
      if (!/%[0-9A-Fa-f]{2}/.test(text)) {
        throw new Error('URL 解码失败：输入中没有 %XX 转义序列，该变换不适用。');
      }
      let decoded;
      try {
        decoded = decodeURIComponent(text.trim());
      } catch (error) {
        throw new Error(`URL 解码失败：存在非法或不完整的 %XX 序列（${error?.message ?? error}）。`);
      }
      return makeState(Buffer.from(decoded, 'utf8'));
    },
  },
  rot13: {
    description: 'ROT13 字母置换',
    apply(state) {
      const text = requireUtf8Text(state, 'ROT13');
      const out = text.replace(/[a-zA-Z]/g, (ch) => {
        const base = ch <= 'Z' ? 65 : 97;
        return String.fromCharCode(base + ((ch.charCodeAt(0) - base + 13) % 26));
      });
      return makeState(Buffer.from(out, 'utf8'));
    },
  },
  binary: {
    description: '二进制位串解码（0/1，按 8 位一组）',
    apply(state) {
      const text = requireUtf8Text(state, 'Binary');
      const cleaned = text.replace(/[\s_|]/g, '');
      if (!/^[01]+$/.test(cleaned)) {
        throw new Error('二进制解码失败：只允许 0/1（可含空格分隔），当前包含其它字符。');
      }
      if (cleaned.length % 8 !== 0) {
        throw new Error(`二进制解码失败：位数 ${cleaned.length} 不是 8 的倍数。`);
      }
      const out = Buffer.alloc(cleaned.length / 8);
      for (let i = 0; i < out.length; i += 1) {
        out[i] = parseInt(cleaned.slice(i * 8, i * 8 + 8), 2);
      }
      return makeState(out);
    },
  },
  morse: {
    description: 'Morse 电码解码（. - 空格分隔字母，/ 或 | 分隔单词）',
    apply(state) {
      const text = requireUtf8Text(state, 'Morse');
      const normalized = text.trim().replace(/\|/g, '/').replace(/\s*\/\s*/g, ' / ');
      if (!/[.-]/.test(normalized)) {
        throw new Error('Morse 解码失败：输入中没有 . 或 - 符号。');
      }
      const tokens = normalized.split(/\s+/).filter(Boolean);
      const chars = [];
      for (const token of tokens) {
        if (token === '/') {
          chars.push(' ');
          continue;
        }
        const decoded = MORSE_TABLE[token];
        if (decoded === undefined) {
          throw new Error(
            `Morse 解码失败：无法识别符号 “${token.slice(0, 40)}”。支持 A-Z/0-9 及常见标点，字母用空格分隔，/ 表示单词分隔。`,
          );
        }
        chars.push(decoded);
      }
      return makeState(Buffer.from(chars.join(''), 'utf8'));
    },
  },
  gzip: decompressionTransform('Gzip', (bytes) => gunzipSync(bytes)),
  zlib: decompressionTransform('Zlib', (bytes) => inflateSync(bytes)),
  'inflate-raw': decompressionTransform('Raw DEFLATE', (bytes) => inflateRawSync(bytes)),
  utf16le: {
    description: 'UTF-16LE 解码（也接受十六进制文本形式的 UTF-16LE 字节）',
    apply(state) {
      let bytes = state.bytes;
      const text = utf8Text(bytes);
      if (text && /^(?:[0-9a-fA-F]{2})+$/.test(text.trim()) && text.trim().length % 4 === 0) {
        bytes = Buffer.from(text.trim(), 'hex');
      }
      if (!bytes.length) throw new Error('UTF-16LE 解码失败：输入为空。');
      if (bytes.length % 2 !== 0) {
        throw new Error(`UTF-16LE 解码失败：字节数 ${bytes.length} 为奇数，无法按 UTF-16 码元解码。`);
      }
      const decoded = bytes.toString('utf16le');
      return makeState(Buffer.from(decoded, 'utf8'));
    },
  },
});

export const TRANSFORM_NAMES = Object.freeze(Object.keys(TRANSFORMS));

/** Apply one named transform; throws actionable errors. */
export function applyTransform(name, state) {
  const transform = TRANSFORMS[name];
  if (!transform) {
    throw new Error(`未知变换 “${String(name)}”。可用变换：${TRANSFORM_NAMES.join(', ')}。`);
  }
  return transform.apply(state);
}

function stepInfo(index, name, state, ok, error) {
  if (!ok) {
    return { step: index + 1, transform: name, ok: false, error: compact(error, 400) };
  }
  const text = state.bytes.toString('utf8');
  const printable = isPrintableText(text, 0.8);
  const flags = printable ? scanFlagsInText(text, { maxItems: 5 }) : [];
  return {
    step: index + 1,
    transform: name,
    ok: true,
    outputBytes: state.bytes.length,
    printable,
    entropy: Number(shannonEntropy(state.bytes).toFixed(3)),
    preview: previewText(text, 300),
    flags: flags.map((f) => f.flag),
  };
}

/**
 * Decode a named transform chain.
 * @returns {{steps:object[], finalBytes:Buffer, finalText:string, truncated:boolean, usedTransforms:string[]}}
 */
export function decodeChain(initialBytes, transformNames, opts = {}) {
  if (!Array.isArray(transformNames) || transformNames.length === 0) {
    throw new Error(
      '未指定变换链 transforms：请按顺序给出编码名，例如 ["base64","gzip"]。' +
        ` 可用变换：${TRANSFORM_NAMES.join(', ')}。`,
    );
  }
  const invalid = transformNames.filter((name) => !Object.hasOwn(TRANSFORMS, name));
  if (invalid.length) {
    throw new Error(
      `未知变换：${invalid.join(', ')}。可用变换：${TRANSFORM_NAMES.join(', ')}。`,
    );
  }
  const maxDepth = clampInt(opts.maxDepth, 10, 1, 64);
  const maxBytes = clampInt(opts.maxBytes, 4 * 1024 * 1024, 1024, 64 * 1024 * 1024);
  const signal = opts.signal;
  const planned = transformNames.slice(0, maxDepth);
  const truncated = transformNames.length > planned.length;

  const steps = [];
  let state = makeState(initialBytes);
  for (let i = 0; i < planned.length; i += 1) {
    const name = planned[i];
    if (signal?.aborted) {
      steps.push({ step: i + 1, transform: name, ok: false, error: '已取消（aborted）' });
      break;
    }
    try {
      const next = applyTransform(name, state);
      if (next.bytes.length > maxBytes) {
        steps.push({
          step: i + 1,
          transform: name,
          ok: false,
          error: `输出 ${next.bytes.length} 字节超过 maxBytes=${maxBytes}，已停止以防内存膨胀`,
        });
        break;
      }
      state = next;
      steps.push(stepInfo(i, name, state, true));
    } catch (error) {
      steps.push({
        step: i + 1,
        transform: name,
        ok: false,
        error: compact(error?.message ?? error, 400),
      });
      break;
    }
  }
  const finalText = state.bytes.toString('utf8');
  return {
    steps,
    finalBytes: state.bytes,
    finalText,
    truncated,
    usedTransforms: steps.filter((s) => s.ok).map((s) => s.transform),
  };
}
