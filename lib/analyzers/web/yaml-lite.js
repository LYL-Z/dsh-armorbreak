// ArmorBreak web domain — a deliberately small YAML-subset parser.
//
// Scope: enough YAML for real-world OpenAPI 3.x documents (indentation-based
// mappings/sequences, quoted & plain scalars, block scalars `|`/`>`, inline
// JSON-ish flow collections, comments, a single `---` document marker).
//
// Anything outside the supported subset raises a YamlParseError with the line
// number and an actionable message (convert the spec to JSON, or simplify that
// construct). This keeps the analyzer honest instead of silently mis-parsing.

export class YamlParseError extends Error {
  constructor(message, line = null) {
    super(line ? `${message}（第 ${line} 行）` : message);
    this.name = 'YamlParseError';
    this.line = line;
  }
}

/** Keys that must never be materialized as own properties (prototype pollution guard). */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
/** Maximum nesting for inline flow collections. */
const MAX_FLOW_DEPTH = 64
/** Maximum nesting for indentation-based nodes. */
const MAX_NODE_DEPTH = 128

function isSeqItem(text) {
  return text === '-' || text.startsWith('- ');
}

function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) {
        if (quote === "'" && line[i + 1] === "'") {
          i += 1;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function tokenize(rawLines) {
  const tokens = [];
  let sawDocumentEnd = false;
  for (let index = 0; index < rawLines.length; index += 1) {
    const original = rawLines[index];
    if (!original) continue;
    const withoutComment = stripComment(original);
    if (!withoutComment.trim()) continue;
    if (/^---\s*$/.test(withoutComment)) {
      if (tokens.length || sawDocumentEnd) {
        throw new YamlParseError('不支持多文档 YAML（出现多个 --- 分隔符），请只提供单个 OpenAPI 文档', index + 1);
      }
      continue;
    }
    if (/^\.\.\.\s*$/.test(withoutComment)) {
      sawDocumentEnd = true;
      continue;
    }
    const indentMatch = /^[ \t]*/.exec(withoutComment)[0];
    if (indentMatch.includes('\t')) {
      throw new YamlParseError('YAML 缩进禁止使用 Tab，请改为空格', index + 1);
    }
    const indent = indentMatch.length;
    const text = withoutComment.slice(indent).replace(/\s+$/, '');
    if (!text) continue;
    tokens.push({ lineNo: index + 1, indent, text });
  }
  return tokens;
}

function splitKeyValue(text, lineNo) {
  // Returns {key, rest} when `text` starts a mapping pair at top level, else null.
  let quote = null;
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) {
        if (quote === "'" && text[i + 1] === "'") {
          i += 1;
          continue;
        }
        quote = null;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '[' || ch === '{') {
      depth += 1;
      continue;
    }
    if (ch === ']' || ch === '}') {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (ch === ':' && depth === 0) {
      const next = text[i + 1];
      if (next === undefined || next === ' ' || next === '\t') {
        const rawKey = text.slice(0, i).trim();
        if (!rawKey) throw new YamlParseError('YAML 映射键为空（形如 “: value”）', lineNo);
        return { key: unquoteScalarText(rawKey, lineNo), rest: text.slice(i + 1).trim(), lineNo };
      }
    }
  }
  return null;
}

function unquoteScalarText(text, lineNo) {
  const trimmed = String(text).trim();
  if (trimmed.startsWith('"')) {
    if (!trimmed.endsWith('"') || trimmed.length < 2) {
      throw new YamlParseError(`未闭合的双引号标量：${clipForError(trimmed)}`, lineNo);
    }
    try {
      return JSON.parse(trimmed);
    } catch {
      throw new YamlParseError(`双引号标量转义不合法：${clipForError(trimmed)}`, lineNo);
    }
  }
  if (trimmed.startsWith("'")) {
    if (!trimmed.endsWith("'") || trimmed.length < 2) {
      throw new YamlParseError(`未闭合的单引号标量：${clipForError(trimmed)}`, lineNo);
    }
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  return trimmed;
}

function clipForError(text) {
  const s = String(text ?? '');
  return s.length > 80 ? `${s.slice(0, 77)}…` : s;
}

function coercePlainScalar(text) {
  const t = String(text).trim();
  if (t === '' || t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return null;
  if (t === 'true' || t === 'True' || t === 'TRUE') return true;
  if (t === 'false' || t === 'False' || t === 'FALSE') return false;
  if (/^[-+]?(?:0|[1-9]\d*)$/.test(t)) return Number(t);
  if (/^[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?$/.test(t)) return Number(t);
  if (/^[-+]?\d+[eE][-+]?\d+$/.test(t)) return Number(t);
  if (t === '.nan' || t === '.NaN' || t === '.NAN') return Number.NaN;
  if (t === '.inf' || t === '.Inf' || t === '.INF') return Infinity;
  return t;
}

function flowBalance(text) {
  let quote = null;
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      if (quote === '"' && ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '[' || ch === '{') depth += 1;
    else if (ch === ']' || ch === '}') depth -= 1;
  }
  return depth;
}

function parseFlow(text, lineNo) {
  const trimmed = text.trim();
  // Fast path: inline flow that is valid JSON.
  if (/^[[{]/.test(trimmed)) {
    try {
      return JSON.parse(trimmed);
    } catch {
      // fall through to the lenient flow parser below
    }
  }
  let i = 0;
  const s = trimmed;
  const ws = () => {
    while (i < s.length && /\s/.test(s[i])) i += 1;
  };
  const fail = (msg) => {
    throw new YamlParseError(`flow 集合解析失败：${msg}（片段：${clipForError(s.slice(Math.max(0, i - 20))) }）`, lineNo);
  };
  const parseQuoted = () => {
    if (s[i] === '"') {
      let j = i + 1;
      while (j < s.length) {
        if (s[j] === '\\') {
          j += 2;
          continue;
        }
        if (s[j] === '"') break;
        j += 1;
      }
      if (j >= s.length) fail('双引号未闭合');
      const raw = s.slice(i, j + 1);
      i = j + 1;
      try {
        return JSON.parse(raw);
      } catch {
        fail('双引号转义不合法');
      }
    }
    let j = i + 1;
    while (j < s.length) {
      if (s[j] === "'") {
        if (s[j + 1] === "'") {
          j += 2;
          continue;
        }
        break;
      }
      j += 1;
    }
    if (j >= s.length) fail('单引号未闭合');
    const raw = s.slice(i + 1, j).replace(/''/g, "'");
    i = j + 1;
    return raw;
  };
  const parsePlain = (terminators) => {
    const start = i;
    while (i < s.length && !terminators.includes(s[i])) i += 1;
    return s.slice(start, i).trim();
  };
  const expect = (ch) => {
    ws();
    if (s[i] !== ch) fail(`期望 “${ch}”`);
    i += 1;
  };
  const parseValue = (depth = 0) => {
    if (depth > MAX_FLOW_DEPTH) fail(`流式集合嵌套超过 ${MAX_FLOW_DEPTH} 层，请改用 JSON 或简化文档`);
    ws();
    if (i >= s.length) fail('值缺失');
    if (s[i] === '[') {
      i += 1;
      const arr = [];
      ws();
      if (s[i] === ']') {
        i += 1;
        return arr;
      }
      for (;;) {
        arr.push(parseValue(depth + 1));
        ws();
        if (s[i] === ',') {
          i += 1;
          ws();
          if (s[i] === ']') {
            i += 1;
            return arr;
          }
          continue;
        }
        expect(']');
        return arr;
      }
    }
    if (s[i] === '{') {
      i += 1;
      const obj = {};
      ws();
      if (s[i] === '}') {
        i += 1;
        return obj;
      }
      for (;;) {
        ws();
        let key;
        if (s[i] === '"' || s[i] === "'") key = parseQuoted();
        else key = parsePlain([':', ',', '}']);
        ws();
        if (s[i] !== ':') fail('映射项缺少 “:”');
        i += 1;
        if (DANGEROUS_KEYS.has(String(key))) fail(`拒绝危险键名 “${String(key)}”`);
        obj[String(key)] = parseValue(depth + 1);
        ws();
        if (s[i] === ',') {
          i += 1;
          ws();
          if (s[i] === '}') {
            i += 1;
            return obj;
          }
          continue;
        }
        expect('}');
        return obj;
      }
    }
    if (s[i] === '"' || s[i] === "'") return parseQuoted();
    const plain = parsePlain([',', ']', '}']);
    return coercePlainScalar(plain);
  };

  const value = parseValue();
  ws();
  if (i < s.length) fail('值后存在多余字符');
  return value;
}

function parseBlockScalar(state, indicatorLineNo, parentIndent, indicator) {
  const { rawLines, tokens } = state;
  const folded = indicator.startsWith('>');
  const keep = indicator.includes('+');
  const collected = [];
  let firstContentIndex = -1;
  let minIndent = Infinity;
  let index = indicatorLineNo; // 0-based index of the first line after the indicator line
  for (; index < rawLines.length; index += 1) {
    const line = rawLines[index];
    if (!line.trim()) {
      collected.push('');
      continue;
    }
    const indent = /^ */.exec(line)[0].length;
    if (indent <= parentIndent) break;
    if (firstContentIndex < 0) firstContentIndex = collected.length;
    minIndent = Math.min(minIndent, indent);
    collected.push(line);
  }
  // Trim trailing blank lines (chomping "clip" behaviour), keep internal blanks.
  while (collected.length && collected[collected.length - 1] === '') collected.pop();
  const startIndex = firstContentIndex < 0 ? collected.length : firstContentIndex;
  const contentLines = collected.slice(startIndex).map((line) => (line === '' ? '' : line.slice(minIndent)));
  let value;
  if (folded) {
    const parts = [];
    for (const line of contentLines) {
      if (line === '') parts.push('\n');
      else if (parts.length && parts[parts.length - 1] !== '\n') parts.push(` ${line}`);
      else parts.push(line);
    }
    value = parts.join('');
  } else {
    value = contentLines.join('\n');
  }
  if (keep && value && !value.endsWith('\n')) value += '\n';
  // Advance token cursor past every token that belongs to the block scalar.
  const consumedThroughLine = index; // 1-based line number of the last consumed line
  while (state.i < tokens.length && tokens[state.i].lineNo <= consumedThroughLine) {
    state.i += 1;
  }
  return value;
}

function parseInlineScalar(text, lineNo) {
  const trimmed = text.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('&') || trimmed.startsWith('*')) {
    throw new YamlParseError(
      '不支持 YAML 锚点/别名（&anchor / *alias）或 merge 键，请展开后重试（或改用 JSON 格式的 OpenAPI）',
      lineNo,
    );
  }
  if (trimmed.startsWith('!!') || trimmed.startsWith('!<') || trimmed.startsWith('! ')) {
    throw new YamlParseError('不支持 YAML 显式标签（!!tag / !<...>），请移除标签后重试', lineNo);
  }
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    return parseFlow(trimmed, lineNo);
  }
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    return unquoteScalarText(trimmed, lineNo);
  }
  return coercePlainScalar(trimmed);
}

function parseFlowWithContinuation(state, initialText, lineNo) {
  let text = initialText;
  let guard = 0;
  while (flowBalance(text) > 0) {
    const token = state.tokens[state.i];
    if (!token) {
      throw new YamlParseError('flow 集合没有闭合（缺少 ] 或 }），请检查该行', lineNo);
    }
    state.i += 1;
    text += ` ${token.text}`;
    guard += 1;
    if (guard > 500) {
      throw new YamlParseError('flow 集合跨行过多，疑似格式错误', lineNo);
    }
  }
  return parseFlow(text, lineNo);
}

function parseSequence(state, indent) {
  const out = [];
  for (;;) {
    const token = state.tokens[state.i];
    if (!token || token.indent < indent) break;
    if (token.indent > indent) {
      throw new YamlParseError(
        `序列缩进不一致：期望 ${indent} 个空格，实际 ${token.indent} 个（内容：${clipForError(token.text)}）`,
        token.lineNo,
      );
    }
    if (!isSeqItem(token.text)) break;
    const dashMatch = /^-(?:[ \t]+|$)/.exec(token.text);
    const prefixLen = dashMatch ? dashMatch[0].length : 1;
    const content = token.text.slice(prefixLen).trim();
    const lineNo = token.lineNo;
    state.i += 1;
    if (content === '') {
      const next = state.tokens[state.i];
      if (next && next.indent > indent) out.push(parseNode(state, next.indent));
      else out.push(null);
      continue;
    }
    if (content === '|' || content === '>' || /^[|>][+-]?$/.test(content)) {
      out.push(parseBlockScalar(state, lineNo, indent, content));
      continue;
    }
    const pair = splitKeyValue(content, lineNo);
    if (pair) {
      const virtualIndent = indent + prefixLen;
      out.push(parseMapping(state, virtualIndent, pair));
      continue;
    }
    out.push(parseInlineScalar(content, lineNo));
  }
  return out;
}

function parseMapping(state, indent, initialPair = null) {
  const out = {};
  const pending = initialPair ? [initialPair] : [];
  for (;;) {
    let pair;
    if (pending.length) {
      pair = pending.shift();
    } else {
      const token = state.tokens[state.i];
      if (!token || token.indent < indent) break;
      if (token.indent > indent) {
        throw new YamlParseError(
          `映射缩进不一致：期望 ${indent} 个空格，实际 ${token.indent} 个（内容：${clipForError(token.text)}）`,
          token.lineNo,
        );
      }
      if (isSeqItem(token.text)) break;
      pair = splitKeyValue(token.text, token.lineNo);
      if (!pair) {
        throw new YamlParseError(
          `映射行缺少 “key: value” 结构：${clipForError(token.text)}（请检查缩进与冒号后的空格）`,
          token.lineNo,
        );
      }
      state.i += 1;
    }
    const key = pair.key;
    if (key === '<<') {
      throw new YamlParseError('不支持 YAML merge key “<<” / 锚点，请展开后重试', pair.lineNo);
    }
    if (DANGEROUS_KEYS.has(String(key))) {
      throw new YamlParseError(`拒绝危险键名 “${String(key)}”（可能存在原型污染风险）`, pair.lineNo);
    }
    if (Object.hasOwn(out, key)) {
      throw new YamlParseError(`YAML 映射出现重复键 “${key}”`, pair.lineNo);
    }
    if (pair.rest === '') {
      const next = state.tokens[state.i];
      if (next && next.indent > indent) out[key] = parseNode(state, next.indent);
      else out[key] = null;
      continue;
    }
    if (pair.rest === '|' || pair.rest === '>' || /^[|>][+-]?$/.test(pair.rest)) {
      out[key] = parseBlockScalar(state, pair.lineNo, indent, pair.rest);
      continue;
    }
    if (pair.rest.startsWith('[') || pair.rest.startsWith('{')) {
      out[key] = parseFlowWithContinuation(state, pair.rest, pair.lineNo);
      continue;
    }
    out[key] = parseInlineScalar(pair.rest, pair.lineNo);
  }
  return out;
}

function parseNode(state, indent) {
  if ((state.depth ?? 0) > MAX_NODE_DEPTH) {
    throw new YamlParseError(`YAML 嵌套超过 ${MAX_NODE_DEPTH} 层，请改用 JSON 或简化文档`, state.tokens[state.i]?.lineNo ?? 1);
  }
  state.depth = (state.depth ?? 0) + 1;
  try {
    const token = state.tokens[state.i];
    if (!token) return null;
    if (token.indent !== indent) {
      throw new YamlParseError(
        `缩进层级不匹配：期望 ${indent} 个空格，实际 ${token.indent} 个（内容：${clipForError(token.text)}）`,
        token.lineNo,
      );
    }
    if (isSeqItem(token.text)) return parseSequence(state, indent);
    if (splitKeyValue(token.text, token.lineNo)) return parseMapping(state, indent);
    state.i += 1;
    return parseInlineScalar(token.text, token.lineNo);
  } finally {
    state.depth -= 1;
  }
}

/**
 * Parse a YAML text using the supported subset.
 * @param {string} text
 * @returns {*} plain JS value
 * @throws {YamlParseError} for unsupported/ambiguous constructs
 */
export function parseYamlLite(text) {
  const source = String(text ?? '').replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  const rawLines = source.split('\n');
  const tokens = tokenize(rawLines);
  if (!tokens.length) {
    throw new YamlParseError('YAML 文档为空：未找到任何内容（仅有注释或空行）');
  }
  const state = { rawLines, tokens, i: 0 };
  const value = parseNode(state, tokens[0].indent);
  if (state.i < tokens.length) {
    const leftover = tokens[state.i];
    throw new YamlParseError(
      `无法解析剩余内容（缩进 ${leftover.indent}）：${clipForError(leftover.text)}。` +
        ' 请检查同级键的缩进是否一致，或把该文档转换为 JSON。',
      leftover.lineNo,
    );
  }
  return value;
}

export { isSeqItem, stripComment };
