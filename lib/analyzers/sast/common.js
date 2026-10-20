// ArmorBreak SAST domain — shared, dependency-free helpers.
//
// Directory access MUST go through the core-provided env.listFiles/env.readFile
// helpers so the Lead's path/size policy is enforced. File contents are always
// treated as untrusted data: control characters stripped, secrets redacted in
// every excerpt, hard bounds on files/bytes/lines.

export const SEVERITY_RANK = Object.freeze({ critical: 5, high: 4, medium: 3, low: 2, info: 1 });

export const DEFAULT_EXCLUDED_DIRS = Object.freeze([
  '.git',
  '.hg',
  '.svn',
  '.idea',
  '.vscode',
  '.venv',
  'venv',
  'env',
  'node_modules',
  '__pycache__',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  'target',
  'bin',
  'obj',
  '.next',
  '.nuxt',
  '.cache',
  '.gradle',
  '.mvn',
  'Pods',
]);

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

/** Strip ANSI escapes / C0+C1 control chars, keep \n and \t. */
export function stripControl(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, '');
}

export function clip(value, max = 2000) {
  const s = stripControl(typeof value === 'string' ? value : String(value ?? ''));
  if (s.length <= max) return s;
  return `${s.slice(0, Math.max(0, max - 1))}…`;
}

export function compact(value, max = 2000) {
  return clip(value, max).replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function normalizeEvidence(item) {
  if (item == null) return { title: 'evidence', excerpt: '' };
  if (typeof item !== 'object') return { title: 'evidence', excerpt: clip(String(item)) };
  const ev = { title: compact(item.title ?? 'evidence', 200), excerpt: clip(item.excerpt ?? '', 2000) };
  if (item.meta && typeof item.meta === 'object' && !Array.isArray(item.meta)) ev.meta = item.meta;
  return ev;
}

const VERIFICATIONS = new Set(['observed', 'corroborated', 'hypothesis', 'unverified']);

/** Build a contract-shaped finding with safe defaults. */
export function finding(spec = {}) {
  return {
    title: compact(spec.title || 'finding', 300),
    severity: Object.hasOwn(SEVERITY_RANK, spec.severity) ? spec.severity : 'info',
    description: compact(spec.description || '', 4000),
    verification: VERIFICATIONS.has(spec.verification) ? spec.verification : 'unverified',
    method: compact(spec.method || '', 300),
    cwe: typeof spec.cwe === 'string' && /^CWE-\d+$/.test(spec.cwe) ? spec.cwe : null,
    cvss: Number.isFinite(spec.cvss) ? Math.max(0, Math.min(10, spec.cvss)) : null,
    remediation: compact(spec.remediation || '', 2000),
    target: spec.target == null ? null : compact(String(spec.target), 500),
    evidence: Array.isArray(spec.evidence) ? spec.evidence.slice(0, 20).map(normalizeEvidence) : [],
  };
}

function cmp(a, b) {
  const x = String(a ?? '');
  const y = String(b ?? '');
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Deterministic order: severity desc, target asc, title asc. */
export function sortFindings(findings) {
  return findings.slice().sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      cmp(a.target, b.target) ||
      cmp(a.title, b.title),
  );
}

// ---------------------------------------------------------------------------
// Path helpers (no node:path dependency so both / and \ inputs work)
// ---------------------------------------------------------------------------

export function baseName(filePath) {
  const parts = String(filePath ?? '').split(/[\\/]+/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

export function extOf(filePath) {
  const base = baseName(filePath);
  const index = base.lastIndexOf('.');
  return index <= 0 ? '' : base.slice(index).toLowerCase();
}

export function parentDir(filePath) {
  const value = String(filePath ?? '');
  const index = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
  return index <= 0 ? '' : value.slice(0, index);
}

export function isExcludedPath(filePath, excludedDirs) {
  const excluded = new Set(
    (Array.isArray(excludedDirs) && excludedDirs.length ? excludedDirs : DEFAULT_EXCLUDED_DIRS)
      .filter((d) => typeof d === 'string' && d.trim())
      .map((d) => d.trim().toLowerCase()),
  );
  if (!excluded.size) return false;
  const parts = String(filePath ?? '').split(/[\\/]+/).filter(Boolean);
  return parts.some((part) => excluded.has(part.toLowerCase()));
}

/**
 * True when a full file path should be skipped by the caller-provided
 * `excludePaths` patterns. A pattern is matched case-insensitively as a
 * substring of the normalized path, so `"tests/"`, `"lib/analyzers/sast/rules.js"`
 * or `"fixtures"` all work without a glob dependency.
 */
export function isFilePathExcluded(filePath, excludePaths) {
  if (!Array.isArray(excludePaths) || excludePaths.length === 0) return false;
  const normalized = String(filePath ?? '').replace(/\\/g, '/').toLowerCase();
  return excludePaths.some((pattern) => {
    const value = typeof pattern === 'string' ? pattern.trim().toLowerCase() : '';
    return value.length > 0 && normalized.includes(value.replace(/\\/g, '/'));
  });
}

export function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

// ---------------------------------------------------------------------------
// Buffer / text helpers
// ---------------------------------------------------------------------------

/** True when the buffer looks binary (NUL byte or very low printable ratio). */
export function isLikelyBinary(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  let printable = 0;
  for (const byte of sample) {
    if (byte === 0) return true;
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) || byte >= 128) printable += 1;
  }
  return printable / sample.length < 0.85;
}

export function shannonEntropy(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? ''), 'utf8');
  if (!data.length) return 0;
  const counts = new Map();
  for (const byte of data) counts.set(byte, (counts.get(byte) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / data.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Mask a secret value: first 4 chars + *** (short values fully masked). */
export function redactSecretValue(value, keep = 4) {
  const v = typeof value === 'string' ? value : String(value ?? '');
  if (!v) return '';
  if (v.length <= keep) return '***';
  return `${v.slice(0, keep)}***`;
}

const INLINE_SECRET_RULES = [
  {
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    mask: (match) => `${match.slice(0, 4)}***`,
  },
  {
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    mask: (match) => `${match.slice(0, 4)}***`,
  },
  {
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{10,}|AIza[0-9A-Za-z_-]{30,})\b/g,
    mask: (match) => `${match.slice(0, 4)}***`,
  },
  {
    re: /((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\w*\s*[:=]\s*['"])([^'"\s]{4,})(['"])/gi,
    mask: (match) => match.replace(/^(.*?[:=]\s*['"])([^'"]+)(['"])$/s, (_m, prefix, value, suffix) => `${prefix}${redactSecretValue(value)}${suffix}`),
  },
];

/** Redact credential-looking values inside an arbitrary code/log line. */
export function redactInlineSecrets(text) {
  let out = String(text ?? '');
  for (const rule of INLINE_SECRET_RULES) {
    out = out.replace(rule.re, (...args) => rule.mask(args[0]));
  }
  return out;
}

/** Safe single-line excerpt for findings/evidence. */
export function excerptLine(line, max = 400) {
  return clip(redactInlineSecrets(line), max);
}

// ---------------------------------------------------------------------------
// Core-provided directory access (env.listFiles / env.readFile)
// ---------------------------------------------------------------------------

function normalizeOptions(options = {}) {
  return {
    excludedDirs: Array.isArray(options.excludeDirs) && options.excludeDirs.length
      ? options.excludeDirs.map(String)
      : DEFAULT_EXCLUDED_DIRS,
    excludedPaths: Array.isArray(options.excludePaths)
      ? options.excludePaths.map(String).filter((value) => value.trim() !== '')
      : [],
  };
}

/**
 * Enumerate candidate files for a directory target without reading them.
 * Returns { files, directoryScan, truncated, excludedCount, fileList }.
 */
export async function listTargetFiles(input, options = {}, caps = {}) {
  const env = input?.env ?? {};
  const targetPath = typeof input?.targetPath === 'string' && input.targetPath.trim() ? input.targetPath.trim() : null;
  const maxFiles = clampInt(caps.maxFiles, 500, 1, 5000);
  const { excludedDirs, excludedPaths } = normalizeOptions(options);

  if (typeof env.listFiles === 'function' && targetPath) {
    let listed;
    try {
      listed = await env.listFiles(targetPath, { maxFiles, maxBytes: caps.maxFileBytes });
    } catch (error) {
      return {
        files: null,
        directoryScan: true,
        error: new Error(
          `无法枚举目录 “${clip(targetPath, 300)}”：${compact(error?.message ?? error, 300)}。` +
            ' 请确认 targetPath 是可读目录，并且核心已提供 env.listFiles / env.readFile（目录型目标必需）。',
        ),
      };
    }
    if (!Array.isArray(listed)) {
      return {
        files: null,
        directoryScan: true,
        error: new Error('env.listFiles 的返回值必须是路径数组（string[]），核心实现与契约不一致。'),
      };
    }
    const paths = listed
      .filter((p) => typeof p === 'string' && p.trim())
      .map((p) => p.trim());
    const afterExclude = paths.filter((p) => !isExcludedPath(p, excludedDirs) && !isFilePathExcluded(p, excludedPaths));
    const uniqueSorted = [...new Set(afterExclude)].sort();
    const truncated = uniqueSorted.length > maxFiles;
    const files = uniqueSorted.slice(0, maxFiles);
    return {
      files,
      directoryScan: true,
      truncated,
      excludedCount: paths.length - afterExclude.length,
      totalCandidates: uniqueSorted.length,
    };
  }

  // Single-file / stdin fallback: no directory helper available.
  if (targetPath || input?.buffer || input?.text) {
    return {
      files: targetPath ? [targetPath] : [],
      directoryScan: false,
      truncated: false,
      excludedCount: 0,
      totalCandidates: targetPath ? 1 : 0,
    };
  }
  return {
    files: null,
    directoryScan: false,
    error: new Error(
      '未提供可分析的目标：需要目录型 targetPath（核心提供 env.listFiles/env.readFile），' +
        '或单文件目标（targetPath/buffer/text）。请检查调用参数。',
    ),
  };
}

/**
 * Read the target files through the core helpers (or the single-file buffer).
 * @param {(filePath:string)=>boolean} [filter] optional pre-read path filter
 * @returns {{sources:{path:string,buffer:Buffer}[], truncated:object, readErrors:object[], fileList:string[], directoryScan:boolean}}
 */
export async function collectSources(input, options = {}, caps = {}, filter = null) {
  const maxFileBytes = clampInt(caps.maxFileBytes, 256 * 1024, 1024, 4 * 1024 * 1024);
  const maxTotalBytes = clampInt(caps.maxTotalBytes, 16 * 1024 * 1024, 4096, 128 * 1024 * 1024);
  const listed = await listTargetFiles(input, options, { ...caps, maxFileBytes });
  if (listed.error) throw listed.error;

  const env = input?.env ?? {};
  const directoryScan = listed.directoryScan;
  const sources = [];
  const readErrors = [];
  let totalBytes = 0;
  let budgetExceeded = false;
  let aborted = false;

  if (directoryScan) {
    if (typeof env.readFile !== 'function') {
      throw new Error(
        '核心未提供 env.readFile：目录扫描需要用它在路径策略内读取文件。' +
          ' 请让核心注入 env.readFile(absPath, maxBytes)，或改用单文件目标。',
      );
    }
    const candidates = listed.files.filter((filePath) => (typeof filter === 'function' ? filter(filePath) : true));
    for (const filePath of candidates) {
      if (env.signal?.aborted) {
        aborted = true;
        break;
      }
      if (totalBytes >= maxTotalBytes) {
        budgetExceeded = true;
        break;
      }
      let raw;
      try {
        raw = await env.readFile(filePath, maxFileBytes);
      } catch (error) {
        if (readErrors.length < 20) {
          readErrors.push({ path: clip(filePath, 300), error: compact(error?.message ?? error, 200) });
        }
        continue;
      }
      const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(raw ?? []);
      const allowed = Math.min(buffer.length, maxFileBytes, maxTotalBytes - totalBytes);
      sources.push({ path: filePath, buffer: buffer.subarray(0, allowed), size: buffer.length });
      totalBytes += allowed;
    }
    return {
      sources,
      fileList: listed.files,
      directoryScan: true,
      readErrors,
      truncated: {
        files: Boolean(listed.truncated),
        totalBytes: budgetExceeded,
        aborted,
      },
      excludedCount: listed.excludedCount ?? 0,
      totalCandidates: listed.totalCandidates ?? listed.files.length,
      maxFiles: clampInt(caps.maxFiles, 500, 1, 5000),
      maxFileBytes,
    };
  }

  // Single-file / stdin fallback.
  const targetPath = typeof input?.targetPath === 'string' ? input.targetPath : null;
  let buffer = null;
  if (Buffer.isBuffer(input?.buffer) && input.buffer.length) buffer = input.buffer;
  else if (typeof input?.text === 'string' && input.text.length) buffer = Buffer.from(input.text, 'utf8');
  if (!buffer || !buffer.length) {
    throw new Error(
      '目标内容为空：目录扫描需要核心提供的 env.listFiles/env.readFile；单文件模式需要 input.buffer 或 input.text。' +
        ' 请检查 targetPath 是否指向存在的文件。',
    );
  }
  const allowed = Math.min(buffer.length, maxFileBytes);
  const path = targetPath || '<input>';
  if (typeof filter === 'function' && targetPath && !filter(targetPath)) {
    throw new Error(
      `目标文件 “${clip(targetPath, 300)}” 不是该能力支持的文件类型/清单。请确认文件扩展名，或把能力指向正确的项目根目录。`,
    );
  }
  return {
    sources: [{ path, buffer: buffer.subarray(0, allowed), size: buffer.length }],
    fileList: [path],
    directoryScan: false,
    readErrors: [],
    truncated: { files: false, totalBytes: buffer.length > allowed, aborted: false },
    excludedCount: 0,
    totalCandidates: 1,
    maxFiles: 1,
    maxFileBytes,
  };
}
