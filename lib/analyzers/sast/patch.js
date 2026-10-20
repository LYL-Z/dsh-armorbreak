// ArmorBreak SAST domain — remediation patch + regression-test suggestion.
//
// SAFETY: this module NEVER writes files and never applies a patch. It emits an
// illustrative unified diff plus a regression-test skeleton; the finding's own
// verification level is preserved (a hypothesis stays a hypothesis).

import { baseName, clip, compact } from './common.js';
import { languageForFile } from './rules.js';

const CWE_GUIDANCE = {
  'CWE-78': {
    label: '命令注入',
    replacement: {
      javascript: 'execFile("/absolute/fixed/binary", argsArray); // 参数数组，禁止 shell 拼接',
      typescript: 'execFile("/absolute/fixed/binary", argsArray); // 参数数组，禁止 shell 拼接',
      python: 'subprocess.run(["/absolute/fixed/binary", *args], shell=False, check=True)',
      java: 'new ProcessBuilder("/absolute/fixed/binary", arg1, arg2).start();',
      go: 'exec.Command("/absolute/fixed/binary", args...)',
      c: '// 使用 execv/execve 参数数组，避免 system()/popen() 拼接',
      php: '// 使用 escapeshellarg($arg) 并避免 shell 元字符，或使用 proc_open 参数数组',
    },
    payload: '"; id; echo " 或 $(id) 或 `id`',
  },
  'CWE-89': {
    label: 'SQL 注入',
    replacement: {
      javascript: 'db.query("SELECT * FROM users WHERE id = ?", [userId]); // 参数化查询',
      typescript: 'db.query("SELECT * FROM users WHERE id = ?", [userId]); // 参数化查询',
      python: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # 参数化',
      java: 'PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?"); stmt.setInt(1, userId);',
      go: 'db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", userID)',
      c: '// 使用预编译语句/参数绑定 API，禁止拼接 SQL',
      php: '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
    },
    payload: "' OR '1'='1",
  },
  'CWE-95': {
    label: '动态代码执行',
    replacement: {
      javascript: 'const handler = SAFE_HANDLERS[action]; if (!handler) throw new Error("invalid action"); handler(input);',
      typescript: 'const handler = SAFE_HANDLERS[action]; if (!handler) throw new Error("invalid action"); handler(input);',
      python: 'handler = SAFE_HANDLERS.get(action); if handler is None: raise ValueError("invalid action"); handler(data)',
      java: '// 用枚举 + switch/白名单分发，禁止脚本引擎执行用户输入',
      go: '// 用白名单 map 分发，禁止动态求值',
      c: '// 移除动态执行路径，改为显式分支/白名单',
      php: '// 用白名单 match/switch 分发，移除 eval',
    },
    payload: '1; system("id")',
  },
  'CWE-79': {
    label: 'XSS',
    replacement: {
      javascript: 'element.textContent = userInput; // 使用 textContent / 安全模板，禁止拼 HTML',
      typescript: 'element.textContent = userInput; // 使用 textContent / 安全模板，禁止拼 HTML',
      python: 'return render_template("page.html", value=user_input)  # 依赖自动转义模板',
      java: '// 使用 OWASP Encoder / 模板自动转义输出',
      go: '// 使用 html/template（自动转义）而非 text/template',
      c: '// 服务端渲染时执行 HTML 实体编码',
      php: 'echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, "UTF-8");',
    },
    payload: '<script>alert(1)</script>',
  },
  'CWE-22': {
    label: '路径穿越',
    replacement: {
      javascript: 'const safePath = path.join(BASE_DIR, path.basename(userPath)); if (!safePath.startsWith(BASE_DIR)) throw new Error("invalid path");',
      typescript: 'const safePath = path.join(BASE_DIR, path.basename(userPath)); if (!safePath.startsWith(BASE_DIR)) throw new Error("invalid path");',
      python: 'safe_path = (BASE_DIR / os.path.basename(user_path)).resolve(); safe_path.relative_to(BASE_DIR)',
      java: 'Path safe = baseDir.resolve(userPath).normalize(); if (!safe.startsWith(baseDir)) throw new SecurityException();',
      go: '// filepath.Clean + filepath.Rel 校验，拒绝 .. 越界',
      c: '// realpath() 后校验前缀，拒绝 .. 穿越',
      php: '$safe = basename($input); $path = $base . "/" . $safe;',
    },
    payload: '../../etc/passwd',
  },
  'CWE-502': {
    label: '不安全反序列化',
    replacement: {
      javascript: 'const data = JSON.parse(payload); // 仅接受 JSON 并做 schema 校验',
      typescript: 'const data = JSON.parse(payload); // 仅接受 JSON 并做 schema 校验',
      python: 'data = json.loads(payload)  # 禁止 pickle/yaml.load 处理不可信数据',
      java: '// 使用 allowlist ObjectInputFilter，或迁移到 JSON + schema 校验',
      go: '// 禁用 gob 反序列化不可信输入，改用 JSON',
      c: '// 使用带长度/类型校验的序列化格式',
      php: 'json_decode($payload, true, 512, JSON_THROW_ON_ERROR); // 禁止 unserialize 不可信数据',
    },
    payload: '恶意序列化对象（触发 gadget chain）',
  },
  'CWE-328': {
    label: '弱哈希',
    replacement: {
      javascript: 'crypto.createHash("sha256").update(value).digest("hex");',
      typescript: 'crypto.createHash("sha256").update(value).digest("hex");',
      python: 'hashlib.sha256(value).hexdigest()  # 口令使用 bcrypt/argon2',
      java: 'MessageDigest.getInstance("SHA-256"); // 口令使用 BCrypt/Argon2',
      go: 'sha256.Sum256(value)',
      c: '// 使用 SHA-256/CH 系列；口令使用 Argon2/bcrypt',
      php: 'hash("sha256", $value); // 口令使用 password_hash($pwd, PASSWORD_ARGON2ID)',
    },
    payload: '弱哈希碰撞/彩虹表',
  },
  'CWE-918': {
    label: 'SSRF',
    replacement: {
      javascript: 'if (!isAllowedHost(targetUrl)) throw new Error("host not allowed"); await fetch(targetUrl);',
      python: 'if not is_allowed_host(target_url): raise ValueError("host not allowed")',
      java: '// 目标域名 allowlist + 解析后 IP 校验，拒绝内网段',
      go: '// 目标域名 allowlist + IP 校验，拒绝内网段',
      c: '// 目标域名 allowlist + 解析后 IP 校验',
      php: '// 目标域名 allowlist + 解析后 IP 校验',
      typescript: 'if (!isAllowedHost(targetUrl)) throw new Error("host not allowed"); await fetch(targetUrl);',
    },
    payload: 'http://169.254.169.254/latest/meta-data/',
  },
  'CWE-330': {
    label: '弱随机数',
    replacement: {
      javascript: 'const token = crypto.randomBytes(32).toString("base64url");',
      typescript: 'const token = crypto.randomBytes(32).toString("base64url");',
      python: 'token = secrets.token_urlsafe(32)',
      java: 'SecureRandom random = new SecureRandom(); byte[] token = new byte[32]; random.nextBytes(token);',
      go: '// crypto/rand.Read(buf)，不要用 math/rand',
      c: '// 使用 getrandom()/RAND_bytes() 等 CSPRNG',
      php: 'bin2hex(random_bytes(32));',
    },
    payload: '可预测随机数',
  },
};

const LANGUAGE_TEST_FILE = {
  javascript: 'regression.test.mjs',
  typescript: 'regression.test.mjs',
  python: 'test_regression.py',
  java: 'RegressionTest.java',
  go: 'regression_test.go',
  c: 'regression_test.c',
  php: 'regression_test.php',
};

function testSkeleton(language, { label, payload, file, cwe, ruleHint }) {
  const location = file ? clip(file, 200) : '(目标文件)';
  const idNote = `CWE-${String(cwe).replace(/^CWE-/, '')}${ruleHint ? ` / ${ruleHint}` : ''}`;
  const header = `// 回归测试建议（由 ArmorBreak sast.patch_suggestion 生成，需人工补全目标函数导入）\n// 覆盖: ${idNote} (${label}); 目标: ${location}\n// 攻击载荷示例: ${payload}\n`;
  if (language === 'javascript' || language === 'typescript') {
    return `${header}import test from 'node:test';\nimport assert from 'node:assert/strict';\n\n// import { targetFunction } from '../src/target.js';\n\ntest('${ruleHint ?? 'vulnerability'} regression: ${label} payload is rejected', async () => {\n  const payload = ${JSON.stringify(payload)};\n  // 用带 payload 的调用替换下面这行\n  const result = await Promise.resolve(undefined /* await targetFunction(payload) */);\n  assert.ok(!String(result ?? '').includes('uid='), '载荷不应被执行');\n  assert.ok(!String(result ?? '').includes('/etc/passwd'), '不应读取任意文件');\n});\n`;
  }
  if (language === 'python') {
    return `# 回归测试建议（由 ArmorBreak sast.patch_suggestion 生成，需人工补全目标函数导入）\n# 覆盖: ${idNote} (${label}); 目标: ${location}\n# 攻击载荷示例: ${payload}\nimport pytest\n\n# from app.target import target_function\n\ndef test_${String(ruleHint ?? 'vuln').replace(/[^a-z0-9]+/gi, '_').toLowerCase()}_rejects_payload():\n    payload = ${JSON.stringify(payload)}\n    # 用带 payload 的调用替换下面这行\n    result = None  # target_function(payload)\n    assert 'uid=' not in str(result or ''), '载荷不应被执行'\n    assert '/etc/passwd' not in str(result or ''), '不应读取任意文件'\n`;
  }
  if (language === 'java') {
    return `${header}class RegressionTest {\n  // @Test\n  void rejectsPayload() {\n    String payload = ${JSON.stringify(payload)};\n    // String result = Target.targetFunction(payload);\n    // assertFalse(result.contains("uid="));\n  }\n}\n`;
  }
  if (language === 'go') {
    return `${header}package main\n\nimport "testing"\n\nfunc TestRejectsPayload(t *testing.T) {\n\tpayload := ${JSON.stringify(payload)}\n\t_ = payload\n\t// result, err := TargetFunction(payload)\n\t// if err == nil && strings.Contains(result, "uid=") {\n\t// \tt.Fatal("payload executed")\n\t// }\n}\n`;
  }
  return `${header}// 请按目标语言补充断言：攻击载荷 “${payload}” 不应被执行/读取。\n`;
}

/**
 * Normalize a caller-provided finding-ish object.
 * Accepts options.finding or JSON-parsed input.text.
 */
export function extractFindingInput(text, options = {}) {
  let candidate = null;
  if (options.finding && typeof options.finding === 'object' && !Array.isArray(options.finding)) {
    candidate = options.finding;
  } else if (typeof text === 'string' && text.trim()) {
    const raw = text.replace(/^\uFEFF/, '').trim();
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(
        `finding 输入不是合法 JSON：${error.message}。请把待修复的 finding 对象（至少含 title/target/cwe）作为 JSON 传入，` +
          '或通过 options.finding 传递。',
      );
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) candidate = parsed;
  }
  if (!candidate) {
    throw new Error(
      '未提供 finding：sast.patch_suggestion 需要一条待修复的 finding（来自 sast.scan 等能力的输出）。' +
        ' 请通过 options.finding 传入对象，或在 input.text 中提供该 finding 的 JSON。',
    );
  }
  if (!candidate.title && !candidate.description && !candidate.target) {
    throw new Error(
      'finding 缺少可用字段：至少需要 title 或 target 之一，用于生成修复建议与回归测试。' +
        ' 建议直接传回 sast.scan 输出的完整 finding 对象。',
    );
  }
  return candidate;
}

/**
 * Build an illustrative patch + regression test from one finding.
 * @returns {{summary:string, findings:object[], evidence:object[], data:object, artifacts:object[]}}
 */
export function buildPatchSuggestion(findingInput, opts = {}) {
  const finding = findingInput && typeof findingInput === 'object' ? findingInput : {};
  const title = clip(finding.title ?? finding.description ?? 'finding', 300);
  const ruleHint = (/^\[([a-z0-9_-]+)\]/i.exec(String(finding.title ?? '')) || [])[1] ?? null;
  const cweMatch = /CWE-(\d+)/.exec(String(finding.cwe ?? ''));
  const cweNumber = cweMatch ? cweMatch[1] : null;

  let file = opts.file ?? null;
  let line = Number.isFinite(opts.line) ? Number(opts.line) : null;
  const targetRaw = typeof finding.target === 'string' ? finding.target.trim() : '';
  if (!file && targetRaw) {
    const targetMatch = /^(.+):(\d+)$/.exec(targetRaw);
    if (targetMatch) {
      file = targetMatch[1];
      line = line ?? Number(targetMatch[2]);
    } else {
      file = targetRaw;
    }
  }
  if (!file && Array.isArray(finding.evidence) && finding.evidence[0]?.title) {
    const evidenceMatch = /^(.+):(\d+)$/.exec(String(finding.evidence[0].title));
    if (evidenceMatch) {
      file = evidenceMatch[1];
      line = line ?? Number(evidenceMatch[2]);
    }
  }
  if (file) file = file.replace(/\\/g, '/');
  const language = languageForFile(file ?? '') ?? opts.language ?? null;
  const guidance = cweNumber ? CWE_GUIDANCE[`CWE-${cweNumber}`] : null;
  const label = guidance?.label ?? '安全缺陷';
  const replacement = (guidance && language && guidance.replacement[language]) || (guidance && guidance.replacement.javascript) || '// 按 CWE 指引修复：校验输入、使用安全 API、补充回归测试';

  let originalLine = null;
  if (typeof opts.codeLine === 'string' && opts.codeLine.trim()) {
    originalLine = opts.codeLine.replace(/\r?\n$/, '');
  } else if (Array.isArray(finding.evidence) && typeof finding.evidence[0]?.excerpt === 'string') {
    const excerpt = finding.evidence[0].excerpt;
    if (excerpt && excerpt.length <= 500 && !excerpt.startsWith('[')) originalLine = excerpt.replace(/\r?\n$/, '');
  }
  const illustrative = !originalLine;
  const relativeFile = file ? clip(file, 300) : '(unknown file)';
  const lineNumber = line ?? 1;
  const removedLine = originalLine ?? `<<${label} 的原始代码行：finding 未携带源码，请按 ${relativeFile}:${lineNumber} 手动替换>>`;
  const diff = [
    `--- a/${relativeFile}`,
    `+++ b/${relativeFile}`,
    `@@ -${lineNumber},1 +${lineNumber},1 @@`,
    `-${removedLine}`,
    `+${replacement}`,
  ].join('\n');

  const payload = guidance?.payload ?? '恶意输入';
  const regressionTest = testSkeleton(language, { label, payload, file: relativeFile, cwe: cweNumber ?? 'unknown', ruleHint });
  const testFileName = LANGUAGE_TEST_FILE[language] ?? 'regression_test.txt';

  const data = {
    title,
    ruleHint,
    cwe: cweNumber ? `CWE-${cweNumber}` : null,
    severity: finding.severity ?? null,
    file: file ? clip(file, 400) : null,
    line: lineNumber,
    language,
    originalProvided: !illustrative,
    illustrative,
    diff,
    regressionTest,
    remediation: clip(finding.remediation ?? '', 2000),
    applyPolicy: 'manual-only',
    disclaimer:
      '该 diff 为修复方向示意：' +
      (illustrative
        ? '原代码行未随 finding 提供，删除行是占位说明而非真实代码。'
        : '仅替换了命中行，实际修复需结合上下文与调用方。') +
      ' 本能力不会写文件、不会自动应用补丁。',
  };

  const summary = compact(
    `针对 “${title}”${data.cwe ? `（${data.cwe}）` : ''} 生成修复建议：目标 ${relativeFile}:${lineNumber}，` +
      `语言 ${language ?? 'unknown'}，${illustrative ? '示意 diff（缺原始代码行）' : '基于命中行的最小 diff'}；` +
      '同时给出回归测试骨架。未自动应用，需人工审核后手动修改。',
    4000,
  );

  return {
    summary,
    findings: [],
    evidence: [
      {
        title: '建议的修复 diff',
        kind: 'suggested-patch',
        excerpt: clip(diff, 2000),
        meta: { file: relativeFile, line: lineNumber, illustrative },
      },
    ],
    data,
    artifacts: [
      { name: 'suggested-patch.diff', content: diff, contentType: 'text/x-diff' },
      { name: testFileName, content: regressionTest, contentType: 'text/plain' },
    ],
  };
}

export { CWE_GUIDANCE, baseName };
