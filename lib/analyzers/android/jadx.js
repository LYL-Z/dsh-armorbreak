/**
 * JADX external adapter (v1.2.0).
 *
 * Decompiles an APK/DEX/JAR into a temp directory, indexes packages/classes/
 * methods and risky APIs, then deletes the temp output. Source text is never
 * returned; only bounded counts and small API-name evidence are exposed.
 * @module dsh-armorbreak/lib/analyzers/android/jadx
 */
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join, relative } from 'node:path'
import { executeTool, resolveJadx, EXTERNAL_TOOL_GUIDANCE } from '../../core/externalTools.js'

const RISKY_APIS = [
  { name: 'Runtime.exec', pattern: /Runtime\.getRuntime\(\)\.exec|\bRuntime\.exec\b/ },
  { name: 'ProcessBuilder', pattern: /ProcessBuilder\b/ },
  { name: 'DexClassLoader', pattern: /DexClassLoader\b/ },
  { name: 'reflection', pattern: /Class\.forName|getDeclaredMethod|setAccessible\s*\(/ },
  { name: 'WebView JS bridge', pattern: /addJavascriptInterface\s*\(/ },
  { name: 'crypto', pattern: /Cipher\.getInstance|SecretKeySpec|MessageDigest\.getInstance/ },
  { name: 'network', pattern: /HttpURLConnection|OkHttpClient|Socket\s*\(/ },
]

/** @param {{path:string,text:string}[]} files @param {{maxFiles?:number,maxFindings?:number}} [options] */
export function summarizeJadxSources(files, options = {}) {
  const maxFiles = Math.max(1, Math.min(Number(options.maxFiles ?? 500), 5000))
  const maxFindings = Math.max(1, Math.min(Number(options.maxFindings ?? 200), 1000))
  const packages = new Set()
  const classes = new Set()
  const methods = new Set()
  const apiHits = {}
  let scanned = 0
  for (const file of files.slice(0, maxFiles)) {
    if (!file || typeof file.text !== 'string') continue
    scanned += 1
    const text = file.text
    const pkg = text.match(/^\s*package\s+([\w.]+)\s*;/m)?.[1]
    if (pkg) packages.add(pkg)
    for (const match of text.matchAll(/\b(?:class|interface|enum)\s+([A-Za-z_$][\w$]*)/g)) classes.add(match[1])
    for (const match of text.matchAll(/^\s*(?:public|private|protected|static|final|synchronized|native|abstract|\s)+\s*[\w<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\(/gm)) methods.add(match[1])
    for (const api of RISKY_APIS) {
      if (!api.pattern.test(text)) continue
      apiHits[api.name] ??= []
      if (apiHits[api.name].length < 20 && !apiHits[api.name].includes(file.path)) apiHits[api.name].push(relative(String(options.root ?? '.'), file.path))
    }
  }
  const findings = []
  const riskyCount = Object.keys(apiHits).length
  if (riskyCount > 0) {
    findings.push({
      title: `JADX 反编译索引命中 ${riskyCount} 类敏感 API`,
      severity: 'low',
      description: `命中类别：${Object.keys(apiHits).join('、')}。这些 API 在合法应用中也很常见，必须结合调用参数、数据流与业务上下文复核；本结论为 hypothesis。`,
      verification: 'hypothesis',
      method: 'JADX 反编译源码 + 敏感 API 正则索引（静态，不执行）',
      cwe: null,
      cvss: null,
      remediation: '在授权环境中复核命中方法与数据流；不要仅凭 API 名定性。',
      target: null,
      evidence: [{ title: '敏感 API 位置样本', kind: 'jadx-api-index', excerpt: JSON.stringify(apiHits).slice(0, 2000), meta: {} }],
    })
  }
  const data = {
    filesScanned: scanned,
    truncated: files.length > maxFiles,
    packages: [...packages].slice(0, 100),
    classCount: classes.size,
    methodCount: methods.size,
    apiCategories: Object.fromEntries(Object.entries(apiHits).map(([key, value]) => [key, value.slice(0, 10)])),
    verification: 'hypothesis',
    tool: 'jadx',
    sourceReturned: false,
  }
  return {
    summary: `JADX：扫描 ${scanned} 个源文件，${packages.size} 个包、${classes.size} 个类、${methods.size} 个方法；敏感 API ${riskyCount} 类。源码未回传，仅保留计数与位置样本。`,
    findings: findings.slice(0, maxFindings),
    evidence: [{ title: 'JADX 反编译索引', kind: 'jadx-index', excerpt: JSON.stringify({ packages: data.packages.slice(0, 20), classes: classes.size, methods: methods.size, apis: Object.keys(apiHits) }), meta: {} }],
    data,
  }
}

function collectJavaFiles(root, maxFiles = 5000) {
  /** @type {{path:string,text:string}[]} */
  const files = []
  const walk = (dir) => {
    if (files.length >= maxFiles) return
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) return
      const full = join(dir, entry.name)
      if (entry.isDirectory()) walk(full)
      else if (entry.isFile() && entry.name.endsWith('.java')) {
        try {
          const text = readFileSync(full, 'utf8').slice(0, 200_000)
          files.push({ path: full, text })
        } catch {
          /* skip unreadable decompiled files */
        }
      }
    }
  }
  walk(root)
  return files
}

export const jadxCapability = {
  id: 'android.jadx',
  title: 'JADX 反编译索引（外部工具）',
  description: '调用本机 JADX 将 APK/DEX/JAR 反编译到临时目录，索引包/类/方法数量与敏感 API 位置，随后删除反编译输出。源码不进入模型上下文；结论为 hypothesis；缺失工具/JRE fail-closed 并给出安装指引。',
  riskLevel: 'L0',
  targetKind: 'file',
  params: {
    type: 'object',
    properties: {
      maxFiles: { type: 'integer', minimum: 1, maximum: 5000, description: '最多索引的反编译文件数，默认 500。' },
    },
    additionalProperties: false,
  },
  async run(input) {
    const targetPath = input.targetPath ?? null
    if (!targetPath) throw new Error('android.jadx needs an APK/DEX/JAR target')
    if (!existsSync(targetPath)) throw new Error(`input file not found: ${targetPath}`)
    const isSeam = typeof input.env?.execExternal === 'function'
    const tool = isSeam ? { command: 'jadx', prefixArgs: [] } : resolveJadx(process.env)
    const outputRoot = mkdtempSync(join(tmpdir(), 'abm-jadx-'))
    try {
      const args = isSeam
        ? ['-d', outputRoot, targetPath]
        : ['-d', outputRoot, '--no-res', '--no-imports', targetPath]
      try {
        await executeTool(input.env, tool, args, { timeoutMs: input.limits?.timeoutMs ?? 300_000, maxOutputBytes: 32 * 1024 * 1024 })
      } catch (error) {
        throw new Error(`android.jadx failed: ${String(error?.message ?? error)} ${EXTERNAL_TOOL_GUIDANCE.jadx}`.trim())
      }
      const files = collectJavaFiles(outputRoot, Math.max(1, Math.min(Number(input.options?.maxFiles ?? 500), 5000)))
      if (files.length === 0) throw new Error('JADX produced no .java files; the input may not be a valid APK/DEX/JAR')
      const parsed = summarizeJadxSources(files, { ...input.options, root: outputRoot })
      return {
        ...parsed,
        meta: {
          domain: 'android', capability: 'android.jadx', tool: 'jadx', target: targetPath,
          inputBytes: statSync(targetPath).size, filesScanned: parsed.data.filesScanned, truncated: parsed.data.truncated,
        },
      }
    } finally {
      try {
        rmSync(outputRoot, { recursive: true, force: true })
      } catch {
        /* temp cleanup is best-effort */
      }
    }
  },
}
