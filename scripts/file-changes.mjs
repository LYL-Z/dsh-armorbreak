/**
 * Generate docs/file-changes.md: the complete file inventory of the delivered
 * package (path, bytes, lines, one-line purpose derived from path/known map).
 * Usage: node scripts/file-changes.mjs
 */
import { readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const SKIP_DIRS = new Set(['.armorbreak', 'node_modules', '.git', 'coverage'])
const SKIP_FILES = new Set(['docs/file-changes.md'])

const PURPOSE = {
  'package.json': 'Bundle 清单（dsh.bundle.patch + dsh.client + 零依赖声明）',
  'cordis.patch.yml': '组合包 patch：Host 行 + preset-armorbreak 模式声明',
  'index.js': 'Host 半：只读状态路由 /armorbreak/state，webServer 注入',
  'client.js': '浏览器半：composer 状态卡（能力/隔离/策略/任务摘要）',
  'tools.js': 'preset 子插件：注册 8 个模型工具并桥接平台审批',
  'skills.js': 'preset 子插件：注册 7 个内置技能',
  'README.md': '项目总览、安装、能力与安全模型摘要',
  'CHANGELOG.md': '变更记录（1.0.4）',
  'LICENSE': 'MIT 许可证',
  'SECURITY.md': '安全政策与漏洞披露流程',
  'CONTRIBUTING.md': '贡献指南与能力适配器开发流程',
  'CODE_OF_CONDUCT.md': '社区行为准则',
  'icon.svg': '插件图标',
  'locale/en.json': '插件显示元数据（英文）',
  'locale/zh.json': '插件显示元数据（中文）',
  'docs/CONTRACT.md': '分析能力/适配器开发契约',
  'docs/architecture.md': '架构设计（分层、Cordis 组合、执行管线、数据模型）',
  'docs/security-model.md': '四级能力控制、授权/审批、路径与命令、隔离、审计',
  'docs/installation.md': '安装/启用/卸载/故障排查',
  'docs/usage.md': '使用指南与场景',
  'docs/compatibility-matrix.md': '运行时/API/外部工具/平台兼容性',
  'docs/known-issues.md': '已知问题与限制（诚实清单）',
  'docs/roadmap.md': '后续扩展路线图',
  'docs/acceptance.md': '验收报告（含实际测试与验证结果）',
  'docs/benchmarks.md': '性能基准：环境、数据、方法、复现',
  'docs/marketplace.md': 'DeepSeek Harness 生态、插件市场与分发指引',
  'docs/file-changes.md': '完整文件变更清单（本文件）',
  'docs/audit/environment-audit.md': 'Phase 0 环境与架构审计报告',
  'docs/releases/v1.0.0.md': 'v1.0.0 发布说明',
  'docs/releases/v1.0.1.md': 'v1.0.1 发布说明',
  'docs/releases/v1.0.2.md': 'v1.0.2 发布说明',
  'benchmarks/bench.mjs': '零依赖可复现微基准脚本',
  'benchmarks/results.json': '参考主机基准原始数据',
  'scripts/file-changes.mjs': '文件清单生成脚本',
  'scripts/clean-temp.mjs': '清理测试临时目录脚本',
  '.github/workflows/ci.yml': '双平台 CI：测试/覆盖率/基准/UTF-8 门禁',
  'docs/media/status-card.png': '模式状态卡真实截图',
  'docs/media/report-deliverables.webp': '报告交付物真实截图',
}

const PREFIX_PURPOSE = [
  ['lib/core/', '核心运行时模块'],
  ['lib/analyzers/', '分析能力实现（按域）'],
  ['skills/', '内置技能正文'],
  ['tests/', '自动化测试（node:test）'],
  ['scripts/', '开发/交付脚本'],
  ['dev/', '开发期测试 profile overlay（不随 bundle 安装生效）'],
]

/** @param {string} file */
function purpose(file) {
  if (PURPOSE[file]) return PURPOSE[file]
  const prefix = PREFIX_PURPOSE.find(([start]) => file.startsWith(start))
  if (prefix) return prefix[1]
  return ''
}

/** @param {string} dir */
async function walk(dir) {
  /** @type {string[]} */
  const out = []
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    if (entry.name.startsWith('.') && entry.isDirectory()) continue
    if (SKIP_DIRS.has(entry.name)) continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) out.push(...(await walk(full)))
    else if (!SKIP_FILES.has(relative(ROOT, full).replace(/\\/g, '/'))) out.push(full)
  }
  return out
}

/** @param {string} file */
async function lines(file) {
  try {
    const text = await readFile(file, 'utf8')
    return text.split('\n').length
  } catch {
    return 0
  }
}

const files = (await walk(ROOT)).sort((a, b) => relative(ROOT, a).localeCompare(relative(ROOT, b)))
const rows = []
let totalBytes = 0
let totalLines = 0
for (const file of files) {
  const info = await stat(file)
  const lineCount = await lines(file)
  totalBytes += info.size
  totalLines += lineCount
  const rel = relative(ROOT, file).replace(/\\/g, '/')
  rows.push(`| \`${rel}\` | ${info.size} | ${lineCount} | ${purpose(rel)} |`)
}

const domains = {}
const domainEntries = await readdir(join(ROOT, 'lib/analyzers'))
for (const domain of domainEntries) {
  const manifest = join(ROOT, 'lib/analyzers', domain, 'manifest.js')
  try {
    const module = await import(`file:///${manifest.replace(/\\/g, '/')}`)
    const caps = (module.default?.capabilities ?? []).map((capability) => capability.id)
    domains[domain] = caps
  } catch {
    domains[domain] = []
  }
}

const content = `# 完整文件变更清单（v1.0.4）

- 生成方式：\`node scripts/file-changes.mjs\`（遍历交付目录，排除 node_modules/.armorbreak）
- 文件总数：**${files.length}**
- 总大小：**${(totalBytes / 1024).toFixed(1)} KiB**
- 总行数：**${totalLines}**（含注释/文档）
- 运行时依赖：**0**（仅 Node 内置模块；无构建步骤）

## 能力清单（由 lib/analyzers/*/manifest.js 自动统计）

| 域 | 能力 |
|---|---|
${Object.entries(domains).map(([domain, caps]) => `| ${domain} | ${caps.length}：${caps.map((id) => `\`${id}\``).join('、')} |`).join('\n')}

## 文件清单

| 路径 | 字节 | 行数 | 说明 |
|---|---:|---:|---|
${rows.join('\n')}

## 说明

- 本清单覆盖交付源码、测试、文档与开发期 overlay；不含测试运行时产生的 \`.armorbreak/\` 数据。
- \`dev/*.yml\` 仅用于开发/验收期挂载测试，不随 bundle 安装生效。
- 未在此清单中的文件（如用户工作区里的 \`.armorbreak/tasks/*\`）是运行时产物，不是交付物。
`

await writeFile(join(ROOT, 'docs/file-changes.md'), content, 'utf8')
console.log(`wrote docs/file-changes.md : ${files.length} files, ${(totalBytes / 1024).toFixed(1)} KiB, ${totalLines} lines`)
for (const [domain, caps] of Object.entries(domains)) console.log(`  ${domain}: ${caps.length} capabilities`)
