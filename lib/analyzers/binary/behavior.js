/**
 * Binary domain — behavior-level heuristics (v1.2.0 Advanced Research).
 *
 * Aggregates the v1.1 `binary.identify` model (imports, sections, packer/overlay
 * clues) into capability categories and suspicious combinations. This is a
 * static, hypothesis-level capability: it never executes the sample and never
 * claims a behavior was observed at runtime.
 * @module dsh-armorbreak/lib/analyzers/binary/behavior
 */
import { identify, SUSPICIOUS_IMPORTS } from './identify.js'
import { makeEvidence, makeFinding, sanitizeText } from './util.js'

const COMBOS = [
  {
    id: 'injection-execution',
    requires: ['process-injection', 'execution'],
    severity: 'high',
    title: '导入表同时具备进程注入与执行能力',
    description: '进程注入类 API 与进程/命令执行 API 同时出现，常见于加载器、注入器与后门；正常软件也可能组合使用，需复核调用链与参数。',
  },
  {
    id: 'credential-exfiltration',
    requires: ['credential-access', 'network'],
    severity: 'high',
    title: '导入表同时具备凭据访问与网络能力',
    description: '凭据读取类 API 与网络 API 同时出现，可能支持凭据窃取/外传链；必须结合字符串、配置与授权证据判断，不能仅凭导入定性。',
  },
  {
    id: 'persistence-execution',
    requires: ['persistence', 'execution'],
    severity: 'medium',
    title: '导入表同时具备持久化与执行能力',
    description: '服务/注册表持久化 API 与执行 API 组合，常见于安装器与驻留组件；需区分合法安装器与恶意持久化。',
  },
  {
    id: 'anti-debug-injection',
    requires: ['anti-debug', 'process-injection'],
    severity: 'medium',
    title: '导入表同时具备反调试与注入能力',
    description: '反调试与注入 API 组合，常见于需要规避分析的工具；也可能是带版权保护的商业软件。',
  },
  {
    id: 'collection-network',
    requires: ['file-collection', 'network'],
    severity: 'high',
    title: '导入表同时具备文件收集与网络能力',
    description: '文件枚举/复制与网络 API 组合，可能支持收集-外传行为；正常同步/备份软件也符合该模式，需结合目标与配置判断。',
  },
]

const CATEGORY_LABELS = {
  'process-injection': '进程注入',
  'anti-debug': '反调试',
  persistence: '持久化',
  'credential-access': '凭据访问',
  network: '网络通信',
  'file-collection': '文件收集',
  execution: '执行',
}

/**
 * @param {Buffer} buffer
 * @param {{maxItems:number,maxStrings:number,maxFindings:number,maxBytes?:number}} limits
 */
export function analyzeBehavior(buffer, limits) {
  const identified = identify(buffer, limits)
  const model = identified.data ?? {}
  const categories = {}
  const apiIndex = {}
  const libraries = model.imports?.libraries ?? []
  for (const lib of libraries) {
    const names = [
      ...(lib.functions ?? []).map((fn) => (typeof fn === 'string' ? fn : fn?.name)),
      ...(lib.sample ?? []),
    ].filter((name) => typeof name === 'string' && name.length > 0)
    for (const name of names) {
      const fnName = sanitizeText(name, 160)
      if (!fnName) continue
      for (const [category, pattern] of SUSPICIOUS_IMPORTS) {
        if (!pattern.test(fnName)) continue
        categories[category] ??= []
        if (categories[category].length < 40 && !categories[category].includes(fnName)) categories[category].push(fnName)
        apiIndex[category] ??= []
        if (apiIndex[category].length < 80 && !apiIndex[category].includes(fnName)) apiIndex[category].push(fnName)
      }
    }
  }
  const hits = Object.keys(categories)
  const matchedCombos = COMBOS.filter((combo) => combo.requires.every((category) => hits.includes(category)))

  const score = Math.min(
    100,
    hits.length * 8
      + matchedCombos.reduce((sum, combo) => sum + (combo.severity === 'high' ? 25 : 15), 0)
      + (model.packer?.detected ? 12 : 0)
      + ((model.sections ?? []).some((section) => typeof section.entropy === 'number' && section.entropy >= 7.2) ? 8 : 0),
  )
  const severity = score >= 60 ? 'high' : score >= 35 ? 'medium' : hits.length > 0 ? 'low' : 'info'

  /** @type {any[]} */
  const findings = []
  if (hits.length > 0) {
    findings.push(makeFinding({
      title: `导入/结构行为启发式：${hits.length} 类敏感能力`,
      severity,
      description: `静态导入表命中 ${hits.map((category) => CATEGORY_LABELS[category] ?? category).join('、')} 共 ${hits.length} 类；启发式得分 ${score}/100。该评分只表示“具备相应 API 能力”，不代表已执行或已确认恶意行为。`,
      verification: 'hypothesis',
      method: '导入函数名类别匹配 + 节熵/加壳/overlay 结构线索加权（静态，不执行样本）',
      cwe: null,
      cvss: null,
      remediation: '在授权且隔离的环境中复核调用链、参数、配置与签名来源；需要动态证据时使用 L1，并保留原始样本哈希与证据链。不要仅凭导入或评分定性。',
      target: null,
      evidence: [makeEvidence('敏感 API 类别', 'binary-behavior', JSON.stringify({ categoryCount: hits.length, categories: apiIndex, score }).slice(0, 2500))],
    }))
  }
  for (const combo of matchedCombos) {
    findings.push(makeFinding({
      title: `行为组合：${combo.title}`,
      severity: combo.severity === 'high' ? 'high' : 'medium',
      description: `${combo.description} 触发类别：${combo.requires.map((category) => CATEGORY_LABELS[category] ?? category).join(' + ')}。验证级别为 hypothesis，需独立证据复核。`,
      verification: 'hypothesis',
      method: `导入类别组合匹配（${combo.requires.join(' + ')}）`,
      cwe: null,
      cvss: null,
      remediation: '复核这些 API 的调用点、参数与数据来源；结合来源信誉、签名与动态行为判断，不要仅凭组合定性。',
      target: null,
      evidence: [makeEvidence(`组合 ${combo.id}`, 'binary-behavior-combo', JSON.stringify({ combo: combo.id, requires: combo.requires, apis: combo.requires.map((category) => apiIndex[category] ?? []) }).slice(0, 2000))],
    }))
  }

  const sections = Array.isArray(model.sections) ? model.sections : []
  const highEntropySections = sections.filter((section) => typeof section.entropy === 'number' && section.entropy >= 7.2).map((section) => ({ name: section.name, entropy: section.entropy, rawSize: section.rawSize }))
  const data = {
    format: model.format ?? 'unknown',
    container: model.container ?? null,
    score,
    severity,
    verification: 'hypothesis',
    categoryCount: hits.length,
    categories: apiIndex,
    combos: matchedCombos.map((combo) => ({ id: combo.id, severity: combo.severity, requires: combo.requires, title: combo.title })),
    importSummary: { dllCount: model.imports?.dllCount ?? 0, functionCount: model.imports?.functionCount ?? 0 },
    packer: model.packer ? { detected: Boolean(model.packer.detected), suspectedFamily: model.packer.suspectedFamily ?? null, score: model.packer.score ?? null } : null,
    overlay: model.overlay ? { present: Boolean(model.overlay.present), size: model.overlay.size ?? 0 } : null,
    highEntropySections: highEntropySections.slice(0, 20),
    limitations: [
      '静态导入名/结构启发式，不证明调用、参数或运行时行为；',
      'API 可能通过动态解析/加壳隐藏，导入表缺失时评分会偏低；',
      '评分与组合不是漏洞结论，升级验证级别需要独立证据。',
    ],
  }
  const summary = [
    `行为启发式：${data.format}，得分 ${score}/100（${severity}），命中 ${hits.length} 类敏感能力。`,
    matchedCombos.length > 0 ? `可疑组合：${matchedCombos.map((combo) => combo.title).join('；')}` : '未命中预定义的高风险 API 组合。',
    `导入 ${data.importSummary.dllCount} 个 DLL / ${data.importSummary.functionCount} 个函数；加壳启发式 ${data.packer?.detected ? '命中' : '未命中'}；高风险熵节 ${highEntropySections.length} 个。`,
    '全部结论为 hypothesis：如需确认，请结合调用链/签名/动态证据复核。',
  ].join('\n')

  return {
    format: data.format,
    summary,
    data,
    findings: findings.slice(0, limits.maxFindings ?? 200),
    evidence: [
      makeEvidence('行为启发式汇总', 'binary-behavior', JSON.stringify({ score, severity, categories: apiIndex, combos: data.combos }).slice(0, 2500)),
      ...highEntropySections.slice(0, 4).map((section) => makeEvidence(`高熵节 ${section.name}`, 'binary-section-entropy', JSON.stringify(section))),
    ].slice(0, 8),
  }
}
