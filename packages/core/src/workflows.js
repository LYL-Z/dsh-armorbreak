/**
 * Reusable analysis workflow definitions. A workflow is an ordered list of
 * capability steps over one target; the runner adds scope checks, approvals,
 * evidence collection, failure isolation, and reporting.
 * @module dsh-armorbreak/lib/core/workflows
 */

/**
 * @typedef {{id: string, title: string, capabilityId: string, options?: Record<string, unknown>}} WorkflowStep
 * @typedef {{id: string, title: string, description: string, targetKind: 'file'|'directory'|'none', steps: WorkflowStep[]}} WorkflowDefinition
 */

/** @type {Record<string, WorkflowDefinition>} */
export const WORKFLOWS = {
  UniversalArtifactTriage: {
    id: 'UniversalArtifactTriage',
    title: '通用产物清点与归档索引',
    description: '对授权的本地项目目录做有界文件清单、格式候选识别与 ZIP/TAR/GZIP 内嵌关系索引；成员只在内存中读取，不执行或写出样本。',
    targetKind: 'directory',
    steps: [
      { id: 'inventory', title: '产物识别与递归清单', capabilityId: 'artifact.inventory' },
    ],
  },
  CrossLanguageSourceReview: {
    id: 'CrossLanguageSourceReview',
    title: '跨语言源码符号审查',
    description: '从授权本地目录中为 JS/TS 文件生成 S2 语法、符号、导入导出与同文件引用；其他语言、跨文件解析、类型语义和数据流会明确报告为覆盖限制。',
    targetKind: 'directory',
    steps: [
      { id: 'symbols', title: 'JS/TS 符号与引用索引', capabilityId: 'source.symbols' },
    ],
  },
  BinaryStaticAnalysis: {
    id: 'BinaryStaticAnalysis',
    title: '二进制静态分析',
    description: '对 PE/ELF/Mach-O 样本做格式识别、结构、函数/符号、字符串、熵、哈希与 IOC 关联，全程离线、不执行样本。',
    targetKind: 'file',
    steps: [
      { id: 'identify', title: '格式与架构识别', capabilityId: 'binary.identify' },
      { id: 'headers', title: '头/节/加载命令解析', capabilityId: 'binary.headers' },
      { id: 'structure', title: '符号、导入导出与函数线索', capabilityId: 'binary.structure' },
      { id: 'strings', title: '字符串提取与分类', capabilityId: 'binary.strings' },
      { id: 'entropy', title: '熵与加壳/加密线索', capabilityId: 'binary.entropy' },
      { id: 'hash', title: '哈希与文件指纹', capabilityId: 'forensics.hash' },
      { id: 'ioc', title: 'IOC 提取', capabilityId: 'forensics.ioc' },
    ],
  },
  AndroidAPKReview: {
    id: 'AndroidAPKReview',
    title: 'Android APK 安全审计',
    description: 'APK 结构、二进制 Manifest、DEX、签名与权限/组件暴露审计，全程离线。',
    targetKind: 'file',
    steps: [
      { id: 'structure', title: 'APK 包结构', capabilityId: 'android.apk_structure' },
      { id: 'manifest', title: 'Manifest 与组件审计', capabilityId: 'android.manifest' },
      { id: 'dex', title: 'DEX 概况', capabilityId: 'android.dex' },
      { id: 'signing', title: '签名信息', capabilityId: 'android.signing' },
      { id: 'findings', title: '安全发现汇总', capabilityId: 'android.findings' },
    ],
  },
  WebCodeSecurityReview: {
    id: 'WebCodeSecurityReview',
    title: 'Web/源码安全审计',
    description: '对本地代码目录做危险调用、敏感信息、依赖与供应链审计，产出 CWE 映射与修复建议。',
    targetKind: 'directory',
    steps: [
      { id: 'scan', title: '危险调用与污点线索扫描', capabilityId: 'sast.scan', failurePolicy: 'continue-independent' },
      { id: 'secrets', title: '硬编码密钥检测', capabilityId: 'sast.secrets', dependsOn: [] },
      { id: 'deps', title: '依赖清单审计', capabilityId: 'sast.deps', dependsOn: [] },
      { id: 'sbom', title: 'SBOM 生成', capabilityId: 'sast.sbom', dependsOn: ['deps'] },
    ],
  },
  PCAPInvestigation: {
    id: 'PCAPInvestigation',
    title: 'PCAP 流量取证分析',
    description: '离线解析 PCAP/PCAPNG：会话、DNS、TLS 元数据、HTTP、IOC 与异常模式。',
    targetKind: 'file',
    steps: [
      { id: 'overview', title: '抓包总览', capabilityId: 'network.pcap_overview' },
      { id: 'flows', title: '会话重建', capabilityId: 'network.flows' },
      { id: 'dns', title: 'DNS 分析', capabilityId: 'network.dns' },
      { id: 'tls', title: 'TLS 元数据', capabilityId: 'network.tls' },
      { id: 'http', title: 'HTTP 明文分析', capabilityId: 'network.http' },
      { id: 'iocs', title: 'IOC 提取', capabilityId: 'network.iocs' },
      { id: 'anomalies', title: '异常通信模式', capabilityId: 'network.anomalies' },
    ],
  },
  DependencyAudit: {
    id: 'DependencyAudit',
    title: '依赖与供应链审计',
    description: '对代码目录的依赖清单做盘点、SBOM 生成与密钥泄漏检查；缺少漏洞库时不伪造 CVE 结论。',
    targetKind: 'directory',
    steps: [
      { id: 'deps', title: '依赖盘点与启发式', capabilityId: 'sast.deps' },
      { id: 'sbom', title: 'CycloneDX SBOM', capabilityId: 'sast.sbom' },
      { id: 'secrets', title: '密钥泄漏检查', capabilityId: 'sast.secrets' },
    ],
  },
  CTFArtifactAnalysis: {
    id: 'CTFArtifactAnalysis',
    title: 'CTF 题目产物分析',
    description: '题目文件分类、哈希识别、编码/古典密码启发式与 flag 模式扫描；仅用于本地题目与靶场。',
    targetKind: 'file',
    steps: [
      { id: 'classify', title: '文件/编码分类', capabilityId: 'ctf.classify' },
      { id: 'hash', title: '哈希识别', capabilityId: 'ctf.hash_id' },
      { id: 'crypto', title: '古典密码分析', capabilityId: 'ctf.crypto_basics' },
      { id: 'flag', title: 'Flag 模式扫描', capabilityId: 'ctf.flag_scan' },
    ],
  },
  ForensicFileReview: {
    id: 'ForensicFileReview',
    title: '数字取证文件审查',
    description: '文件类型、哈希、元数据、时间线、IOC 与规则匹配，形成可复核证据链。',
    targetKind: 'file',
    steps: [
      { id: 'filetype', title: '文件类型', capabilityId: 'forensics.filetype' },
      { id: 'hash', title: '哈希', capabilityId: 'forensics.hash' },
      { id: 'metadata', title: '元数据', capabilityId: 'forensics.metadata' },
      { id: 'timeline', title: '时间线', capabilityId: 'forensics.timeline' },
      { id: 'ioc', title: 'IOC', capabilityId: 'forensics.ioc' },
      { id: 'yara', title: '规则匹配（启发式）', capabilityId: 'forensics.yara_lite' },
    ],
  },
  WebAPIReview: {
    id: 'WebAPIReview',
    title: 'Web API 规范审计',
    description: '审计 OpenAPI 规范与 HAR 记录：认证/授权、安全响应头、Cookie、CORS、敏感参数。',
    targetKind: 'file',
    steps: [
      { id: 'openapi', title: 'OpenAPI 规范审计', capabilityId: 'web.openapi' },
      { id: 'har', title: 'HAR 记录审计', capabilityId: 'web.har' },
    ],
  },
  SecurityReportGeneration: {
    id: 'SecurityReportGeneration',
    title: '安全研究报告生成',
    description: '不执行分析，仅从任务已有证据/发现生成报告（Markdown/HTML/JSON/SARIF/PDF）。',
    targetKind: 'none',
    steps: [],
  },
}

/**
 * Resolve a workflow by id (also accepts the exact id with different case).
 * @param {string} id
 * @returns {WorkflowDefinition}
 */
export function getWorkflow(id) {
  if (!id) throw new Error('workflow id is required')
  const direct = WORKFLOWS[id]
  if (direct) return direct
  const found = Object.values(WORKFLOWS).find((workflow) => workflow.id.toLowerCase() === String(id).toLowerCase())
  if (!found) {
    throw new Error(`unknown workflow "${id}"; available: ${Object.keys(WORKFLOWS).join(', ')}`)
  }
  return found
}

/** @returns {Array<{id: string, title: string, description: string, targetKind: string, steps: number}>} */
export function listWorkflows() {
  return Object.values(WORKFLOWS).map((workflow) => ({
    id: workflow.id,
    title: workflow.title,
    description: workflow.description,
    targetKind: workflow.targetKind,
    steps: workflow.steps.length,
  }))
}
