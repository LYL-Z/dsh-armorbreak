/**
 * Preset-scoped skills plugin: registers ArmorBreak's professional skill bodies
 * into the calling preset's skill layer. Bodies live in ../skills/*.md and are
 * read at activation so they ship with the bundle (no external directory).
 * @module dsh-armorbreak/skills
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const inject = ['skills']

const SKILLS = [
  {
    name: 'armorbreak-binary-analysis',
    file: 'binary-static-analysis.md',
    description: '离线二进制静态分析流程：格式/架构识别、头与节、导入导出、字符串、熵与加壳判定、证据化结论，不执行样本。',
    whenToUse: '分析 PE/ELF/Mach-O 样本、做恶意样本初筛、判断加壳/混淆、提取 IOC 或准备逆向报告时。',
  },
  {
    name: 'armorbreak-android-audit',
    file: 'android-apk-audit.md',
    description: 'Android APK 离线审计流程：Manifest/组件暴露/权限/签名/明文流量与敏感配置的风险判定与降噪规则。',
    whenToUse: '拿到 APK、需要判断可导出组件/权限/签名/cleartext 风险，或输出移动应用安全评估时。',
  },
  {
    name: 'armorbreak-pcap-investigation',
    file: 'pcap-investigation.md',
    description: 'PCAP/PCAPNG 离线取证流程：会话重建、DNS/TLS/HTTP 元数据、IOC 提取、异常通信启发式与可信度标注。',
    whenToUse: '分析抓包、排查可疑外联、提取 IOC、复盘事件时间线或撰写流量取证报告时。',
  },
  {
    name: 'armorbreak-code-review',
    file: 'sast-code-review.md',
    description: '源码与供应链安全审计流程：危险调用与污点线索、密钥泄漏、依赖/SBOM、CWE 映射、修复补丁与回归测试建议。',
    whenToUse: '审计本地代码仓库、评估依赖风险、检查硬编码密钥，或把扫描告警转成可复核发现时。',
  },
  {
    name: 'armorbreak-forensics-triage',
    file: 'forensics-triage.md',
    description: '数字取证初筛流程：哈希与证据完整性、元数据与时间线、IOC、规则匹配与证据链记录规范。',
    whenToUse: '对可疑文件做取证初筛、需要固定证据哈希/时间线，或准备可复现的取证说明时。',
  },
  {
    name: 'armorbreak-ctf-arena',
    file: 'ctf-arena.md',
    description: 'CTF 与本地靶场分析流程：文件/编码分类、递归解码、古典密码与哈希识别、flag 提取与实验记录。',
    whenToUse: '解 CTF 题目、做本地靶场实验、分析编码/古典密码或整理可复现的解题步骤时。',
  },
  {
    name: 'armorbreak-report-writing',
    file: 'report-writing.md',
    description: '安全研究报告规范：发现结构、严重程度与 CVSS 依据、验证状态、影响/修复/复测、证据链与不确定性表达。',
    whenToUse: '需要把分析结果整理成 Markdown/HTML/JSON/SARIF 报告，或复核报告是否有证据支撑时。',
  },
]

/** @param {string} file */
function readSkill(file) {
  return readFileSync(fileURLToPath(new URL(`../skills/${file}`, import.meta.url)), 'utf8')
}

/** @param {import('@deepseek-ai/cordis').Context} ctx */
export function apply(ctx) {
  for (const skill of SKILLS) {
    try {
      ctx.skills.register({
        name: skill.name,
        description: skill.description,
        whenToUse: skill.whenToUse,
        content: readSkill(skill.file),
        provider: 'armorbreak',
        resourceBase: {
          kind: 'opaque',
          description: 'Bundled with the ArmorBreak preset. Referenced tools are ArmorBreak tools (armorbreak_*) and built-in file/shell tools.',
        },
      })
    } catch (error) {
      ctx.logger?.warn?.(`[armorbreak] failed to register skill ${skill.name}: ${String(error?.message ?? error)}`)
    }
  }
}

export default { inject, apply }
