/**
 * Static help text shared by the tools module. Kept out of tools.js so the
 * narrative can be reused by docs without importing the Cordis plugin.
 * @module dsh-armorbreak/lib/core/help
 */

export const POLICY_TOOL_DOC = {
  riskLevels: {
    L0: '离线只读分析：默认允许，但目标必须在任务工作区内或有有效授权覆盖。',
    L1: '本地动态分析：必须有可用的容器/虚拟机隔离提供者，并通过平台审批；默认拒绝。',
    L2: '授权范围内的主动安全测试：必须有覆盖该目标的授权记录、平台审批、速率限制；默认拒绝。',
    L3: '可能造成破坏/数据泄露/持久化的操作：始终拒绝，不提供自动执行通道。',
  },
  evidence: '每条证据包含 SHA-256、脱敏摘录与哈希链；报告中的每条发现必须能追溯到证据 id。',
  honesty: '扫描告警不等于漏洞；启发式结论使用 hypothesis/unverified 标注；缺失能力必须明示。',
}

export default POLICY_TOOL_DOC
