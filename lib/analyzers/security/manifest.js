import { correlateEvidenceBundle, EVIDENCE_BUNDLE_SCHEMA } from './correlator.js'

export default {
  domain: 'security',
  capabilities: [
    {
      id: 'security.correlate',
      title: '离线安全证据关联',
      description: `读取授权范围内的 ${EVIDENCE_BUNDLE_SCHEMA} JSON 文件，将 ArmorBreak finding、SARIF 2.1.0、Semgrep JSON、Trivy JSON、显式 OSV 匹配记录及 CycloneDX/SPDX 证据按 artifact SHA-256、位置、CWE/rule 和证据上下文做确定性关联；保留来源记录并生成 JSON/SARIF。全程离线，不运行样本、不访问网络；关联不等于漏洞确认。`,
      riskLevel: 'L0',
      targetKind: 'file',
      params: {
        type: 'object',
        properties: {
          asOfDate: { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}$', description: '可选的数据库快照评估日期；省略时 stale 状态为 unknown。' },
        },
        additionalProperties: false,
      },
      async run(input) {
        if (input.env?.targetTruncated) throw new Error('security evidence bundle was truncated; increase the bounded input limit before retrying')
        const result = correlateEvidenceBundle(input.buffer, { maxBytes: input.limits?.maxInputBytes, asOfDate: input.options?.asOfDate })
        if (input.env?.signal?.aborted) throw new Error('security evidence correlation cancelled')
        return result
      },
    },
  ],
}
