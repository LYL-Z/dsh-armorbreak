import { inspectDshHostHealth } from '../../integrations/dshHostHealth.js'

export default {
  domain: 'host',
  capabilities: [{
    id: 'host.health', title: 'Read-only Desktop host health',
    description: 'Inspect explicit workspace-scoped Desktop disk identity without executing host code.',
    riskLevel: 'L0', targetKind: 'directory',
    params: { type: 'object', properties: { expectedVersion: { type: 'string' } }, additionalProperties: false },
    async run(input) {
      if (Object.keys(input.options ?? {}).some(key => key !== 'expectedVersion')) throw new Error('unsupported host.health option')
      if (!input.env?.readFile) throw new Error('Core directory reader is required')
      const data = await inspectDshHostHealth({ resources: input.targetPath, readFile: input.env.readFile, expectedVersion: input.options?.expectedVersion })
      return { summary: `Host disk inspection: ${data.observation}; runtime UNKNOWN`, data,
        findings: [], evidence: [{ kind: 'host-health', title: 'Bounded disk observation', excerpt: JSON.stringify(data), meta: { runtimeVerified: false } }],
        artifacts: [{ name: 'host-health.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }],
        meta: { inputCompleteness: data.layoutStatus === 'DISK_PACKAGE_FOUND' ? 'complete' : 'partial', runtimeVerified: false } }
    },
  }],
}
