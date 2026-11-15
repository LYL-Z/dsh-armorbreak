import { diagnoseHostBundle } from '../../integrations/dshDiagnosticBundle.js'
export default { domain: 'diagnostics', capabilities: [{
  id: 'host.diagnostics', title: 'Composite read-only host diagnostics', riskLevel: 'L0', targetKind: 'directory',
  description: 'Compose disk identity, profile, literal anchor, configuration and local plugin checks through one scoped Core task.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (Object.keys(input.options ?? {}).length) throw new Error('host.diagnostics accepts no options')
    const data = await diagnoseHostBundle(input)
    return { summary: `Host diagnostics: ${data.status}; runtime UNKNOWN`, data,
      evidence: [{ kind: 'host-diagnostics', title: 'Composite disk diagnostics', excerpt: JSON.stringify(data) }],
      artifacts: [{ name: 'host-diagnostics.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
  },
}] }
