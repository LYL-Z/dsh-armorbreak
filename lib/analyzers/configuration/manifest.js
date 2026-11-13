import { resolveConfig } from '../../integrations/configOverlay.js'
export default {
  domain: 'configuration', capabilities: [{
    id: 'configuration.preview', title: 'Data-only profile and overlay preview', riskLevel: 'L0', targetKind: 'file',
    description: 'Resolve bounded JSON layers without writing host configuration or granting authority.',
    params: { type: 'object', properties: {}, additionalProperties: false },
    async run(input) {
      if (Object.keys(input.options ?? {}).length) throw new Error('configuration.preview accepts no options')
      if (!input.buffer || input.buffer.length > 1024 * 1024 || input.env?.targetTruncated) throw new Error('complete JSON input of at most 1 MiB required')
      let bundle
      try { bundle = JSON.parse(input.buffer.toString('utf8')) } catch { throw new Error('invalid config overlay JSON') }
      const { preview: data } = resolveConfig(bundle)
      return { summary: `Configuration ${data.status}: ${data.changes.length} changes; no host write`, data,
        evidence: [{ title: 'Configuration preview', kind: 'configuration-preview', excerpt: JSON.stringify(data) }],
        artifacts: [{ name: 'configuration-preview.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
    },
  }],
}
