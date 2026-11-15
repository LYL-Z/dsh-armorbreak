export default {
  domain: 'configuration-import', capabilities: [{
    id: 'configuration.convert', title: 'Strict data-only YAML, Cordis and Purge preset import preview',
    riskLevel: 'L0', targetKind: 'file', sensitiveInput: true,
    description: 'Validate and convert data in memory; export only a redacted result, never host writes or plugin execution.',
    params: { type: 'object', properties: {}, additionalProperties: false },
    async run(input) {
      if (Object.keys(input.options ?? {}).length || !input.buffer || input.buffer.length > 1024 * 1024 || input.env?.targetTruncated) throw new Error('complete bounded configuration import envelope required')
      let data
      try {
        const { importConfiguration } = await import('../../integrations/configFormats.js')
        data = importConfiguration(JSON.parse(input.buffer.toString('utf8'))).preview
      } catch { throw new Error('configuration import rejected: invalid, unsupported data or missing locked runtime dependency') }
      return { summary: 'Configuration converted in memory; no host write or plugin execution', data,
        evidence: [{ title: 'Configuration import', kind: 'configuration-import', excerpt: JSON.stringify(data) }],
        artifacts: [{ name: 'configuration-import.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
    },
  }],
}
