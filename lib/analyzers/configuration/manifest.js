import { resolveConfig } from '../../integrations/configOverlay.js'
export default {
  domain: 'configuration', capabilities: [{
    id: 'configuration.preview', title: 'Data-only profile and overlay preview', riskLevel: 'L0', targetKind: 'file',
    sensitiveInput: true,
    description: 'Resolve bounded JSON layers or preview explicit data-only edits without writing host configuration or granting authority.',
    params: { type: 'object', properties: { mode: { enum: ['edit'] } }, additionalProperties: false },
    async run(input) {
      const options = input.options ?? {}
      if (Object.keys(options).some(key => key !== 'mode') || (Object.hasOwn(options, 'mode') && options.mode !== 'edit')) {
        throw new Error('configuration.preview accepts only mode edit')
      }
      if (!input.buffer || input.buffer.length > 1024 * 1024 || input.env?.targetTruncated) throw new Error('complete JSON input of at most 1 MiB required')
      if (options.mode === 'edit') {
        const { parseConfigurationEdit, prepareConfigurationEdit } = await import('../../integrations/configEdit.js')
        const { preview: data } = prepareConfigurationEdit(parseConfigurationEdit(input.buffer))
        return {
          summary: `Configuration edit ${data.status}; no host write`, data,
          evidence: [{ title: 'Configuration edit preview', kind: 'configuration-edit-preview', excerpt: JSON.stringify(data) }],
          artifacts: [{ name: 'configuration-edit-preview.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }],
        }
      }
      let bundle
      try { bundle = JSON.parse(input.buffer.toString('utf8')) } catch { throw new Error('invalid config overlay JSON') }
      const { preview: data } = resolveConfig(bundle)
      return { summary: `Configuration ${data.status}: ${data.changes.length} changes; no host write`, data,
        evidence: [{ title: 'Configuration preview', kind: 'configuration-preview', excerpt: JSON.stringify(data) }],
        artifacts: [{ name: 'configuration-preview.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
    },
  }],
}
