import { verifyPluginPackage } from '../../catalog/pluginPackage.js'
export default { domain: 'plugin', capabilities: [{
  id: 'plugin.verify', title: 'Local plugin metadata and file verification', riskLevel: 'L0', targetKind: 'directory',
  description: 'Review immutable plugin sources, dependency graph and listed file hashes without loading, network access or installation.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (Object.keys(input.options ?? {}).length) throw new Error('plugin.verify accepts no options')
    const data = await verifyPluginPackage(input)
    return { summary: `Plugin metadata: ${data.plugins.length}; ${data.verifiedFiles.length} local files verified; none loaded`, data,
      evidence: [{ kind: 'plugin-review', title: 'Local package verification', excerpt: JSON.stringify(data) }],
      artifacts: [{ name: 'plugin-review.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
  },
}] }
