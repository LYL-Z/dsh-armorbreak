import { planHostMaintenance } from '../../../packages/installer/maintenancePlan.js'
export default { domain: 'maintenance', capabilities: [{
  id: 'maintenance.plan', title: 'Read-only host maintenance preflight', riskLevel: 'L0', targetKind: 'directory',
  description: 'Verify explicit file hashes and plan maintenance without creating backups, downloads or host writes.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (Object.keys(input.options ?? {}).length) throw new Error('maintenance.plan accepts no options')
    const data = await planHostMaintenance(input)
    return { summary: `Maintenance preflight: ${data.files.length} verified sources; no host write`, data,
      evidence: [{ kind: 'maintenance-plan', title: 'Source verification', excerpt: JSON.stringify(data) }],
      artifacts: [{ name: 'maintenance-preflight.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }] }
  },
}] }
