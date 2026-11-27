import { planHostMaintenance } from '../../../packages/installer/maintenancePlan.js'
import { inspectBackupUsage } from '../../integrations/backupUsage.js'
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
}, {
  id: 'maintenance.backup_usage', title: 'Measure backup storage', riskLevel: 'L0', targetKind: 'directory',
  description: 'Measure complete-declared snapshot and object bytes in a selected workspace copy of a Purge maintenance store.',
  params: { type: 'object', properties: {}, additionalProperties: false },
  async run(input) {
    if (Object.keys(input.options ?? {}).length) throw new Error('maintenance.backup_usage accepts no options')
    const data = await inspectBackupUsage(input)
    return {
      summary: `${data.count} complete-declared snapshots and ${data.objectFiles} object files: ${data.bytes} logical bytes, ${data.unconfirmedSnapshots} unconfirmed snapshots`,
      data,
      evidence: [{ kind: 'backup-usage', title: 'Bounded backup inventory', excerpt: JSON.stringify(data) }],
      artifacts: [{ name: 'backup-usage.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }],
      meta: { inputCompleteness: data.unconfirmedSnapshots ? 'partial' : 'complete' },
    }
  },
}] }
