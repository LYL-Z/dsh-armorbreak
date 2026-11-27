import { planHostMaintenance } from '../../../packages/installer/maintenancePlan.js'
import { inspectBackupUsage } from '../../integrations/backupUsage.js'
import { verifyBackupSnapshot } from '../../integrations/backupSnapshotVerification.js'
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
  description: 'Measure backup storage or verify one declared snapshot in an explicit workspace copy of a Purge maintenance store.',
  params: { type: 'object', properties: { verifySnapshot: { type: 'string' } }, additionalProperties: false },
  async run(input) {
    const options = input.options ?? {}
    if (Object.keys(options).some(key => key !== 'verifySnapshot')) throw new Error('unsupported backup inspection option')
    if (Object.hasOwn(options, 'verifySnapshot')) {
      const data = await verifyBackupSnapshot(input, options.verifySnapshot)
      return {
        summary: `${data.snapshotFiles} snapshot files and ${data.referencedObjects} objects match their declarations`,
        data,
        evidence: [{ kind: 'backup-snapshot-verification', title: 'Snapshot and object agreement', excerpt: JSON.stringify(data) }],
        artifacts: [{ name: 'backup-verification.json', contentType: 'application/json', content: JSON.stringify(data, null, 2) }],
      }
    }
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
