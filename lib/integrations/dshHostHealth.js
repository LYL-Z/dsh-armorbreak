/** Original read-only composition; functional references are recorded in docs. */
import { inspectDshRuntimeLayout } from './dshRuntimeLayout.js'

const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

export async function inspectDshHostHealth({ resources, readFile, inspectHostArchive, expectedVersion } = {}) {
  if (expectedVersion !== undefined && (typeof expectedVersion !== 'string' || !VERSION.test(expectedVersion))) {
    throw new Error('expectedVersion must be an exact semantic version')
  }
  const layout = await inspectDshRuntimeLayout({ resources, readFile, inspectHostArchive })
  const detected = layout.status === 'DISK_PACKAGE_FOUND'
  const version = layout.identity.version && VERSION.test(layout.identity.version) ? layout.identity.version : null
  return {
    schema: 'armorbreak.host-health/v1', mode: 'READ_ONLY',
    observation: detected ? 'DETECTED_ON_DISK' : 'UNKNOWN',
    disk: layout.disk, archiveMetadata: layout.archiveMetadata, layoutStatus: layout.status,
    identity: { family: layout.identity.family, version, evidence: layout.identity.evidence },
    compatibility: {
      // Caller-selected version equality is a requirement check, not a claim
      // that this host version passed integration or runtime verification.
      versionRequirement: expectedVersion === undefined ? 'NOT_REQUESTED' : !version ? 'UNKNOWN' : version === expectedVersion ? 'MATCH' : 'MISMATCH',
      runtime: 'UNKNOWN', feature: 'UNKNOWN',
      inspection: detected ? 'AVAILABLE' : 'UNKNOWN',
    },
    process: 'UNKNOWN', runtime: 'UNKNOWN', feature: 'UNKNOWN',
    limitations: ['Only allowlisted package metadata is read from ASAR. Disk metadata is untrusted and cannot verify process state, patch activation or host compatibility.',
      'Select one workspace-scoped Resources directory per call; installation discovery and process probing are not performed.'],
  }
}
