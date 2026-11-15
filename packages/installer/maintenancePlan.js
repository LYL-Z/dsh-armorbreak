/** Bounded read-only preflight for the existing installer. Never executes a plan. */
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { canonicalConfig } from '../../lib/integrations/configOverlay.js'
const hash = value => createHash('sha256').update(value).digest('hex')
const SHA = /^[a-f0-9]{64}$/

export function maintenancePath(value) {
  if (typeof value !== 'string' || value.length > 240 || value.includes('\\') || /[\x00-\x1f:<>?"*|]/.test(value)) throw new Error('invalid maintenance relative path')
  const parts = value.split('/')
  if (parts.some(part => !part || part === '.' || part === '..' || /[. ]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) throw new Error('invalid maintenance relative path')
  return parts
}

export async function planHostMaintenance(input) {
  if (!input.env?.readFile || !input.targetPath) throw new Error('Core directory reader required')
  const read = async path => {
    const bytes = await input.env.readFile(path, 1024 * 1024 + 1)
    if (bytes.length > 1024 * 1024 || input.env.targetTruncated) throw new Error('complete maintenance input of at most 1 MiB required')
    return bytes
  }
  const bytes = await read(join(input.targetPath, 'armorbreak-maintenance.json'))
  let request
  try { request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch { throw new Error('invalid maintenance JSON') }
  canonicalConfig(request)
  if (request.schema !== 'armorbreak.maintenance-request/v1' || Object.keys(request).some(key => !['schema', 'files', 'operation'].includes(key))) throw new Error('invalid maintenance schema')
  if (!['backup', 'update', 'uninstall-check'].includes(request.operation)) throw new Error('unsupported maintenance operation')
  if (!Array.isArray(request.files) || !request.files.length || request.files.length > 64) throw new Error('maintenance requires 1-64 explicit files')
  const seen = new Set(), files = []
  for (const row of request.files) {
    if (!row || typeof row !== 'object' || Object.keys(row).some(key => !['path', 'expectedSha256', 'candidateSha256'].includes(key)) || !SHA.test(row.expectedSha256 ?? '') || (request.operation === 'update' && !SHA.test(row.candidateSha256 ?? ''))) throw new Error('invalid maintenance file identity')
    const parts = maintenancePath(row.path)
    if (seen.has(row.path.toLowerCase())) throw new Error('duplicate or case-colliding maintenance path')
    seen.add(row.path.toLowerCase())
    const fileId = hash(row.path), content = await read(join(input.targetPath, ...parts)), currentSha256 = hash(content)
    if (currentSha256 !== row.expectedSha256) throw new Error(`maintenance source drift: ${fileId}`)
    files.push({ fileId, bytes: content.length, currentSha256, candidateSha256: request.operation === 'update' ? row.candidateSha256 : null,
      action: request.operation === 'update' ? currentSha256 === row.candidateSha256 ? 'UNCHANGED' : 'REPLACEMENT_REQUIRES_APPROVAL' : 'VERIFIED_SOURCE' })
  }
  const body = { schema: 'armorbreak.maintenance-preflight/v1', requestSha256: hash(bytes), operation: request.operation, files,
    mode: 'READ_ONLY', status: 'PREFLIGHT_ONLY', approvalRequired: true, executable: false, backend: 'existing TransactionalInstaller; host adapter NOT_IMPLEMENTED',
    rollback: 'A verified backup and separately scoped executor are required before any host write. No backup was created.',
    hostModified: false }
  return { ...body, planSha256: hash(canonicalConfig(body)) }
}
