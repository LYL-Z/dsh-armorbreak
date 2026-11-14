/** Trusted host only: signed package review -> inert fresh-lab staging -> Core approval. */
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { canonicalConfig } from '../../../lib/integrations/configOverlay.js'
import { verifyPluginClosure } from '../../../lib/catalog/pluginPackage.js'
import { maintenancePath } from '../../installer/maintenancePlan.js'
import { createSyntheticMaintenance } from './syntheticMaintenance.js'

async function capture(input) {
  const snapshot = await verifyPluginClosure(input), files = []
  for (const file of snapshot.closure) {
    const bytes = await input.env.readFile(join(input.targetPath, ...maintenancePath(file.path)), 65537)
    if (bytes.length > 65536 || createHash('sha256').update(bytes).digest('hex') !== file.sha256) throw new Error('PLUGIN_CAPTURE_DRIFT_OR_LIMIT')
    files.push({ path: file.path, base64: bytes.toString('base64') })
  }
  const content = canonicalConfig({ schema: 'armorbreak.inert-plugin-bundle/v1', files })
  if (Buffer.byteLength(content) > 65536) throw new Error('PLUGIN_CAPTURE_LIMIT')
  return { snapshot, content }
}

/** Cannot supply a destination or an existing DSH root. Even .js bytes remain inert base64 text. */
export async function planSyntheticPluginUpdate(runtime, { current, candidate, reviewer, receipts, operator, sessionId }) {
  if (!reviewer || typeof reviewer.review !== 'function') throw new Error('PLUGIN_TRUSTED_REVIEWER_REQUIRED')
  const next = await capture(candidate), review = reviewer.review(next.snapshot, receipts)
  if (review.state !== 'READY_FOR_SYNTHETIC_STAGING_APPROVAL') throw new Error('PLUGIN_STAGING_REVIEW_DENIED')
  const previous = current ? await capture(current) : null
  const lab = await createSyntheticMaintenance(runtime, { operator, sessionId, seeds: { 'packages.txt': previous?.content ?? '' } })
  const plan = await lab.plan([{ name: 'packages.txt', content: next.content }])
  return { lab, plan, review, mode: 'SYNTHETIC_INERT_BUNDLE_ONLY', dependencyOrder: review.dependencyOrder,
    previousClosureSha256: previous?.snapshot.closureSha256 ?? null, candidateClosureSha256: next.snapshot.closureSha256,
    approvalRequired: true, activationAuthorized: false, hostWrites: false, releaseEligible: false }
}
