/** Trusted host composition. Only fresh synthetic data; never an existing DSH path. */
import { importConfiguration, exportConfiguration } from '../../../lib/integrations/configFormats.js'
import { resolveConfig, CONFIG_SCHEMA } from '../../../lib/integrations/configOverlay.js'
import { createSyntheticMaintenance } from './syntheticMaintenance.js'

export async function planSyntheticConfiguration(runtime, { configuration, profiles = [], selectedProfile, overlays = [], conflictPolicy = 'reject', operator, sessionId }) {
  const { document, preview: imported } = importConfiguration(configuration)
  if (!['json', 'yaml'].includes(document.format)) throw new Error('SYNTHETIC_CONFIG_OBJECT_FORMAT_REQUIRED')
  const bundle = { schema: CONFIG_SCHEMA, base: document.data, profiles, overlays, conflictPolicy }
  if (selectedProfile !== undefined) bundle.selectedProfile = selectedProfile
  const { config, preview } = resolveConfig(bundle)
  if (preview.status !== 'PREVIEW_READY') throw new Error('SYNTHETIC_CONFIG_CONFLICT')
  const candidate = exportConfiguration({ ...document, data: config })
  // Both the original raw bytes and the converted candidate stay private in the lab.
  // The original is copied, never opened for writing; the caller cannot supply a path.
  const lab = await createSyntheticMaintenance(runtime, { operator, sessionId, seeds: { 'config.txt': configuration.source } })
  const plan = await lab.plan([{ name: 'config.txt', content: candidate }])
  return { lab, plan, preview: { ...preview, conversion: imported, mode: 'SYNTHETIC_ONLY', approvalRequired: true } }
}
