/** Trusted host composition. Only fresh synthetic data; never an existing DSH path. */
import { importConfiguration, exportConfiguration } from '../../../lib/integrations/configFormats.js'
import { resolveConfig, CONFIG_SCHEMA } from '../../../lib/integrations/configOverlay.js'
import { createSyntheticMaintenance } from './syntheticMaintenance.js'

export async function planSyntheticConfiguration(runtime, { configuration, profiles = [], selectedProfile, overlays = [], conflictPolicy = 'reject', operator, sessionId }) {
  const { document, preview: imported } = importConfiguration(configuration)
  const base = document.format === 'cordis' ? { composition: document.data } : document.data
  const bundle = { schema: CONFIG_SCHEMA, base, profiles, overlays, conflictPolicy }
  if (selectedProfile !== undefined) bundle.selectedProfile = selectedProfile
  const { config, preview } = resolveConfig(bundle)
  if (preview.status !== 'PREVIEW_READY') throw new Error('SYNTHETIC_CONFIG_CONFLICT')
  if (document.format === 'cordis' && Object.keys(config).join(',') !== 'composition') throw new Error('SYNTHETIC_CORDIS_SHAPE_REQUIRED')
  const candidate = exportConfiguration({ ...document, data: document.format === 'cordis' ? config.composition : config })
  // Both the original raw bytes and the converted candidate stay private in the lab.
  // The original is copied, never opened for writing; the caller cannot supply a path.
  const seeds = document.format === 'purge-preset' ? { 'preset.txt': configuration.source.preset, 'agent.txt': configuration.source.agent } : { 'config.txt': configuration.source }
  const changes = document.format === 'purge-preset' ? [{ name: 'preset.txt', content: candidate.preset }, { name: 'agent.txt', content: candidate.agent }] : [{ name: 'config.txt', content: candidate }]
  const lab = await createSyntheticMaintenance(runtime, { operator, sessionId, seeds })
  const plan = await lab.plan(changes)
  return { lab, plan, preview: { ...preview, conversion: imported, mode: 'SYNTHETIC_ONLY', approvalRequired: true } }
}
