/** Trusted host composition. Only fresh synthetic data; never an existing DSH path. */
import { importConfiguration, exportConfiguration } from '../../../lib/integrations/configFormats.js'
import { resolveConfig, CONFIG_SCHEMA } from '../../../lib/integrations/configOverlay.js'
import { prepareConfigurationEdit } from '../../../lib/integrations/configEdit.js'
import { createSyntheticMaintenance } from './syntheticMaintenance.js'

export async function planSyntheticConfiguration(runtime, { configuration, profiles = [], selectedProfile, overlays = [], conflictPolicy = 'reject', operator, sessionId }) {
  const { document, preview: imported } = importConfiguration(configuration)
  const base = document.format === 'cordis' ? { composition: document.data } : document.data
  const bundle = { schema: CONFIG_SCHEMA, base, profiles, overlays, conflictPolicy }
  if (selectedProfile !== undefined) bundle.selectedProfile = selectedProfile
  const { config, preview } = resolveConfig(bundle)
  if (preview.status !== 'PREVIEW_READY') throw new Error('SYNTHETIC_CONFIG_CONFLICT')
  if (document.format === 'cordis' && Object.keys(config).join(',') !== 'composition') throw new Error('SYNTHETIC_CORDIS_SHAPE_REQUIRED')
  const candidate = exportConfiguration({ ...document, data: document.format === 'cordis' ? config.composition : config }, {preserveSource:configuration.source})
  const { lab, plan } = await stageConfiguration(runtime, configuration, candidate, { operator, sessionId })
  const conversion = document.format === 'json' ? imported : {...imported,limitations:['Existing comments, map order and compatible scalar style are retained; arbitrary whitespace layout is not guaranteed. Comments on deleted nodes may be removed.',...imported.limitations.slice(1)]}
  return { lab, plan, preview: { ...preview, conversion, serialization:document.format==='json'?'JSON_DATA_WITH_EXACT_UNCHANGED_SOURCE':'YAML_AST_WITH_EXACT_UNCHANGED_SOURCE', mode: 'SYNTHETIC_ONLY', approvalRequired: true } }
}

export async function planSyntheticConfigurationEdit(runtime, request, context) {
  const { candidate, preview } = prepareConfigurationEdit(request)
  if (preview.status === 'NO_CHANGES') throw new Error('CONFIG_EDIT_NO_CHANGES')
  const { lab, plan } = await stageConfiguration(runtime, request.configuration, candidate, context)
  return { lab, plan, preview: { ...preview, mode: 'SYNTHETIC_ONLY', approvalRequired: true } }
}

async function stageConfiguration(runtime, configuration, candidate, { operator, sessionId }) {
  // Both the original raw bytes and the converted candidate stay private in the lab.
  // The original is copied, never opened for writing; the caller cannot supply a path.
  const seeds = configuration.format === 'purge-preset' ? { 'preset.txt': configuration.source.preset, 'agent.txt': configuration.source.agent } : { 'config.txt': configuration.source }
  const changes = configuration.format === 'purge-preset' ? [{ name: 'preset.txt', content: candidate.preset }, { name: 'agent.txt', content: candidate.agent }] : [{ name: 'config.txt', content: candidate }]
  if (changes.some(change => Buffer.byteLength(change.content) > 65536)) throw new Error('LAB_PLAN_INVALID')
  const lab = await createSyntheticMaintenance(runtime, { operator, sessionId, seeds })
  const plan = await lab.plan(changes)
  return { lab, plan }
}
