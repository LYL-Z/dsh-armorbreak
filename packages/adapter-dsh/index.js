/** Thin DSH adapter shim: legacy Cordis exports remain the source of truth. */
import legacyHost, { inject, apply } from '../../index.js'
import legacyTools from '../../tools.js'

export const adapterId = 'dsh'
export const presetId = 'armorbreak'
export const legacy = { host: legacyHost, tools: legacyTools, inject, apply }
export { inject, apply }
export default legacyHost
