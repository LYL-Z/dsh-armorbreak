/** Original data-only configuration model. No host I/O, templates or hooks. */
import { createHash } from 'node:crypto'
const BLOCKED = new Set(['__proto__', 'prototype', 'constructor'])
const ID = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/
export const CONFIG_SCHEMA = 'armorbreak.config-overlay/v1'
const digest = text => createHash('sha256').update(text).digest('hex')
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x)

export function canonicalConfig(value) {
  let nodes = 0
  const walk = (x, depth) => {
    if (++nodes > 20000 || depth > 24) throw new Error('configuration complexity limit exceeded')
    if (x === null || typeof x === 'boolean' || typeof x === 'string' || (typeof x === 'number' && Number.isFinite(x))) return JSON.stringify(x)
    if (Array.isArray(x)) return `[${x.map(v => walk(v, depth + 1)).join(',')}]`
    if (!object(x) || ![Object.prototype, null].includes(Object.getPrototypeOf(x))) throw new Error('configuration must contain JSON data only')
    return `{${Object.keys(x).sort().map(key => {
      if (BLOCKED.has(key)) throw new Error('unsafe configuration key')
      return `${JSON.stringify(key)}:${walk(x[key], depth + 1)}`
    }).join(',')}}`
  }
  const result = walk(value, 0)
  if (Buffer.byteLength(result) > 1024 * 1024) throw new Error('configuration exceeds 1 MiB')
  return result
}

function fields(obj, allowed) {
  if (!object(obj) || Object.keys(obj).some(key => !allowed.includes(key))) throw new Error('unsupported configuration envelope field')
}
function named(row) {
  fields(row, ['id', 'values'])
  if (typeof row.id !== 'string' || !ID.test(row.id) || !object(row.values)) throw new Error('layer needs a stable id and object values')
}

/** Recursively merge objects; arrays, null and all explicit falsey values replace. */
export function resolveConfig(bundle) {
  canonicalConfig(bundle)
  fields(bundle, ['schema', 'base', 'profiles', 'selectedProfile', 'overlays', 'conflictPolicy'])
  if (bundle.schema !== CONFIG_SCHEMA || !object(bundle.base)) throw new Error('invalid config overlay schema or base')
  const profiles = bundle.profiles ?? [], overlays = bundle.overlays ?? []
  if (!Array.isArray(profiles) || !Array.isArray(overlays) || profiles.length + overlays.length > 64) throw new Error('at most 64 data layers allowed')
  const ids = new Set()
  for (const layer of [...profiles, ...overlays]) {
    named(layer)
    if (ids.has(layer.id)) throw new Error('duplicate layer id')
    ids.add(layer.id)
  }
  if (!['reject', 'last-wins'].includes(bundle.conflictPolicy ?? 'reject')) throw new Error('invalid conflict policy')
  const layers = []
  if (bundle.selectedProfile !== undefined) {
    const selected = profiles.find(row => row.id === bundle.selectedProfile)
    if (!selected) throw new Error('selected profile not found')
    layers.push(selected)
  }
  layers.push(...overlays)
  const original = JSON.parse(canonicalConfig(bundle.base)), conflicts = [], changes = []
  // Public identifiers are call-local ordinals, never functions of secret keys,
  // values or caller-supplied labels. Do not export config/snapshot digests.
  const fieldIds = new Map()
  const merge = (left, right, path, layer) => {
    const result = structuredClone(left)
    for (const [key, value] of Object.entries(right)) {
      const pointer = `${path}/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`
      if (Object.hasOwn(left, key) && object(left[key]) && object(value)) result[key] = merge(left[key], value, pointer, layer)
      else if (!Object.hasOwn(left, key) || canonicalConfig(left[key]) !== canonicalConfig(value)) {
        if (!fieldIds.has(pointer)) fieldIds.set(pointer, `field-${fieldIds.size + 1}`)
        const change = { fieldId: fieldIds.get(pointer), layer, operation: Object.hasOwn(left, key) ? 'replace' : 'add' }
        changes.push(change)
        if (changes.length > 2048) throw new Error('configuration change limit exceeded')
        if (change.operation === 'replace') conflicts.push({ fieldId: change.fieldId, layer })
        result[key] = structuredClone(value)
      }
    }
    return result
  }
  let config = original
  layers.forEach((layer, index) => { config = merge(config, layer.values, '', `layer-${index + 1}`) })
  const policy = bundle.conflictPolicy ?? 'reject'
  return { config, preview: {
    schema: 'armorbreak.config-preview/v2', mode: 'READ_ONLY',
    status: conflicts.length && policy === 'reject' ? 'CONFLICT' : 'PREVIEW_READY',
    profileSelected: bundle.selectedProfile !== undefined, layers: layers.map((_, index) => `layer-${index + 1}`),
    disclosure: 'STRUCTURE_ONLY; counts, equality/conflict and operation order remain observable. No value, key, label or input digest is exported.',
    conflictPolicy: policy, changes, conflicts, applied: false,
    authorization: 'Configuration data never grants Core permissions. No host write performed.',
  } }
}

export function snapshotConfig(config) {
  const content = canonicalConfig(config)
  return { schema: 'armorbreak.config-snapshot/v1', content, sha256: digest(content) }
}
export function restoreConfigSnapshot(snapshot) {
  fields(snapshot, ['schema', 'content', 'sha256'])
  if (snapshot.schema !== 'armorbreak.config-snapshot/v1' || typeof snapshot.content !== 'string' || snapshot.content.length > 1024 * 1024 || digest(snapshot.content) !== snapshot.sha256) throw new Error('configuration snapshot integrity mismatch')
  const value = JSON.parse(snapshot.content)
  canonicalConfig(value)
  return value
}
