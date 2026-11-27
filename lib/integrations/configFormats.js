/** Data conversion only. Does not load Cordis, evaluate expressions or touch a host. */
import { parseDocument, isAlias, isMap, isSeq, isScalar, stringify } from 'yaml'
import { canonicalConfig } from './configOverlay.js'

export const IMPORT_SCHEMA = 'armorbreak.configuration-import/v1'
const DOCUMENT_SCHEMA = 'armorbreak.configuration-document/v1'
const formats = new Set(['json', 'yaml', 'cordis', 'purge-preset'])
const blocked = new Set(['__proto__', 'constructor', 'prototype', '<<'])
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x)
function fail() { throw new Error('configuration import rejected: invalid, ambiguous, unsupported or excessive data') }

/** Strict YAML 1.2 data tree, including JSON; errors never echo source/key/value. */
function parseData(text, json = false) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 1024 * 1024) fail()
  try {
    if (json) JSON.parse(text)
    const doc = parseDocument(text, { version: '1.2', schema: 'core', strict: true,
      uniqueKeys: true, intAsBigInt: true, resolveKnownTags: false, prettyErrors: false })
    if (doc.errors.length || doc.warnings.length || doc.directives.yaml.version !== '1.2') fail()
    let nodes = 0
    const walk = (node, depth = 0) => {
      if (++nodes > 20000 || depth > 24 || isAlias(node) || node?.anchor || node?.tag) fail()
      if (node === null) return null
      if (isMap(node)) {
        const out = Object.create(null)
        for (const pair of node.items) {
          if (!isScalar(pair.key) || typeof pair.key.value !== 'string' || blocked.has(pair.key.value)) fail()
          if (Object.hasOwn(out, pair.key.value)) fail()
          out[pair.key.value] = walk(pair.value, depth + 1)
        }
        return out
      }
      if (isSeq(node)) return node.items.map(item => walk(item, depth + 1))
      if (!isScalar(node)) fail()
      const value = typeof node.value === 'bigint' ? Number(node.value) : node.value
      if (typeof node.value === 'bigint' && BigInt(value) !== node.value) fail()
      if (typeof value === 'number' && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) fail()
      if (value !== null && !['string', 'boolean', 'number'].includes(typeof value)) fail()
      return value
    }
    return JSON.parse(canonicalConfig(walk(doc.contents)))
  } catch { fail() }
}
export { parseData as parseStrictConfigurationData }
function cordis(rows, depth = 0) {
  if (!Array.isArray(rows) || rows.length > 512 || depth > 12) fail()
  const ids = new Set()
  for (const row of rows) {
    if (!object(row) || typeof row.id !== 'string' || !row.id || ids.has(row.id) ||
        (row.disabled !== undefined && typeof row.disabled !== 'boolean')) fail()
    ids.add(row.id)
    if (row.group === true) cordis(row.config, depth + 1)
    else if (typeof row.name !== 'string' || !row.name) fail()
  }
}
function validate(format, data) {
  if (!formats.has(format)) fail()
  canonicalConfig(data)
  if (format === 'cordis') cordis(data)
  else if (format === 'purge-preset') {
    if (!object(data) || Object.keys(data).sort().join(',') !== 'composition,metadata' ||
        !object(data.metadata) || typeof data.metadata.name !== 'string') fail()
    cordis(data.composition)
  } else if (!object(data)) fail()
}

/** Private in-memory result: contains configuration secrets; never export to public reports. */
export function importConfiguration(input) {
  try {
    canonicalConfig(input)
    if (!object(input) || input.schema !== IMPORT_SCHEMA || !formats.has(input.format) ||
        Object.keys(input).some(key => !['schema', 'format', 'source'].includes(key))) fail()
    let data
    if (input.format === 'purge-preset') {
      if (!object(input.source) || Object.keys(input.source).sort().join(',') !== 'agent,preset') fail()
      data = { metadata: parseData(input.source.preset), composition: parseData(input.source.agent) }
    } else data = parseData(input.source, input.format === 'json')
    validate(input.format, data)
    const document = { schema: DOCUMENT_SCHEMA, format: input.format, data }
    return { document, preview: { schema: 'armorbreak.configuration-import-preview/v1',
      status: 'CONVERTED_DATA_ONLY', format: input.format, mode: 'READ_ONLY', applied: false,
      pluginExecution: 'UNAVAILABLE', templateEvaluation: 'UNAVAILABLE', rightsState: 'NOT_EVALUATED',
      disclosure: 'Only format is public. Configuration values, keys, names and digests are not exported.',
      limitations: ['Comments, quoting and layout are not preserved; JSON data semantics are preserved.',
        'Parsing does not establish host compatibility, plugin rights or authorization to apply.'] } }
  } catch { fail() }
}

/** Explicit private export; caller must protect returned plaintext, like the source. */
export function exportConfiguration(document, options = {}) {
  try {
    if (!object(options) || Object.keys(options).some(k => k !== 'preserveSource')) fail()
    if (!object(document) || document.schema !== DOCUMENT_SCHEMA ||
        Object.keys(document).sort().join(',') !== 'data,format,schema') fail()
    validate(document.format, document.data)
    if (options.preserveSource !== undefined) {
      const source = options.preserveSource
      // Reuse the exact strict importer first: preserving presentation never permits tags,
      // aliases, duplicate keys, unsafe numbers, excessive depth or prototype fields.
      const original = importConfiguration({schema:IMPORT_SCHEMA,format:document.format,source}).document
      if (canonicalConfig(original.data) === canonicalConfig(document.data)) return structuredClone(source)
      if (document.format === 'purge-preset') return {preset:preserveYaml(source.preset,document.data.metadata),agent:preserveYaml(source.agent,document.data.composition)}
      if (document.format !== 'json') return preserveYaml(source,document.data)
    }
    const yaml = value => stringify(value, { version: '1.2', lineWidth: 0, aliasDuplicateObjects: false })
    return document.format === 'purge-preset'
      ? { preset: yaml(document.data.metadata), agent: yaml(document.data.composition) }
      : document.format === 'json' ? `${canonicalConfig(document.data)}\n` : yaml(document.data)
  } catch { fail() }
}

/** Private output. Existing presentation is retained where the data node still exists. */
function preserveYaml(source, data) {
  const doc = parseDocument(source, {version:'1.2',schema:'core',strict:true,uniqueKeys:true,resolveKnownTags:false})
  function reconcile(node, value) {
    if (isMap(node) && object(value)) {
      node.items = node.items.filter(pair => Object.hasOwn(value, pair.key.value))
      for (const [name, next] of Object.entries(value)) {
        const pair = node.items.find(pair => pair.key.value === name)
        if (pair) pair.value = reconcile(pair.value, next)
        else node.add(doc.createPair(name, next))
      }
      return node
    }
    if (isSeq(node) && Array.isArray(value)) {
      // Cordis component identity is stable across explicit reordering. Do not
      // attach an existing component's comment to a different component's ID.
      const identified = value.length && value.every(v => object(v) && typeof v.id === 'string') && new Set(value.map(v=>v.id)).size===value.length
      const previous = identified ? new Map(node.items.filter(isMap).map(n=>[n.get('id'),n])) : null
      node.items = value.map((v,i) => reconcile(previous?.get(v.id) ?? (identified ? null : node.items[i]),v))
      return node
    }
    if (isScalar(node) && (value === null || typeof value !== 'object')) {node.value=value;return node}
    const replacement=doc.createNode(value)
    // Retain a node's own human annotation when its data type must change.
    if (node && replacement) for (const key of ['comment','commentBefore','spaceBefore']) if (node[key] !== undefined) replacement[key]=node[key]
    return replacement
  }
  doc.contents=reconcile(doc.contents,data)
  let output=doc.toString({lineWidth:0})
  if (/\r\n/.test(source) && !/(?<!\r)\n/.test(source)) output=output.replace(/\n/g,'\r\n')
  // Verify the serialized candidate against the private intended JSON semantics.
  if (canonicalConfig(parseData(output)) !== canonicalConfig(data)) fail()
  return output
}
