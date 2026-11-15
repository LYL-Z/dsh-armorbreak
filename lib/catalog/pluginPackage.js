/** Native metadata and local-file verification. Never loads or installs a plugin. */
import { createHash } from 'node:crypto'
import { join, relative, sep } from 'node:path'
import { canonicalConfig } from '../integrations/configOverlay.js'
import { maintenancePath } from '../../packages/installer/maintenancePlan.js'
import { assessComponent } from './licenseGate.js'
import { collectCatalog } from './collector.js'
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const ID = /^[a-z][a-z0-9-]{0,79}$/
const VERSION = /^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/
const SHA = /^[a-f0-9]{64}$/
const RISK = { 'workspace.read': 'L0', 'sandbox.execute': 'L1', 'host.modify': 'L2', 'credential.attack': 'L3' }
const LEVEL = { L0: 0, L1: 1, L2: 2, L3: 3 }

function exactObject(value, keys) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).some(key => !keys.includes(key))) throw new Error('invalid plugin metadata fields')
}

/** Strict native format. Upstream formats require an explicit, separately tested converter. */
export function inspectPluginMetadata(input) {
  canonicalConfig(input)
  exactObject(input, ['schema', 'plugins'])
  if (input.schema !== 'armorbreak.plugin-catalog/v1' || !Array.isArray(input.plugins) || !input.plugins.length || input.plugins.length > 64) throw new Error('invalid plugin catalog schema')
  const byId = new Map(), plugins = []
  for (const entry of input.plugins) {
    exactObject(entry, ['id', 'version', 'source', 'license', 'dependencies', 'permissions', 'platforms', 'channel', 'enabled', 'files'])
    if (!ID.test(entry.id ?? '') || !VERSION.test(entry.version ?? '') || byId.has(entry.id)) throw new Error('invalid or duplicate plugin identity')
    exactObject(entry.source, ['repository', 'commit'])
    let url
    try { url = new URL(entry.source.repository) } catch { throw new Error('invalid plugin repository') }
    if (url.protocol !== 'https:' || !['github.com', 'gitlab.com'].includes(url.hostname) || url.username || url.password || url.port || url.search || url.hash || !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(url.pathname) || !/^[a-f0-9]{40}$/.test(entry.source.commit ?? '')) throw new Error('immutable credential-free plugin source required')
    if (!['stable', 'preview'].includes(entry.channel) || typeof entry.enabled !== 'boolean' || !Array.isArray(entry.platforms) || !entry.platforms.length || entry.platforms.some(p => !['win32', 'linux', 'darwin'].includes(p))) throw new Error('invalid plugin channel, platform or enabled state')
    if (!Array.isArray(entry.permissions) || entry.permissions.length > 16 || entry.permissions.some(p => !Object.hasOwn(RISK, p))) throw new Error('unknown plugin permission')
    if (!Array.isArray(entry.dependencies) || entry.dependencies.length > 64) throw new Error('invalid plugin dependencies')
    const dependencies = new Set()
    for (const dep of entry.dependencies) {
      exactObject(dep, ['id', 'version'])
      if (!ID.test(dep.id ?? '') || !VERSION.test(dep.version ?? '') || dependencies.has(dep.id)) throw new Error('invalid or duplicate dependency')
      dependencies.add(dep.id)
    }
    if (!Array.isArray(entry.files) || !entry.files.length || entry.files.length > 64) throw new Error('plugin requires explicit package files')
    const paths = new Set()
    for (const file of entry.files) {
      exactObject(file, ['path', 'sha256'])
      maintenancePath(file.path)
      if (!SHA.test(file.sha256 ?? '') || paths.has(file.path.toLowerCase())) throw new Error('invalid or duplicate package file')
      paths.add(file.path.toLowerCase())
    }
    const riskLevel = entry.permissions.reduce((level, p) => LEVEL[RISK[p]] > LEVEL[level] ? RISK[p] : level, 'L0')
    const assessment = assessComponent({ name: entry.id, version: entry.version, license: entry.license, commit: entry.source.commit, digest: `sha256:${hash(canonicalConfig(entry.files))}`, scripts: {} })
    const row = { id: entry.id, version: entry.version, source: { ...entry.source }, channel: entry.channel, platforms: [...entry.platforms],
      requestedEnabled: entry.enabled, loadedState: 'UNKNOWN', executionState: riskLevel === 'L3' ? 'DENIED' : 'NOT_LOADED', riskLevel,
      permissions: [...entry.permissions], dependencyIds: [...dependencies], licenseClaim: assessment.license,
      metadataShapeValid: true, riskClassificationEligible: riskLevel !== 'L3',
      licenseClaimRecognized: assessment.allowed,
      localFilesVerified: false, sourceAuthenticated: false, rightsVerified: false,
      rightsState: 'UNVERIFIED_NOT_IMPORTED', corePolicyState: riskLevel === 'L3' ? 'DENIED' : 'NOT_EVALUATED',
      policyEligible: false, activationAuthorized: false, releaseEligible: false, executable: false,
      fileCount: entry.files.length }
    plugins.push(row); byId.set(entry.id, { entry, row })
  }
  const visiting = new Set(), visited = new Set(), order = []
  function visit(id) {
    if (visiting.has(id)) throw new Error('plugin dependency cycle')
    if (visited.has(id)) return
    visiting.add(id)
    for (const dep of byId.get(id).entry.dependencies) {
      const target = byId.get(dep.id)
      if (!target || target.entry.version !== dep.version) throw new Error('missing dependency or exact version mismatch')
      visit(dep.id)
    }
    visiting.delete(id); visited.add(id); order.push(id)
  }
  for (const id of byId.keys()) visit(id)
  const catalog = collectCatalog(plugins.map(p => ({ url: p.source.repository, commit: p.source.commit, license: 'metadata-claim-only', version: p.version, source: p.id })))
  return { schema: 'armorbreak.plugin-review/v1', plugins, dependencyOrder: order, uniqueSources: catalog.items.length,
    sourceManifestSha256: hash(canonicalConfig(input)), executable: false, networkUsed: false, installationPerformed: false }
}

export async function verifyPluginPackage(input) {
  if (!input.env?.readFile || !input.targetPath) throw new Error('Core directory reader required')
  const read = async path => {
    const bytes = await input.env.readFile(path, 1024 * 1024 + 1)
    if (bytes.length > 1024 * 1024 || input.env.targetTruncated) throw new Error('complete plugin input of at most 1 MiB required')
    return bytes
  }
  let manifest
  try { manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await read(join(input.targetPath, 'armorbreak-plugin.json')))) } catch (error) { throw new Error(`plugin manifest unavailable or invalid: ${error.code ?? 'INVALID_JSON'}`) }
  const result = inspectPluginMetadata(manifest), verifiedFiles = []
  for (const entry of manifest.plugins) for (const file of entry.files) {
    const bytes = await read(join(input.targetPath, ...maintenancePath(file.path))), actual = hash(bytes)
    if (actual !== file.sha256) throw new Error(`plugin package hash mismatch: ${hash(file.path)}`)
    verifiedFiles.push({ pluginId: entry.id, fileId: hash(file.path), sha256: actual, bytes: bytes.length })
  }
  return { ...result, plugins: result.plugins.map(row => ({ ...row, localFilesVerified: true })), verificationStatus: 'LOCAL_LISTED_FILES_VERIFIED', verifiedFiles,
    limitation: 'Only listed files were checked. No signature, rights clearance, full archive closure, runtime activation or host compatibility is proven.' }
}

/** Strict closure is opt-in; generic source inventories intentionally skip some directories. */
export async function verifyPluginClosure(input) {
  if (typeof input.env?.listFiles !== 'function') throw new Error('Core strict directory reader required')
  const inventory = async () => (await input.env.listFiles(input.targetPath, { strict: true, maxFiles: 4096, maxDepth: 8 }))
    .map(path => relative(input.targetPath, path).split(sep).join('/')).sort()
  const before = await inventory()
  const manifestBytes = await input.env.readFile(join(input.targetPath, 'armorbreak-plugin.json'), 1024 * 1024 + 1)
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes))
  const result = await verifyPluginPackage(input)
  const declared = new Map([['armorbreak-plugin.json', hash(manifestBytes)]])
  for (const plugin of manifest.plugins) for (const file of plugin.files) {
    const key = file.path.toLowerCase()
    if (key === 'armorbreak-plugin.json' || [...declared.keys()].some(path => path.toLowerCase() === key)) throw new Error('package closure path ownership conflict')
    declared.set(file.path, file.sha256)
  }
  const expected = [...declared.keys()].sort()
  if (canonicalConfig(before) !== canonicalConfig(expected)) throw new Error('package closure contains missing or undeclared files')
  // A second bounded read binds the digest to the manifest and payload actually reviewed.
  for (const [path, digest] of declared) {
    const bytes = await input.env.readFile(join(input.targetPath, ...maintenancePath(path)), 1024 * 1024 + 1)
    if (bytes.length > 1024 * 1024 || hash(bytes) !== digest) throw new Error('package closure drift')
  }
  if (canonicalConfig(await inventory()) !== canonicalConfig(before) || result.sourceManifestSha256 !== hash(canonicalConfig(manifest))) throw new Error('package closure drift')
  const closure = expected.map(path => ({ path, sha256: declared.get(path) }))
  return { ...result, verificationStatus: 'LOCAL_PACKAGE_CLOSURE_VERIFIED', packageClosureVerified: true,
    catalog: manifest, closure, closureSha256: hash(canonicalConfig(closure)),
    limitation: 'Bounded repeated-read snapshot; not an atomic filesystem freeze. No source authentication, rights clearance, execution, installation or real host compatibility is inferred.' }
}
