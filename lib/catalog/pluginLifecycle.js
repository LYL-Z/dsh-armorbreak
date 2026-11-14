/** Trusted-host review composition. No module import, network, installer or activation. */
import { createPublicKey, verify, createHash } from 'node:crypto'
import { canonicalConfig } from '../integrations/configOverlay.js'
import { inspectPluginMetadata } from './pluginPackage.js'
const hash = value => createHash('sha256').update(canonicalConfig(value)).digest('hex')

/** Trust roots are configured by trusted host code, never by catalog, HTTP or MCP input. */
export function createPluginReviewer(trustRoots) {
  if (!Array.isArray(trustRoots) || trustRoots.length > 32) throw new Error('PLUGIN_TRUST_ROOTS_INVALID')
  const roots = new Map()
  for (const root of trustRoots) {
    if (!root || typeof root.keyId !== 'string' || !root.keyId || roots.has(root.keyId) || !['source', 'rights'].includes(root.role) || !Array.isArray(root.repositories) || !root.repositories.length) throw new Error('PLUGIN_TRUST_ROOT_INVALID')
    const key = createPublicKey(root.publicKey)
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('PLUGIN_TRUST_KEY_TYPE')
    roots.set(root.keyId, { role: root.role, repositories: [...root.repositories], key })
  }
  function authentic(receipt, role, binding) {
    try {
      if (!receipt || Object.keys(receipt).some(key => !['keyId', 'payload', 'signature'].includes(key))) return false
      const root = roots.get(receipt.keyId), payload = receipt.payload
      if (!root || root.role !== role || canonicalConfig(payload) !== canonicalConfig(binding) || !binding.repositories.every(repo => root.repositories.includes(repo))) return false
      if (!/^[A-Za-z0-9+/]{86}==$/.test(receipt.signature ?? '')) return false
      return verify(null, Buffer.from(canonicalConfig(payload)), root.key, Buffer.from(receipt.signature, 'base64'))
    } catch { return false }
  }
  return Object.freeze({
    review(snapshot, { sourceReceipt, rightsReceipt } = {}) {
      // Snapshot must be a complete, internally consistent closure review from Core.
      if (!snapshot?.packageClosureVerified || snapshot.verificationStatus !== 'LOCAL_PACKAGE_CLOSURE_VERIFIED' || !Array.isArray(snapshot.closure) || hash(snapshot.closure) !== snapshot.closureSha256 || !snapshot.plugins?.length) throw new Error('PLUGIN_CLOSURE_REQUIRED')
      const metadata = inspectPluginMetadata(snapshot.catalog)
      if (metadata.sourceManifestSha256 !== snapshot.sourceManifestSha256 || canonicalConfig(metadata.dependencyOrder) !== canonicalConfig(snapshot.dependencyOrder) || canonicalConfig(metadata.plugins.map(plugin => ({ ...plugin, localFilesVerified: true }))) !== canonicalConfig(snapshot.plugins)) throw new Error('PLUGIN_METADATA_BINDING')
      const expected = snapshot.catalog.plugins.flatMap(plugin => plugin.files).sort((a, b) => a.path.localeCompare(b.path))
      const actual = snapshot.closure.filter(file => file.path !== 'armorbreak-plugin.json').sort((a, b) => a.path.localeCompare(b.path))
      if (snapshot.closure.filter(file => file.path === 'armorbreak-plugin.json').length !== 1 || canonicalConfig(expected) !== canonicalConfig(actual)) throw new Error('PLUGIN_CLOSURE_BINDING')
      const repositories = [...new Set(snapshot.plugins.map(plugin => plugin.source.repository))].sort()
      const identity = { closureSha256: snapshot.closureSha256, manifestSha256: snapshot.sourceManifestSha256, repositories,
        packages: snapshot.plugins.map(plugin => ({ id: plugin.id, version: plugin.version, commit: plugin.source.commit, licenseClaim: plugin.licenseClaim })).sort((a, b) => a.id.localeCompare(b.id)) }
      const sourceAuthenticated = authentic(sourceReceipt, 'source', { schema: 'armorbreak.plugin-source-attestation/v1', ...identity })
      const rightsVerified = authentic(rightsReceipt, 'rights', { schema: 'armorbreak.plugin-rights-attestation/v1', scope: 'review-and-synthetic-staging-only', ...identity })
      const blocked = []
      if (!sourceAuthenticated) blocked.push('SOURCE_NOT_AUTHENTICATED')
      if (!rightsVerified) blocked.push('RIGHTS_NOT_VERIFIED')
      if (snapshot.plugins.some(plugin => !plugin.riskClassificationEligible || !plugin.licenseClaimRecognized)) blocked.push('PACKAGE_POLICY_DENIED')
      return { schema: 'armorbreak.plugin-lifecycle-plan/v1', identity,
        state: blocked.length ? 'BLOCKED' : 'READY_FOR_SYNTHETIC_STAGING_APPROVAL', blocked,
        dependencyOrder: [...snapshot.dependencyOrder], sourceAuthenticated, rightsVerified,
        plugins: snapshot.plugins.map(plugin => ({ ...plugin, sourceAuthenticated, rightsVerified,
          rightsState: rightsVerified ? 'VERIFIED_SYNTHETIC_SCOPE_ONLY' : 'UNVERIFIED_NOT_IMPORTED',
          corePolicyState: blocked.length ? 'DENIED_OR_UNVERIFIED' : 'SYNTHETIC_PLAN_ELIGIBLE',
          policyEligible: blocked.length === 0, activationAuthorized: false, releaseEligible: false, executable: false })),
        installationPerformed: false, activationAuthorized: false, releaseEligible: false,
        limitation: 'Pinned-key signatures authenticate the scoped attester assertion, not independent legal ownership or repository server identity. Synthetic staging eligibility grants no runtime, host install or redistribution permission.' }
    },
  })
}

/** Receipt payload builder is data-only, not an authorization grant or signing API. */
export function pluginAttestationPayload(snapshot, role) {
  if (!['source', 'rights'].includes(role)) throw new Error('PLUGIN_ATTESTATION_ROLE')
  const plan = createPluginReviewer([]).review(snapshot)
  return role === 'source' ? { schema: 'armorbreak.plugin-source-attestation/v1', ...plan.identity }
    : { schema: 'armorbreak.plugin-rights-attestation/v1', scope: 'review-and-synthetic-staging-only', ...plan.identity }
}

/** Trusted-host policy: distinct key material AND declared authorities, with monotonic revocation. */
export function createIndependentPluginReviewer({ roots, revocations = { schema: 'armorbreak.plugin-revocations/v1', keys: [], authorities: [] } }) {
  if (!Array.isArray(roots) || roots.length > 32) throw new Error('PLUGIN_INDEPENDENT_ROOTS_INVALID')
  const id = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(value)
  if (!revocations || Object.keys(revocations).sort().join(',') !== 'authorities,keys,schema' || revocations.schema !== 'armorbreak.plugin-revocations/v1' || !['keys','authorities'].every(k => Array.isArray(revocations[k]) && revocations[k].length <= 1024 && revocations[k].every(id))) throw new Error('PLUGIN_REVOCATION_INVALID')
  const keys = new Set(), immutable = roots.map(root => {
    if (!root || Object.keys(root).some(k => !['keyId','authorityId','role','repositories','publicKey'].includes(k)) || !id(root.keyId) || !id(root.authorityId)) throw new Error('PLUGIN_INDEPENDENT_ROOT_INVALID')
    const key = createPublicKey(root.publicKey), fingerprint = createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex')
    if (keys.has(fingerprint)) throw new Error('PLUGIN_INDEPENDENT_KEY_REQUIRED')
    keys.add(fingerprint)
    return { ...root, repositories: [...root.repositories], publicKey: key.export({ type: 'spki', format: 'pem' }) }
  })
  // Reuse exact role/repository/key checks even when all roots start revoked.
  createPluginReviewer(immutable)
  const byKey = new Map(immutable.map(root => [root.keyId, root]))
  const revokedKeys = new Set(revocations.keys), revokedAuthorities = new Set(revocations.authorities)
  return Object.freeze({
    kind: 'INDEPENDENT_SCOPED_PLUGIN_REVIEWER_V1',
    revokeKey(keyId) { if (!id(keyId)) throw new Error('PLUGIN_REVOCATION_INVALID'); revokedKeys.add(keyId) },
    revokeAuthority(authorityId) { if (!id(authorityId)) throw new Error('PLUGIN_REVOCATION_INVALID'); revokedAuthorities.add(authorityId) },
    exportRevocations() { return { schema: 'armorbreak.plugin-revocations/v1', keys: [...revokedKeys].sort(), authorities: [...revokedAuthorities].sort() } },
    review(snapshot, receipts = {}) {
      const active = immutable.filter(root => !revokedKeys.has(root.keyId) && !revokedAuthorities.has(root.authorityId))
      const result = createPluginReviewer(active).review(snapshot, receipts)
      const source = byKey.get(receipts.sourceReceipt?.keyId), rights = byKey.get(receipts.rightsReceipt?.keyId)
      if (result.sourceAuthenticated && result.rightsVerified && source.authorityId === rights.authorityId) result.blocked.push('SIGNER_AUTHORITIES_NOT_INDEPENDENT')
      const blocked = result.blocked.length > 0
      return { ...result, state: blocked ? 'BLOCKED' : 'READY_FOR_SYNTHETIC_STAGING_APPROVAL',
        trustPolicy: { mode: 'INDEPENDENT_SCOPED_ATTESTERS_V1', independentKeyRequired: true, independentAuthorityRequired: true,
          authorityIndependence: 'DECLARED_BY_TRUSTED_HOST_NOT_EXTERNALLY_VERIFIED', revocationCount: revokedKeys.size + revokedAuthorities.size },
        plugins: result.plugins.map(plugin => ({ ...plugin, policyEligible: !blocked, corePolicyState: blocked ? 'DENIED_OR_UNVERIFIED' : 'SYNTHETIC_PLAN_ELIGIBLE' })) }
    },
  })
}
