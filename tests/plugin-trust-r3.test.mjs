import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createHash, sign } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import * as lifecycle from '../lib/catalog/pluginLifecycle.js'
import { canonicalConfig } from '../lib/integrations/configOverlay.js'
import { verifyPluginClosure } from '../lib/catalog/pluginPackage.js'
const repository='https://github.com/example/self-authored-fixture'
async function fixture(t) {
  const root=await mkdtemp(join(tmpdir(),'ab-trust-r3-'));t.after(()=>rm(root,{recursive:true,force:true}))
  const bytes='export const inert = true\n'
  const catalog={schema:'armorbreak.plugin-catalog/v1',plugins:[{id:'inert',version:'1.0.0',source:{repository,commit:'a'.repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux'],channel:'stable',enabled:false,files:[{path:'inert.js',sha256:createHash('sha256').update(bytes).digest('hex')}]}]}
  await writeFile(join(root,'inert.js'),bytes);await writeFile(join(root,'armorbreak-plugin.json'),JSON.stringify(catalog))
  const { readFile }=await import('node:fs/promises')
  const snapshot=await verifyPluginClosure({targetPath:root,env:{readFile:async p=>readFile(p),listFiles:async()=>['armorbreak-plugin.json','inert.js'].map(p=>join(root,p))},options:{}})
  const source=generateKeyPairSync('ed25519'),rights=generateKeyPairSync('ed25519')
  const roots=[{keyId:'source',authorityId:'publisher-review',role:'source',repositories:[repository],publicKey:source.publicKey.export({type:'spki',format:'pem'})},{keyId:'rights',authorityId:'rights-review',role:'rights',repositories:[repository],publicKey:rights.publicKey.export({type:'spki',format:'pem'})}]
  const receipt=(role,key)=>{const payload=lifecycle.pluginAttestationPayload(snapshot,role);return {keyId:role,payload,signature:sign(null,Buffer.from(canonicalConfig(payload)),key).toString('base64')}}
  return {roots,snapshot,receipts:{sourceReceipt:receipt('source',source.privateKey),rightsReceipt:receipt('rights',rights.privateKey)}}
}

test('independent policy rejects one public key assigned to both attester roles',async t=>{
  const {roots}=await fixture(t)
  roots[1].publicKey=roots[0].publicKey
  assert.throws(()=>lifecycle.createIndependentPluginReviewer({roots}),/INDEPENDENT_KEY/)
})
test('different keys under the same declared authority cannot satisfy independent review',async t=>{
  const {roots,snapshot,receipts}=await fixture(t);roots[1].authorityId=roots[0].authorityId
  const review=lifecycle.createIndependentPluginReviewer({roots}).review(snapshot,receipts)
  assert.equal(review.sourceAuthenticated,true);assert.equal(review.rightsVerified,true)
  assert.equal(review.state,'BLOCKED');assert.ok(review.blocked.includes('SIGNER_AUTHORITIES_NOT_INDEPENDENT'))
  assert.equal(review.plugins[0].policyEligible,false)
})
test('distinct authorities/keys remain scoped, role/repository bound and monotonically revocable',async t=>{
  const {roots,snapshot,receipts}=await fixture(t),reviewer=lifecycle.createIndependentPluginReviewer({roots})
  const allowed=reviewer.review(snapshot,receipts)
  assert.equal(allowed.state,'READY_FOR_SYNTHETIC_STAGING_APPROVAL')
  assert.equal(allowed.trustPolicy.authorityIndependence,'DECLARED_BY_TRUSTED_HOST_NOT_EXTERNALLY_VERIFIED')
  assert.equal(allowed.activationAuthorized,false);assert.equal(allowed.releaseEligible,false)
  assert.equal(reviewer.review(snapshot,{sourceReceipt:receipts.rightsReceipt,rightsReceipt:receipts.sourceReceipt}).state,'BLOCKED')
  const otherRoots=structuredClone(roots);otherRoots[0].repositories=['https://github.com/example/other']
  assert.equal(lifecycle.createIndependentPluginReviewer({roots:otherRoots}).review(snapshot,receipts).sourceAuthenticated,false)
  roots[0].authorityId='caller-mutated';assert.equal(reviewer.review(snapshot,receipts).state,'READY_FOR_SYNTHETIC_STAGING_APPROVAL')
  reviewer.revokeKey('source')
  assert.equal(reviewer.review(snapshot,receipts).sourceAuthenticated,false)
  const resumed=lifecycle.createIndependentPluginReviewer({roots,revocations:reviewer.exportRevocations()})
  assert.equal(resumed.review(snapshot,receipts).state,'BLOCKED')
  assert.equal(typeof reviewer.unrevokeKey,'undefined')
})
test('authority revocation invalidates every bound key; candidate revocation overrides are rejected',async t=>{
  const {roots,snapshot,receipts}=await fixture(t),reviewer=lifecycle.createIndependentPluginReviewer({roots})
  reviewer.revokeAuthority('rights-review')
  const result=reviewer.review(snapshot,receipts)
  assert.equal(result.rightsVerified,false);assert.equal(result.state,'BLOCKED')
  assert.throws(()=>lifecycle.createIndependentPluginReviewer({roots,revocations:{schema:'forged',keys:[],authorities:[]}}),/REVOCATION/)
  assert.equal(reviewer.review(snapshot,{...receipts,revocations:{keys:[],authorities:[]}}).state,'BLOCKED')
})
