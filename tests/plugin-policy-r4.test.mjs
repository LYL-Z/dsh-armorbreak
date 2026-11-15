import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { storeFixture, approved, context } from './helpers/plugin-store-fixture.mjs'
import { canonicalConfig } from '../lib/integrations/configOverlay.js'
import { createPersistentPluginReviewer, openPersistentPluginReviewer } from '../lib/catalog/persistentPluginTrust.js'
import { reopenIsolatedPluginInstall } from '../packages/core/src/isolatedPluginStore.js'

const moduleUrl=new URL('../lib/catalog/persistentPluginTrust.js',import.meta.url).href
async function fixture(t){
 const issuer=generateKeyPairSync('ed25519'),publicKey=issuer.publicKey.export({type:'spki',format:'pem'})
 const envelope=(roots,version=1,extra={})=>{const payload={schema:'armorbreak.plugin-trust-policy/v1',policyId:'synthetic-owner-policy',version,notBefore:Date.now()-60000,expiresAt:Date.now()+600000,roots,...extra};return {payload,signature:sign(null,Buffer.from(canonicalConfig(payload)),issuer.privateKey).toString('base64')}}
 let directory,policy
 const f=await storeFixture(t,{reviewerFactory({roots,root}){directory=join(root,'trust');policy=envelope(roots);return createPersistentPluginReviewer({directory,policy,policyPublicKey:publicKey})}})
 writeFileSync(join(f.root,'public-key.pem'),publicKey)
 const reopen=minimumSequence=>openPersistentPluginReviewer({directory,policyPublicKey:publicKey,minimumSequence})
 const child=action=>JSON.parse(execFileSync(process.execPath,['--input-type=module','-e',`import {openPersistentPluginReviewer} from ${JSON.stringify(moduleUrl)};import{readFileSync}from'node:fs';const r=openPersistentPluginReviewer({directory:process.argv[1],policyPublicKey:readFileSync(process.argv[2],'utf8')});try{${action};console.log(JSON.stringify({checkpoint:r.checkpoint(),revocations:r.exportRevocations()}))}catch(e){console.log(JSON.stringify({error:e.message}))}`,directory,join(f.root,'public-key.pem')],{encoding:'utf8',timeout:30000}))
 return {...f,directory,policy,publicKey,envelope,reopen,child}
}

test('actual fresh process sees durable revocations; reopened store refuses both exports',async t=>{
 const f=await fixture(t),candidate=await f.candidate(),store=await f.plan(candidate);await store.apply(approved)
 f.reviewer.revokeKey('source');const seq=f.reviewer.checkpoint().sequence
 assert.equal(f.child('').revocations.keys.includes('source'),true)
 const reopened=await reopenIsolatedPluginInstall(f.runtime,store.root,{...context,reviewer:f.reopen(seq)})
 await assert.rejects(()=>reopened.copySelected(),/DISABLED_OR_UNTRUSTED/)
 await assert.rejects(()=>reopened.readInstalled('inert.js'),/DISABLED_OR_UNTRUSTED/)
 f.child("r.revokeAuthority('rights-reviewer')")
 assert.deepEqual(f.reviewer.exportRevocations().authorities,['rights-reviewer'])
 const {verifyPluginClosure}=await import('../lib/catalog/pluginPackage.js')
 assert.equal(f.reviewer.review(await verifyPluginClosure(candidate.candidate),candidate.receipts).state,'BLOCKED')
})

test('signed rotation advances policy, rejects old/repeated policy and preserves revoked key material',async t=>{
 const f=await fixture(t),candidate=await f.candidate(),newKey=generateKeyPairSync('ed25519')
 const roots=structuredClone(f.roots);roots[0]={...roots[0],keyId:'source-rotated',publicKey:newKey.publicKey.export({type:'spki',format:'pem'})}
 const next=f.envelope(roots,2);f.reviewer.rotatePolicy(next)
 const receipts=structuredClone(candidate.receipts);receipts.sourceReceipt={...receipts.sourceReceipt,keyId:'source-rotated',signature:sign(null,Buffer.from(canonicalConfig(receipts.sourceReceipt.payload)),newKey.privateKey).toString('base64')}
 const {verifyPluginClosure}=await import('../lib/catalog/pluginPackage.js'),snapshot=await verifyPluginClosure(candidate.candidate)
 assert.equal(f.reviewer.review(snapshot,candidate.receipts).state,'BLOCKED')
 assert.equal(f.reviewer.review(snapshot,receipts).state,'READY_FOR_SYNTHETIC_STAGING_APPROVAL')
 assert.throws(()=>f.reviewer.rotatePolicy(f.policy),/VERSION_ROLLBACK/)
 assert.throws(()=>f.reviewer.rotatePolicy(next),/VERSION_ROLLBACK/)
 f.reviewer.revokeKey('source-rotated')
 roots[0].keyId='renamed-revoked-key';f.reviewer.rotatePolicy(f.envelope(roots,3))
 receipts.sourceReceipt.keyId=roots[0].keyId
 assert.equal(f.reopen().review(snapshot,receipts).sourceAuthenticated,false)
 assert.equal(f.child('').checkpoint.policyVersion,3)
})

test('unsigned, expired, future and role/repository-mixed policies or assertions do not authorize staging',async t=>{
 const f=await fixture(t),candidate=await f.candidate(),{verifyPluginClosure}=await import('../lib/catalog/pluginPackage.js'),snapshot=await verifyPluginClosure(candidate.candidate)
 const tampered=structuredClone(f.policy);tampered.payload.version=2
 assert.throws(()=>f.reviewer.rotatePolicy(tampered),/SIGNATURE/)
 assert.throws(()=>f.reviewer.rotatePolicy(f.envelope(f.roots,2,{notBefore:0,expiresAt:1})),/NOT_CURRENT/)
 assert.throws(()=>f.reviewer.rotatePolicy(f.envelope(f.roots,2,{notBefore:Date.now()+60000,expiresAt:Date.now()+120000})),/NOT_CURRENT/)
 assert.equal(f.reviewer.review(snapshot,{sourceReceipt:candidate.receipts.rightsReceipt,rightsReceipt:candidate.receipts.sourceReceipt}).state,'BLOCKED')
 const roots=structuredClone(f.roots);roots[0].repositories=['https://github.com/example/other'];f.reviewer.rotatePolicy(f.envelope(roots,2))
 assert.equal(f.reviewer.review(snapshot,candidate.receipts).state,'BLOCKED')
 const common=structuredClone(f.roots);common[1].authorityId=common[0].authorityId;f.reviewer.rotatePolicy(f.envelope(common,3))
 assert.equal(f.reviewer.review(snapshot,candidate.receipts).state,'BLOCKED')
 assert.equal(f.reviewer.checkpoint().authorityIdentity,'PINNED_ISSUER_ASSERTION_NOT_EXTERNAL_IDENTITY_PROOF')
})

test('truncated, corrupt or locally rolled-back journals fail closed; restart floor must come from trusted caller',async t=>{
 const f=await fixture(t),journal=join(f.directory,'policy.ndjson'),genesis=readFileSync(journal)
 f.reviewer.revokeKey('source');const current=readFileSync(journal),floor=f.reviewer.checkpoint().sequence
 writeFileSync(journal,genesis)
 assert.throws(()=>f.reviewer.checkpoint(),/HISTORY_ROLLBACK/)
 assert.throws(()=>f.reopen(floor),/HISTORY_ROLLBACK/)
 writeFileSync(journal,current.subarray(0,current.length-8));assert.throws(()=>f.reopen(),/INCOMPLETE/)
 writeFileSync(journal,Buffer.from(current.toString().replace('revokeKey','revokexxx')));assert.throws(()=>f.reopen(),/CORRUPT/)
 writeFileSync(journal,current);assert.equal(f.reopen(floor).checkpoint().sequence,floor)
})

test('actual cross-process revocation cannot complete during selector commit; completed revocation blocks later selection',async t=>{
 const f=await fixture(t),store=await f.plan(await f.candidate())
 let enter,release;const waiting=new Promise(r=>enter=r),hold=new Promise(r=>release=r)
 const applying=store.apply(approved,async()=>{enter();await hold})
 await waiting
 try{assert.equal(f.child("r.revokeKey('source')").error,'PLUGIN_POLICY_BUSY');await assert.rejects(()=>store.copySelected(),/TRANSACTION_NOT_FINAL|POLICY_BUSY/)}finally{release();await applying}
 assert.ok((await store.copySelected()).files.length)
 assert.equal(f.child("r.revokeKey('source')").revocations.keys.includes('source'),true)
 await assert.rejects(()=>store.copySelected(),/DISABLED_OR_UNTRUSTED/)
 await store.rollback(approved);assert.equal((await store.inspect()).state.status,'NOT_INSTALLED')
})
