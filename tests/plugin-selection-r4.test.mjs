import test from 'node:test'
import assert from 'node:assert/strict'
import { storeFixture, approved, context } from './helpers/plugin-store-fixture.mjs'
import { reopenIsolatedPluginInstall } from '../packages/core/src/isolatedPluginStore.js'
import { createIndependentPluginReviewer } from '../lib/catalog/pluginLifecycle.js'

test('disabled public exports refuse bytes while private history still supports update and rollback',async t=>{
 const f=await storeFixture(t),installed=await f.plan(await f.candidate());await installed.apply(approved)
 const original=(await installed.copySelected()).files.find(x=>x.path==='inert.js').bytes
 const disabled=await f.plan({operation:'disable',current:installed});await disabled.apply(approved)
 await assert.rejects(()=>disabled.copySelected(),/DISABLED_OR_UNTRUSTED/)
 await assert.rejects(()=>disabled.copySelected({allowHistorical:true}),/DISABLED_OR_UNTRUSTED/)
 const next=await f.plan({...await f.candidate('2.0.0'),operation:'update',current:disabled});await next.apply(approved)
 assert.equal((await next.inspect()).state.status,'DISABLED');await assert.rejects(()=>next.copySelected(),/DISABLED_OR_UNTRUSTED/)
 await next.rollback(approved);await assert.rejects(()=>next.copySelected(),/DISABLED_OR_UNTRUSTED/)
 await disabled.rollback(approved);assert.deepEqual((await disabled.copySelected()).files.find(x=>x.path==='inert.js').bytes,original)
 assert.equal(typeof disabled.copySnapshot,'undefined');assert.equal(typeof disabled.copyHistorical,'undefined')
})
for(const action of ['revokeKey','revokeAuthority'])test(`${action}: public reads, copy and reopened objects refuse; internal disable/rollback retains history`,async t=>{
 const f=await storeFixture(t),store=await f.plan(await f.candidate());await store.apply(approved)
 f.baseReviewer[action](action==='revokeKey'?'source':'rights-reviewer')
 await assert.rejects(()=>store.readInstalled('inert.js'),/DISABLED_OR_UNTRUSTED/)
 await assert.rejects(()=>store.copySelected(),/DISABLED_OR_UNTRUSTED/)
 const restartedReviewer=createIndependentPluginReviewer({roots:f.roots,revocations:f.baseReviewer.exportRevocations()})
 const reopened=await reopenIsolatedPluginInstall(f.runtime,store.root,{...context,reviewer:restartedReviewer})
 await assert.rejects(()=>reopened.copySelected(),/DISABLED_OR_UNTRUSTED/)
 const disabled=await f.plan({current:reopened,operation:'disable'});await disabled.apply(approved)
 await disabled.rollback(approved);assert.equal((await disabled.inspect()).selectionAvailable,false)
 await assert.rejects(()=>disabled.copySelected(),/DISABLED_OR_UNTRUSTED/)
})
test('real pending commit exports no selector bytes; finalized commit and original-byte rollback remain usable',async t=>{
 const f=await storeFixture(t),store=await f.plan(await f.candidate())
 let entered,release;const waiting=new Promise(r=>entered=r),hold=new Promise(r=>release=r)
 const pending=store.apply(approved,async()=>{entered();await hold})
 await waiting
 try{
  assert.equal((await store.inspect()).transactionFinalized,false)
  await assert.rejects(()=>store.copySelected(),/TRANSACTION_NOT_FINAL|DISABLED_OR_UNTRUSTED/)
  await assert.rejects(()=>store.readInstalled('inert.js'),/DISABLED_OR_UNTRUSTED/)
 }finally{release();await pending}
 assert.ok((await store.copySelected()).files.length)
 await store.rollback(approved);await assert.rejects(()=>store.copySelected(),/NOT_INSTALLED|DISABLED_OR_UNTRUSTED/)
})
for(const method of ['readInstalled','copySelected'])test(`${method} rechecks real revocation occurring after its initial inspection`,async t=>{
 let armed=false
 const f=await storeFixture(t,{wrapReviewer:base=>({kind:base.kind,review(...args){const result=base.review(...args);if(armed){armed=false;queueMicrotask(()=>base.revokeKey('source'))}return result}})})
 const store=await f.plan(await f.candidate());await store.apply(approved);armed=true
 await assert.rejects(()=>method==='readInstalled'?store.readInstalled('inert.js'):store.copySelected(),/DISABLED_OR_UNTRUSTED|SELECTION_CHANGED/)
 assert.equal((await store.inspect()).selectionAvailable,false)
})
