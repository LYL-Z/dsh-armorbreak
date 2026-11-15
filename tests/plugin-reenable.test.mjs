import test from 'node:test'
import assert from 'node:assert/strict'
import { storeFixture, approved, context } from './helpers/plugin-store-fixture.mjs'
import { reopenIsolatedPluginInstall } from '../packages/core/src/isolatedPluginStore.js'
async function disabledFixture(t){
 const f=await storeFixture(t),installed=await f.plan(await f.candidate());await installed.apply(approved)
 const disabled=await f.plan({operation:'disable',current:installed});await disabled.apply(approved)
 return {...f,installed,disabled}
}
test('disabled quarantine can regain file selection only by a fresh reviewed and approved transaction, and restore returns to disabled',async t=>{
 const f=await disabledFixture(t);await assert.rejects(()=>f.disabled.copySelected(),/DISABLED/)
 const enabled=await f.plan({operation:'enable',current:f.disabled})
 assert.equal((await enabled.inspect()).selectionAvailable,false);await assert.rejects(()=>enabled.copySelected(),/TRANSACTION_NOT_FINAL/)
 const done=await enabled.apply(approved);assert.equal(done.selectionAvailable,true);assert.equal(done.activationAuthorized,false);assert.equal(done.hostWrites,false);assert.equal(done.productionInstallation,false)
 assert.deepEqual(await enabled.readInstalled('inert.js'),Buffer.from('throw new Error("NEVER_EXECUTE_1.0.0")\r\n'))
 assert.equal((await f.disabled.inspect()).state.status,'DISABLED');await assert.rejects(()=>f.disabled.copySelected(),/DISABLED/)
 const reopened=await reopenIsolatedPluginInstall(f.runtime,enabled.root,{...context,reviewer:f.reviewer});assert.equal((await reopened.inspect()).selectionAvailable,true)
 await reopened.rollback(approved);assert.equal((await reopened.inspect()).state.status,'DISABLED');await assert.rejects(()=>reopened.readInstalled('inert.js'),/DISABLED/)
})
test('enable refuses missing approval, wrong owner/session, active packages and injected replacement candidates',async t=>{
 const f=await disabledFixture(t)
 await assert.rejects(()=>f.plan({operation:'enable',current:f.installed}),/REQUIRES_DISABLED/)
 const replacement=await f.candidate('2.0.0')
 await assert.rejects(()=>f.plan({operation:'enable',current:f.disabled,...replacement}),/OPERATION_INVALID/)
 await assert.rejects(()=>f.plan({operation:'enable',current:f.disabled,operator:'another-user'}))
 await assert.rejects(()=>f.plan({operation:'enable',current:f.disabled,sessionId:'another-session'}))
 const enabled=await f.plan({operation:'enable',current:f.disabled});await assert.rejects(()=>enabled.apply({request:async()=> 'denied'}))
 assert.equal((await enabled.inspect()).selectionAvailable,false);await assert.rejects(()=>enabled.copySelected())
})
for(const revocation of ['key','authority'])test(`enable cannot revive a ${revocation}-revoked package`,async t=>{
 const f=await disabledFixture(t)
 if(revocation==='key')f.reviewer.revokeKey('source');else f.reviewer.revokeAuthority('rights-reviewer')
 await assert.rejects(()=>f.plan({operation:'enable',current:f.disabled}),/REVIEW_DENIED/)
 await assert.rejects(()=>f.disabled.copySelected(),/DISABLED/)
})
test('revocation between enable planning and delayed approval is rechecked before commit',async t=>{
 const f=await disabledFixture(t),enabled=await f.plan({operation:'enable',current:f.disabled})
 await assert.rejects(()=>enabled.apply({request:async()=>{f.reviewer.revokeKey('source');return 'allowed-once'}}),/REVOKED_OR_DENIED/)
 assert.equal((await enabled.inspect()).selectionAvailable,false);await assert.rejects(()=>enabled.copySelected())
 assert.equal((await f.disabled.inspect()).state.status,'DISABLED')
})
