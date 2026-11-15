import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { storeFixture, approved, context } from './helpers/plugin-store-fixture.mjs'
import { reopenIsolatedPluginInstall } from '../packages/core/src/isolatedPluginStore.js'

test('uninstall deselects only after one-use Core approval, reopens, and separately restores exact selected bytes',async t=>{
 const f=await storeFixture(t),installed=await f.plan(await f.candidate());await installed.apply(approved)
 const original=(await installed.copySelected()).files
 const removed=await f.plan({operation:'uninstall',current:installed}),selector=join(removed.root,'data','installation.txt'),before=await readFile(selector)
 await assert.rejects(()=>removed.apply(),/PROVIDER_REQUIRED/);assert.deepEqual(await readFile(selector),before)
 await assert.rejects(()=>removed.apply({request:async()=> 'denied'}));assert.deepEqual(await readFile(selector),before)
 await removed.apply(approved)
 assert.equal((await removed.inspect()).state.status,'NOT_INSTALLED');assert.equal((await removed.inspect()).fileCount,0)
 await assert.rejects(()=>removed.readInstalled('inert.js'),/DISABLED/);await assert.rejects(()=>removed.copySelected(),/NOT_INSTALLED/)
 await assert.rejects(()=>removed.apply(approved))
 const reopened=await reopenIsolatedPluginInstall(f.runtime,removed.root,{...context,reviewer:f.reviewer})
 await assert.rejects(()=>reopened.rollback({request:async()=> 'denied'}))
 await reopened.rollback(approved);assert.deepEqual((await reopened.copySelected()).files,original)
 await assert.rejects(()=>reopened.rollback(approved))
})
for(const action of ['revokeKey','revokeAuthority'])test(`uninstall retains private revoked history for rollback without granting export: ${action}`,async t=>{
 const f=await storeFixture(t),installed=await f.plan(await f.candidate());await installed.apply(approved)
 f.reviewer[action](action==='revokeKey'?'source':'rights-reviewer')
 const removed=await f.plan({operation:'uninstall',current:installed});await removed.apply(approved)
 await assert.rejects(()=>removed.copySelected(),/NOT_INSTALLED/)
 await removed.rollback(approved);assert.equal((await removed.inspect()).selectionAvailable,false)
 await assert.rejects(()=>removed.copySelected(),/DISABLED/)
})
test('disabled uninstall rollback stays disabled; drift and arbitrary destination/candidate options are refused',async t=>{
 const f=await storeFixture(t),installed=await f.plan(await f.candidate());await installed.apply(approved)
 const disabled=await f.plan({operation:'disable',current:installed});await disabled.apply(approved)
 const removed=await f.plan({operation:'uninstall',current:disabled});await removed.apply(approved);await removed.rollback(approved)
 assert.equal((await removed.inspect()).state.status,'DISABLED');await assert.rejects(()=>removed.copySelected(),/DISABLED/)
 await assert.rejects(async()=>f.plan({operation:'uninstall',current:installed,...await f.candidate()}),/OPERATION_INVALID/)
 await assert.rejects(()=>f.plan({operation:'uninstall',current:installed,destination:f.root}),/OPERATION_INVALID/)
 const drifted=await f.plan({operation:'uninstall',current:installed});await writeFile(join(drifted.root,'data','installation.txt'),'unknown partial bytes')
 await assert.rejects(()=>drifted.apply(approved),/DRIFT|CHANGED/)
})
test('post-selector interruption refuses export until separately approved rollback restores bytes',async t=>{
 const f=await storeFixture(t),installed=await f.plan(await f.candidate());await installed.apply(approved)
 const bytes=(await installed.copySelected()).files,removed=await f.plan({operation:'uninstall',current:installed})
 await assert.rejects(()=>removed.apply(approved,()=>{throw new Error('INJECTED_UNINSTALL_CRASH')}),/INJECTED/)
 const reopened=await reopenIsolatedPluginInstall(f.runtime,removed.root,{...context,reviewer:f.reviewer})
 await assert.rejects(()=>reopened.copySelected(),/TRANSACTION_NOT_FINAL/)
 await reopened.rollback(approved);assert.deepEqual((await reopened.copySelected()).files,bytes)
})
