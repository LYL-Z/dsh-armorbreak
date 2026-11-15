import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { fork } from 'node:child_process'
import { once } from 'node:events'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
import { planSyntheticConfiguration } from '../packages/core/src/syntheticConfiguration.js'
import { reopenSyntheticMaintenance } from '../packages/core/src/syntheticMaintenance.js'
const context={operator:'fault-owner',sessionId:'fault-session'},source='value: "old"\r\nfuture: false\r\n',approved={request:async()=> 'allowed-once'}
async function setup(t) {
 const stateRoot=await mkdtemp(join(tmpdir(),'ab-config-fault-'));t.after(()=>rm(stateRoot,{recursive:true,force:true}))
 const runtime=new ArmorBreakRuntime({stateRoot});await runtime.init()
 const result=await planSyntheticConfiguration(runtime,{...context,configuration:{schema:'armorbreak.configuration-import/v1',format:'yaml',source},overlays:[{id:'inert',values:{value:'new'}}],conflictPolicy:'last-wins'})
 t.after(()=>rm(result.lab.root,{recursive:true,force:true}));return {...result,runtime,stateRoot}
}
for(const phase of ['TRUNCATED','PARTIAL_WRITE'])test(`configuration ${phase} refuses automatic rollback and preserves sealed original for manual diagnosis`,async t=>{
 const {lab,plan}=await setup(t)
 await assert.rejects(()=>lab.apply(plan.planId,approved,undefined,{maxWriteBytes:2,onWritePhase:event=>{if(event.phase===phase)throw new Error('INJECTED_WRITE_PHASE')}}),/INJECTED_WRITE_PHASE/)
 const bytes=await readFile(join(lab.data,'config.txt'))
 assert.equal(bytes.length,phase==='TRUNCATED'?0:2)
 const status=await lab.recoveryStatus(plan.planId);assert.equal(status.status,'MANUAL_REVIEW_REQUIRED');assert.equal(status.automaticRecovery,false)
 await assert.rejects(()=>lab.rollback(plan.planId,approved),/CONTENT_DRIFT/)
 assert.deepEqual(await readFile(join(lab.data,'config.txt')),bytes)
 assert.deepEqual(Buffer.from(JSON.parse(await readFile(join(lab.control,'plan.json'),'utf8')).value.rows[0].before,'base64'),Buffer.from(source))
})
test('corrupt configuration journal refuses recovery status and writes; only intact evidence permits exact restore',async t=>{
 const {lab,plan}=await setup(t);assert.equal((await lab.recoveryStatus(plan.planId)).status,'PLAN_UNAPPLIED')
 await lab.apply(plan.planId,approved)
 assert.equal((await lab.recoveryStatus(plan.planId)).status,'SAFE_FOR_SEPARATELY_APPROVED_ROLLBACK')
 const path=join(lab.control,'journal.jsonl'),original=await readFile(path),bytes=await readFile(join(lab.data,'config.txt'))
 await writeFile(path,'{"value":{"state":"COMMITTED"},"signature":"bad"}\n')
 await assert.rejects(()=>lab.recoveryStatus(plan.planId),/JOURNAL_INTEGRITY/)
 await assert.rejects(()=>lab.rollback(plan.planId,approved),/JOURNAL_INTEGRITY/)
 assert.deepEqual(await readFile(join(lab.data,'config.txt')),bytes)
 // Fixture restores its preserved journal, not a product repair API or production recovery claim.
 await writeFile(path,original);await lab.rollback(plan.planId,approved)
 assert.deepEqual(await readFile(join(lab.data,'config.txt')),Buffer.from(source))
 assert.equal((await lab.recoveryStatus(plan.planId)).status,'ALREADY_RESTORED')
})
for(const phase of ['TRUNCATED','PARTIAL_WRITE','FILE_SYNCED'])test(`actual child SIGKILL at configuration ${phase} classifies recovery and preserves exact known bytes`,{timeout:30000},async t=>{
 const stateRoot=await mkdtemp(join(tmpdir(),'ab-config-kill-'));t.after(()=>rm(stateRoot,{recursive:true,force:true}))
 const child=fork(new URL('./fixtures/configuration-write-worker.mjs',import.meta.url),[stateRoot,phase],{stdio:['ignore','pipe','pipe','ipc']})
 let stderr='';child.stderr.on('data',b=>stderr+=b);t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL')})
 const message=await Promise.race([once(child,'message').then(([m])=>m),once(child,'exit').then(()=>{throw new Error('CHILD_EXITED: '+stderr)})])
 t.after(()=>rm(message.root,{recursive:true,force:true}))
 const exit=once(child,'exit');child.kill('SIGKILL');await exit
 const runtime=new ArmorBreakRuntime({stateRoot});await runtime.init()
 const lab=await reopenSyntheticMaintenance(runtime,message.root,context)
 await assert.rejects(()=>lab.rollback(message.planId,approved),/LOCKED_RECOVERY_REQUIRED/)
 await lab.releaseExitedProcessLock(child.pid)
 const status=await lab.recoveryStatus(message.planId)
 if(phase==='FILE_SYNCED'){
  assert.equal(status.status,'SAFE_FOR_SEPARATELY_APPROVED_ROLLBACK')
  await assert.rejects(()=>lab.rollback(message.planId,{request:async()=> 'denied'}),/APPROVAL_DENIED/)
  await lab.rollback(message.planId,approved);assert.deepEqual(await readFile(join(lab.data,'config.txt')),Buffer.from(source))
 }else{
  assert.equal(status.status,'MANUAL_REVIEW_REQUIRED')
  const bytes=await readFile(join(lab.data,'config.txt'));assert.equal(bytes.length,phase==='TRUNCATED'?0:2)
  await assert.rejects(()=>lab.rollback(message.planId,approved),/CONTENT_DRIFT/)
  assert.deepEqual(await readFile(join(lab.data,'config.txt')),bytes)
 }
})
