import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm, readdir, readFile, appendFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawn } from 'node:child_process'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { publish, reconcile } from '../tools/trusted-gate/runtime.mjs'
import { publish as oldPublish, withLease as oldLease } from './fixtures/trusted-runtime-d95.mjs'
const sha='a'.repeat(40), externalId='d'.repeat(64)
async function fixture(t){
 const stateDirectory=await mkdtemp(join(tmpdir(),'ab-r4-'));t.after(()=>rm(stateDirectory,{recursive:true,force:true}))
 const f={calls:[],remote:null,visible:true,dropPost:false,dropPatch:false,wrongReadback:false}
 f.args={stateDirectory,config:{appId:99,repositoryId:10},repository:'owner/repo',target:sha,decision:{context:'trusted',errors:[]},externalId,recheck:async()=>{}}
 f.api=async(path,method='GET',body)=>{
  f.calls.push({path,method,body})
  if(path.startsWith('installation/'))return{total_count:1,repositories:[{id:10}]}
  if(path.includes('/commits/'))return{total_count:f.remote&&f.visible?1:0,check_runs:f.remote&&f.visible?[{...f.remote}]:[]}
  if(method==='POST'){f.remote={id:3,name:'trusted',app:{id:99},head_sha:sha,external_id:externalId,status:'in_progress',conclusion:null};if(f.dropPost)throw new Error('POST response lost');return{...f.remote}}
  if(method==='PATCH'){f.remote={...f.remote,status:body.status,conclusion:body.conclusion};if(f.dropPatch)throw new Error('PATCH response lost');return{...f.remote}}
  if(!f.remote)throw new Error('remote unavailable')
  return {...f.remote,...(f.wrongReadback?{status:'in_progress'}:{})}
 }
 f.posts=()=>f.calls.filter(x=>x.method==='POST').length
 f.patches=()=>f.calls.filter(x=>x.method==='PATCH').length
 f.rows=async()=>{const files=await readdir(stateDirectory);const file=files.find(n=>n.endsWith('.jsonl'));return(await readFile(join(stateDirectory,file),'utf8')).trim().split('\n').map(JSON.parse)}
 return f
}
test('old runtime repeats ambiguous POST; new runtime persists and refuses retry',async t=>{
 const f=await fixture(t);f.dropPost=true;f.visible=false
 const lock=join(f.args.stateDirectory,'old.lock')
 for(let i=0;i<2;i++)await assert.rejects(oldLease(lock,()=>oldPublish(f.api,f.args)),/POST response lost/)
 assert.equal(f.posts(),2)
 const n=await fixture(t);n.dropPost=true;n.visible=false
 await assert.rejects(publish(n.api,n.args),/POST response lost/)
 await assert.rejects(publish(n.api,n.args),/RECONCILIATION_REQUIRED/)
 assert.equal(n.posts(),1)
 assert.equal((await n.rows()).at(-1).state,'RECONCILIATION_REQUIRED')
 assert.equal((await n.rows())[1].state,'POST_INTENT')
 assert.equal((await n.rows())[1].binding.externalId,externalId)
})
test('POST remote effect with lost response reconciles without new POST',async t=>{
 const f=await fixture(t);f.dropPost=true
 await assert.rejects(publish(f.api,f.args))
 assert.equal((await reconcile(f.api,f.args)).state,'READY_TO_COMPLETE')
 assert.equal((await publish(f.api,f.args)).status,'completed')
 assert.equal(f.posts(),1);assert.equal(f.patches(),1)
 assert.equal((await f.rows()).at(-1).state,'COMPLETED')
})
test('POST timeout and temporarily invisible receipt remains unresolved',async t=>{
 const f=await fixture(t);f.dropPost=true;f.visible=false
 await assert.rejects(publish(f.api,f.args))
 for(let i=0;i<3;i++)await assert.rejects(reconcile(f.api,f.args),/not yet visible/)
 await assert.rejects(publish(f.api,f.args),/RECONCILIATION_REQUIRED/)
 assert.equal(f.posts(),1);assert.equal(f.patches(),0)
})
test('PATCH remote effect with lost response is recovered read-only',async t=>{
 const f=await fixture(t);f.dropPatch=true
 await assert.rejects(publish(f.api,f.args),/PATCH response lost/)
 await assert.rejects(publish(f.api,f.args),/RECONCILIATION_REQUIRED/)
 assert.equal((await reconcile(f.api,f.args)).state,'COMPLETED')
 assert.equal((await publish(f.api,f.args)).status,'completed')
 assert.equal(f.posts(),1);assert.equal(f.patches(),1)
})
test('PATCH uncertain and incomplete read must not cause another PATCH',async t=>{
 const f=await fixture(t);f.dropPatch=true;await assert.rejects(publish(f.api,f.args))
 f.remote.status='in_progress';f.remote.conclusion=null
 await assert.rejects(reconcile(f.api,f.args),/uncertain completion/)
 await assert.rejects(publish(f.api,f.args),/RECONCILIATION_REQUIRED/)
 assert.equal(f.patches(),1)
})
test('repeated successful polling neither recreates nor repatches',async t=>{
 const f=await fixture(t);await publish(f.api,f.args)
 for(let i=0;i<3;i++)await publish(f.api,f.args)
 assert.equal(f.posts(),1);assert.equal(f.patches(),1)
})
test('fresh runtime import sees durable unresolved publication',async t=>{
 const f=await fixture(t);f.dropPost=true;await assert.rejects(publish(f.api,f.args))
 const fresh=await import(new URL('../tools/trusted-gate/runtime.mjs?restart',import.meta.url))
 await assert.rejects(fresh.publish(f.api,f.args),/RECONCILIATION_REQUIRED/)
 assert.equal(f.posts(),1)
})
test('wrong App receipt cannot reconcile or cause recreation',async t=>{
 const f=await fixture(t);f.dropPost=true;await assert.rejects(publish(f.api,f.args));f.remote.app.id=88
 await assert.rejects(reconcile(f.api,f.args),/issuer/)
 await assert.rejects(publish(f.api,f.args),/RECONCILIATION_REQUIRED/);assert.equal(f.posts(),1)
})
test('conclusion success without status completed is not completion evidence',async t=>{
 const f=await fixture(t);f.wrongReadback=true
 await assert.rejects(publish(f.api,f.args),/readback status/)
 await assert.rejects(reconcile(f.api,f.args),/uncertain completion/)
 assert.equal(f.patches(),1)
})
test('recovery rejects duplicate remote receipts',async t=>{
 const f=await fixture(t);f.dropPost=true;await assert.rejects(publish(f.api,f.args))
 const api=(p,m,b)=>p.includes('/commits/')?Promise.resolve({total_count:2,check_runs:[f.remote,{...f.remote,id:4}]}):f.api(p,m,b)
 await assert.rejects(reconcile(api,f.args),/duplicate/);assert.equal(f.posts(),1)
})
test('changed decision for same external_id cannot adopt journal',async t=>{
 const f=await fixture(t);await publish(f.api,f.args)
 await assert.rejects(publish(f.api,{...f.args,target:'b'.repeat(40)}),/journal identity/)
 assert.equal(f.posts(),1)
})
test('recovery revalidates live PR/base/policy before action',async t=>{
 const f=await fixture(t);f.dropPost=true;await assert.rejects(publish(f.api,f.args))
 f.args.recheck=async()=>{throw new Error('base changed')}
 await assert.rejects(reconcile(f.api,f.args),/base changed/)
 assert.equal(f.patches(),0)
})
test('torn journal is retained and refuses publication',async t=>{
 const f=await fixture(t);await publish(f.api,f.args)
 const file=(await readdir(f.args.stateDirectory)).find(n=>n.endsWith('.jsonl'))
 await appendFile(join(f.args.stateDirectory,file),'torn')
 await assert.rejects(publish(f.api,f.args),/torn/)
 assert.ok((await readFile(join(f.args.stateDirectory,file),'utf8')).endsWith('torn'))
 assert.equal(f.posts(),1)
})
const runtimeURL=new URL('../tools/trusted-gate/runtime.mjs',import.meta.url).href
const worker=`import {publish} from ${JSON.stringify(runtimeURL)};import{appendFile,writeFile,readdir}from'node:fs/promises';import{join}from'node:path';const dir=process.argv[1],who=process.argv[2],drop=process.argv[3]==='drop';await writeFile(join(dir,'ready-'+who),'1');if(!drop){while((await readdir(dir)).filter(x=>x.startsWith('ready-')).length<2)await new Promise(r=>setTimeout(r,5));}const id='d'.repeat(64),sha='a'.repeat(40);const check={id:3,name:'trusted',app:{id:99},head_sha:sha,external_id:id,status:'completed',conclusion:'success'};const api=async(p,m='GET',b)=>{if(p.startsWith('installation/'))return{total_count:1,repositories:[{id:10}]};if(p.includes('/commits/'))return{total_count:0,check_runs:[]};if(m==='POST'){await appendFile(join(dir,'posts'),'POST\\n');if(drop)throw Error('lost POST');await new Promise(r=>setTimeout(r,100));return{...check,status:'in_progress',conclusion:null}}return check};try{await publish(api,{stateDirectory:dir,config:{appId:99,repositoryId:10},repository:'owner/repo',target:sha,externalId:id,decision:{context:'trusted',errors:[]},recheck:async()=>{}})}catch(e){console.error(e.message);process.exitCode=1}`
function child(dir,who,mode='normal'){return new Promise((resolve,reject)=>{const p=spawn(process.execPath,['--input-type=module','-e',worker,dir,who,mode]);let err='';p.stderr.on('data',d=>err+=d);p.on('error',reject);p.on('exit',code=>resolve({code,err}))})}
test('two real publishing processes compete; at most one remote POST',async t=>{
 const f=await fixture(t);const results=await Promise.all([child(f.args.stateDirectory,'1'),child(f.args.stateDirectory,'2')])
 assert.ok(results.some(r=>r.code===0));assert.ok(results.every(r=>r.code===0||/lease/.test(r.err)))
 assert.equal((await readFile(join(f.args.stateDirectory,'posts'),'utf8')).trim().split('\n').length,1)
})
test('real process restart retains uncertain POST and cannot post again',async t=>{
 const f=await fixture(t);const first=await child(f.args.stateDirectory,'1','drop');assert.equal(first.code,1);assert.match(first.err,/lost POST/)
 const second=await child(f.args.stateDirectory,'2','drop');assert.equal(second.code,1);assert.match(second.err,/RECONCILIATION_REQUIRED/)
 assert.equal((await readFile(join(f.args.stateDirectory,'posts'),'utf8')).trim().split('\n').length,1)
})

test('hard crash after POST intent survives explicit lock-only operator recovery',async t=>{
 const f=await fixture(t)
 const crashWorker=worker.replace("drop=process.argv[3]==='drop'", "drop=process.argv[3]==='drop',crash=process.argv[3]==='crash'").replace('if(!drop){','if(!drop&&!crash){').replace("if(drop)throw Error('lost POST');", "if(crash)process.exit(5);if(drop)throw Error('lost POST');")
 const result=await new Promise((resolve,reject)=>{const p=spawn(process.execPath,['--input-type=module','-e',crashWorker,f.args.stateDirectory,'1','crash']);p.on('error',reject);p.on('exit',code=>resolve(code))})
 assert.equal(result,5)
 assert.equal((await f.rows()).at(-1).state,'POST_INTENT')
 // Explicit test operator action AFTER proving process termination; only the
 // mutex is released. Publication history is never deleted or reset.
 const lock=(await readdir(f.args.stateDirectory)).find(n=>n.endsWith('.lock'))
 await rm(join(f.args.stateDirectory,lock))
 const retry=await child(f.args.stateDirectory,'2','drop')
 assert.equal(retry.code,1);assert.match(retry.err,/RECONCILIATION_REQUIRED/)
 assert.equal((await f.rows()).at(-1).state,'RECONCILIATION_REQUIRED')
 assert.equal((await readFile(join(f.args.stateDirectory,'posts'),'utf8')).trim().split('\n').length,1)
})
