import { mkdtempSync, rmSync } from 'node:fs'
import { after } from 'node:test'
const publicationScratch=[]
after(()=>publicationScratch.forEach(p=>rmSync(p,{recursive:true,force:true})))
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { evaluate, expectedJobs } from '../tools/trusted-gate/evaluate.mjs'
import { evaluate as oldEvaluate } from './fixtures/trusted-gate-v1.mjs'
import { mergeTarget } from '../tools/trusted-gate/binding.mjs'
import { digest, verifyApproval, controllerVersion, readRootFile } from '../tools/trusted-gate/trust.mjs'
import { githubApi, paged, issueToken, publish, withLease } from '../tools/trusted-gate/runtime.mjs'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
const sha = 'a'.repeat(40)
function fixture() {
 const files = {'.github/workflows/development-gate.yml':'100644:worker', 'tests/security.test.mjs':'100644:test', 'package.json':'100644:manifest', 'scripts/validate-development-gate.mjs':'100644:validator', 'tools/trusted-gate/controller.mjs':'100644:controller'}
 const steps=['Full test suite','TypeScript contract check','Assert exact candidate SHA','Static L0 network-free gate','Pull a digest-pinned image','Verify hardened container execution path','Require executed successful dependencies on this exact candidate'].map(name=>({name,status:'completed',conclusion:'success'}))
 return {policy:{repository:'owner/repo',workflowId:10,files},candidate:{repository:'owner/repo',sha,number:38,headRef:'feature',baseRef:'main',baseSha:'b'.repeat(40),headRepository:'owner/repo',baseRepository:'owner/repo',headRepositoryId:1,baseRepositoryId:1},run:{id:20,workflow_id:10,head_sha:sha,repository:{full_name:'owner/repo',id:1},head_repository:{id:1},pull_requests:[{number:38,head:{sha,ref:'feature',repo:{id:1,url:'https://api.github.com/repos/owner/repo'}},base:{sha:'b'.repeat(40),ref:'main',repo:{id:1,url:'https://api.github.com/repos/owner/repo'}}}],event:'pull_request',path:'.github/workflows/development-gate.yml',status:'completed',conclusion:'success'},jobs:expectedJobs.map(name=>({name,head_sha:sha,run_id:20,status:'completed',conclusion:'success',steps:structuredClone(steps)})),tree:{truncated:false,tree:Object.entries(files).map(([path,v])=>({path,type:'blob',mode:v.split(':')[0],sha:v.split(':')[1]}))}}
}
for (const [name,mutate] of [
 ['cross PR success borrowing',f=>f.run.pull_requests[0].number=999],
 ['changed base SHA',f=>f.candidate.baseSha='c'.repeat(40)],
 ['retargeted branch same commit',f=>f.candidate.baseRef='other-main'],
 ['head repository mismatch',f=>f.run.head_repository.id=2],
 ['base repository mismatch',f=>f.run.repository.id=2],
 ['missing run association',f=>delete f.run.pull_requests],
 ['missing candidate PR identity',f=>delete f.candidate.number],
 ['missing head association field',f=>delete f.run.pull_requests[0].head.repo],
 ]) test(`R1 regression: ${name}; old accepts, new rejects`,()=>{const f=fixture();mutate(f);assert.deepEqual(oldEvaluate(f),[]);assert.ok(evaluate(f).length)})
const mergeFixture=()=>({pr:{head:{sha},base:{sha:'b'.repeat(40)},merge_commit_sha:'c'.repeat(40)},merge:{sha:'c'.repeat(40),parents:[{sha:'b'.repeat(40)},{sha}],tree:{sha:'d'.repeat(40)}},head:{sha,tree:{sha:'d'.repeat(40)}}})
test('R2 identical tested HEAD tree qualifies exact merge SHA',()=>{const f=mergeFixture();assert.equal(mergeTarget(f.pr,f.merge,f.head).sha,f.pr.merge_commit_sha)})
for(const [name,mutate]of [['baseline changes',f=>f.pr.base.sha='e'.repeat(40)],['different merge content',f=>f.merge.tree.sha='e'.repeat(40)],['merge unavailable',f=>f.pr.merge_commit_sha=null],['different candidate HEAD',f=>f.head.sha='e'.repeat(40)]])test(`R2 refuses ${name}`,()=>{const f=mergeFixture();mutate(f);assert.throws(()=>mergeTarget(f.pr,f.merge,f.head))})
function approvalFixture(){
 const {privateKey,publicKey}=generateKeyPairSync('ed25519')
 const policy={version:1,repository:'owner/repo',workflowId:10,trustCommit:'a'.repeat(40),files:{}}
 const policyBytes=Buffer.from(JSON.stringify(policy));const code={}
 for(const n of ['bootstrap.mjs','controller.mjs','evaluate.mjs','binding.mjs','trust.mjs','runtime.mjs'])code[n]=Buffer.from(n)
 const m={controllerVersion,policyVersion:1,policySha256:digest(policyBytes),trustCommit:policy.trustCommit,approval:{id:'TEST-ONLY',reason:'fixture',date:'2026-11-10'},controllerFiles:Object.fromEntries(Object.entries(code).map(([n,b])=>[n,digest(b)]))}
 const wrap=()=>{const manifestBytes=Buffer.from(JSON.stringify(m));return{manifestBytes,signature:sign(null,manifestBytes,privateKey),publicKey,policyBytes,minimum:{controllerVersion,policyVersion:1},code}}
 return {policy,m,wrap}
}
test('R3 separately signed policy and actual controller bytes accepted',()=>assert.equal(verifyApproval(approvalFixture().wrap()).policy.version,1))
test('R3 policy tamper refuses before evaluation',()=>{const a=approvalFixture().wrap();a.policyBytes=Buffer.from('{}');assert.throws(()=>verifyApproval(a),/digest/)})
test('R3 arbitrary policy with valid repository was accepted by old evaluator',()=>{const f=fixture();f.policy.files={};f.tree.tree=[];assert.deepEqual(oldEvaluate(f),[]);const a=approvalFixture().wrap();a.policyBytes=Buffer.from(JSON.stringify(f.policy));assert.throws(()=>verifyApproval(a))})
test('R3 unsigned manifest upgrade refused',()=>{const a=approvalFixture().wrap();a.manifestBytes=Buffer.from(a.manifestBytes.toString().replace('TEST-ONLY','FAKE'));assert.throws(()=>verifyApproval(a),/signature/)})
test('R3 signed but unauthorized policy version refused',()=>{const f=approvalFixture();f.m.policyVersion=2;assert.throws(()=>verifyApproval(f.wrap()),/version/)})
test('R3 controller version mismatch refused',()=>{const f=approvalFixture();f.m.controllerVersion='unreviewed';assert.throws(()=>verifyApproval(f.wrap()),/version/)})
test('R3 modified controller module refused',()=>{const a=approvalFixture().wrap();a.code['controller.mjs']=Buffer.from('changed');assert.throws(()=>verifyApproval(a),/controller identity/)})
test('R3 signed rollback below deployment minimum refused',()=>{const a=approvalFixture().wrap();a.minimum.policyVersion=2;assert.throws(()=>verifyApproval(a),/version/)})
test('R3 trustCommit field does not replace verified digest',()=>{const a=approvalFixture().wrap();a.policyBytes=Buffer.from(a.policyBytes.toString()+' ');assert.throws(()=>verifyApproval(a),/digest/)})
test('R3 arbitrary policy traversal path refused',()=>assert.throws(()=>readRootFile('/trusted','../policy.json'),/file name/))
const config={appId:99,installationId:7,repositoryId:10,accountId:20}
const permissions={contents:'read',actions:'read',pull_requests:'read',checks:'write',metadata:'read'}
function issuerFixture(){const calls=[];const app={id:99};const installation={id:7,repository_selection:'selected',app_id:99,account:{id:20},suspended_at:null,permissions:{...permissions}};const issued={token:'TEST_ONLY',permissions:{...permissions},repositories:[{id:10}],expires_at:new Date(Date.now()+1800000).toISOString()};return{calls,app,installation,issued,api:async(path,method='GET',body)=>{calls.push({path,method,body});if(path==='app')return app;if(method==='POST')return issued;return installation}}}
test('R4 validate issuer and scope before token issuance',async()=>{const f=issuerFixture();assert.equal(await issueToken(f.api,config),'TEST_ONLY');assert.equal(f.calls[0].path,'app');assert.deepEqual(f.calls[2].body.repository_ids,[10])})
for(const [name,mutate]of [['wrong App',f=>f.app.id=88],['wrong installation account',f=>f.installation.account.id=30],['extra permission',f=>f.installation.permissions.administration='write']])test(`R4 ${name} denies before mint`,async()=>{const f=issuerFixture();mutate(f);await assert.rejects(issueToken(f.api,config));assert.equal(f.calls.filter(x=>x.method==='POST').length,0)})
for(const [name,mutate]of [['overbroad token',f=>f.issued.repositories.push({id:11})],['expired token',f=>f.issued.expires_at='2020-01-01']])test(`R4 reject ${name}`,async()=>{const f=issuerFixture();mutate(f);await assert.rejects(issueToken(f.api,config))})
for(const status of [401,403,429,500])test(`R4 API ${status} fails closed`,async()=>{await assert.rejects(githubApi('TEST',async()=>({ok:false,status}))('repos/owner/repo/pulls/1'),new RegExp(String(status)))})
test('R4 network timeout refuses',async()=>{await assert.rejects(githubApi('TEST',async()=>{throw new Error('timeout')})('repos/owner/repo'),/network\/timeout/)})
test('R4 malformed JSON refuses',async()=>{await assert.rejects(githubApi('TEST',async()=>({ok:true,json:async()=>{throw new Error()}}))('repos/owner/repo'),/invalid GitHub JSON/)})
test('R4 duplicate pagination denied',async()=>{await assert.rejects(paged(async()=>({total_count:2,jobs:[{id:1}]}),'repos/owner/repo/jobs','jobs'),/duplicate/)})
test('R4 missing page denied',async()=>{await assert.rejects(paged(async()=>({total_count:1,jobs:[]}), 'repos/owner/repo/jobs','jobs'),/incomplete/)})
test('R4 changed pagination totals denied',async()=>{let i=0;await assert.rejects(paged(async()=>({total_count:++i===1?2:3,jobs:[{id:i}]}),'repos/owner/repo/jobs','jobs'),/inconsistent/)})
function publisherFixture(){const stateDirectory=mkdtempSync(join(tmpdir(),'ab-publish-'));publicationScratch.push(stateDirectory);const calls=[];const check={id:3,name:'trusted',status:'completed',app:{id:99},head_sha:sha,external_id:'receipt',conclusion:'success'};const api=async(path,method='GET',body)=>{calls.push({path,method,body});if(path.startsWith('installation/'))return{total_count:1,repositories:[{id:10}]};if(path.includes('/commits/'))return{total_count:0,check_runs:[]};if(method==='POST')return {...check,status:'in_progress',conclusion:null};return check};return{calls,check,api,args:{stateDirectory,config,repository:'owner/repo',target:sha,decision:{context:'trusted',errors:[]},externalId:'receipt',recheck:async()=>{}}}}
test('R4 wrong publication issuer never completes success',async()=>{const f=publisherFixture();f.check.app.id=88;await assert.rejects(publish(f.api,f.args),/issuer/);assert.equal(f.calls.filter(x=>x.method==='PATCH').length,0)})
test('R4 head/base change before completion leaves no green check',async()=>{const f=publisherFixture();f.args.recheck=async()=>{throw new Error('base changed')};await assert.rejects(publish(f.api,f.args),/base changed/);assert.equal(f.calls.filter(x=>x.method==='PATCH').length,0)})
test('R4 normal publication validates readback (SIMULATED)',async()=>{const f=publisherFixture();assert.equal((await publish(f.api,f.args)).app.id,99)})
test('R4 repeated matching event reuses existing receipt (SIMULATED)',async()=>{const f=publisherFixture();const api=async(p,m,b)=>p.includes('/commits/')?{total_count:1,check_runs:[f.check]}:f.api(p,m,b);await publish(api,f.args);assert.equal(f.calls.filter(x=>x.method==='POST').length,0)})
test('R4 concurrent or surviving lease refuses automatic recovery',async()=>{const dir=await mkdtemp(join(tmpdir(),'ab-trust-'));const path=join(dir,'lease');try{await withLease(path,()=>assert.rejects(withLease(path,async()=>{}),/lease/));await writeFile(path,'crash');await assert.rejects(withLease(path,async()=>{}),/lease/)}finally{await rm(dir,{recursive:true,force:true})}})

test('R4 wrong installation ID refuses before issuing token',async()=>{const f=issuerFixture();f.installation.id=8;await assert.rejects(issueToken(f.api,config));assert.equal(f.calls.filter(x=>x.method==='POST').length,0)})
test('R4 readback issuer mismatch is detected (SIMULATED)',async()=>{const f=publisherFixture();const api=async(p,m,b)=>p.endsWith('/check-runs/3')&&m===undefined?{...f.check,app:{id:88}}:f.api(p,m,b);await assert.rejects(publish(api,f.args),/readback/)})
