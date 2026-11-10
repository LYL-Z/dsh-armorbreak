import test from 'node:test'
import assert from 'node:assert/strict'
import { evaluate, expectedJobs } from '../tools/trusted-gate/evaluate.mjs'
const sha = 'a'.repeat(40)
function fixture() {
 const files = {'.github/workflows/development-gate.yml':'100644:worker', 'tests/security.test.mjs':'100644:test', 'package.json':'100644:manifest', 'scripts/validate-development-gate.mjs':'100644:validator', 'tools/trusted-gate/controller.mjs':'100644:controller'}
 const steps=['Full test suite','TypeScript contract check','Assert exact candidate SHA','Static L0 network-free gate','Pull a digest-pinned image','Verify hardened container execution path','Require executed successful dependencies on this exact candidate'].map(name=>({name,status:'completed',conclusion:'success'}))
 return {policy:{repository:'owner/repo',workflowId:10,files},candidate:{repository:'owner/repo',sha},run:{id:20,workflow_id:10,head_sha:sha,repository:{full_name:'owner/repo'},event:'pull_request',path:'.github/workflows/development-gate.yml',status:'completed',conclusion:'success'},jobs:expectedJobs.map(name=>({name,head_sha:sha,run_id:20,status:'completed',conclusion:'success',steps:structuredClone(steps)})),tree:{truncated:false,tree:Object.entries(files).map(([path,v])=>({path,type:'blob',mode:v.split(':')[0],sha:v.split(':')[1]}))}}
}
test('normal candidate accepted by frozen external policy',()=>assert.deepEqual(evaluate(fixture()),[]))
for(const path of ['.github/workflows/development-gate.yml','tests/security.test.mjs','package.json','scripts/validate-development-gate.mjs','tools/trusted-gate/controller.mjs']) test(`candidate cannot weaken ${path}`,()=>{const f=fixture();f.tree.tree.find(x=>x.path===path).sha='changed';assert.ok(evaluate(f).includes(`protected control changed: ${path}`))})
test('new spoofed workflow denied even if all jobs claim success',()=>{const f=fixture();f.tree.tree.push({path:'.github/workflows/spoof.yml',type:'blob',mode:'100644',sha:'evil'});assert.ok(evaluate(f).some(x=>x.includes('spoof.yml')))})
for(const conclusion of ['failure','skipped','cancelled','timed_out','neutral'])test(`API dependency ${conclusion} denied`,()=>{const f=fixture();f.jobs[0].conclusion=conclusion;assert.ok(evaluate(f).some(x=>x.includes('job failed')))})
test('old SHA rejected',()=>{const f=fixture();f.run.head_sha='b'.repeat(40);assert.ok(evaluate(f).includes('untrusted or unsuccessful workflow run'))})
test('replaced test step cannot pass',()=>{const f=fixture();f.jobs[0].steps=f.jobs[0].steps.filter(x=>x.name!=='Full test suite');assert.ok(evaluate(f).some(x=>x.includes('Full test suite')))})
test('duplicate successful jobs cannot replace matrix member',()=>{const f=fixture();f.jobs[1]=structuredClone(f.jobs[0]);assert.ok(evaluate(f).includes('job set'))})
test('truncated source tree denied',()=>{const f=fixture();f.tree.truncated=true;assert.deepEqual(evaluate(f),['incomplete candidate tree'])})
test('ordinary product source change allowed',()=>{const f=fixture();f.tree.tree.push({path:'lib/diagnostic.js',type:'blob',mode:'100644',sha:'new'});assert.deepEqual(evaluate(f),[])})

test('ordinary integration documentation change allowed',()=>{const f=fixture();f.tree.tree.push({path:'docs/integrations/read-only.md',type:'blob',mode:'100644',sha:'doc'});assert.deepEqual(evaluate(f),[])})
