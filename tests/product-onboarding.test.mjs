import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createWorkbenchServer } from '../workbench/server.mjs'
import { runCli } from '../packages/cli/index.js'
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'ab-product-')),workspace=join(root,'project'),stateRoot=join(root,'state')
 await mkdir(workspace);await writeFile(join(workspace,'hello.txt'),'actual user file\r\n');await writeFile(join(workspace,'app.js'),'export function inspect(value) { return eval(value) }\n');await writeFile(join(workspace,'package.json'),'{"name":"inert","dependencies":{"lodash":"4.17.20"}}')
 t.after(()=>rm(root,{recursive:true,force:true}));const server=await createWorkbenchServer({native:{workspaceId:workspace,stateRoot}});t.after(()=>server.close())
 const session=await(await fetch(server.url+'/api/native/session')).json(),headers={'content-type':'application/json','x-armorbreak-session':session.csrf}
 const request=(path,input,extra={})=>fetch(server.url+'/api/product/'+path,{headers:{...headers,...extra},...(input===undefined?{}:{method:'POST',body:JSON.stringify(input)})})
 return {root,workspace,stateRoot,server,session,request}
}
test('first real example produces current task, evidence and downloadable report without a host/model or project writes',async t=>{
 const f=await fixture(t),before=await readFile(join(f.workspace,'hello.txt')),catalog=await(await f.request('catalog')).json()
 assert.equal(catalog.hostConnection,'NOT_CONNECTED');assert.equal(catalog.authentication,'NONE');assert.equal(catalog.actions.length,6)
 const response=await f.request('example',{});assert.equal(response.status,200);const result=await response.json()
 assert.equal(result.state,'COMPLETED');assert.ok(result.data.digests.sha256&&result.taskId&&result.evidenceIds.length&&result.reportAvailable);assert.ok(result.durationMs>=0)
 const tasks=await(await f.request('tasks')).json();assert.ok(tasks.some(t=>t.taskId===result.taskId&&t.scope==='example'&&t.state==='COMPLETED'))
 const evidence=await(await f.request('evidence?taskId='+result.taskId)).json();assert.ok(evidence.evidence.length)
 const report=await(await f.request('report?taskId='+result.taskId)).json();assert.match(report.markdown,/sha256|SHA|哈希/);assert.doesNotMatch(JSON.stringify(report),/"path":/)
 assert.match(report.markdown,/任务状态：\*\*COMPLETED\*\*/)
 assert.deepEqual(await readFile(join(f.workspace,'hello.txt')),before)
})
test('project actions run existing Core file/code/dependency analyzers with real results and persisted report',async t=>{
 const f=await fixture(t)
 const hash=await(await f.request('run',{action:'file-integrity',target:'hello.txt'})).json()
 assert.equal(hash.state,'COMPLETED');assert.equal(hash.data.digests.sha256,createHash('sha256').update('actual user file\r\n').digest('hex'))
 for(const action of ['project-review','dependency-review']){const response=await f.request('run',{action,target:'.'});assert.equal(response.status,200);const result=await response.json();assert.equal(result.state,'COMPLETED');assert.ok(result.reportAvailable&&result.evidenceIds.length)}
 const all=await(await f.request('tasks')).json();assert.equal(all.filter(t=>t.scope==='workspace').length,3)
})
test('bad/missing targets can be corrected and retried; scope, token, report and privilege injection refuse',async t=>{
 const f=await fixture(t)
 // Missing targets may be rejected during canonical scope validation (notably
 // Windows TEMP aliases). Also exercise a real analyzer failure on an existing
 // in-scope directory, so FAILED settlement is required on every platform.
 for(const body of [{action:'file-integrity',target:'missing'},{action:'file-integrity',target:'.'},{action:'file-integrity',target:'../SECRET_OUTSIDE.txt'},{action:'file-integrity',target:'hello.txt',principal:'admin'},{action:'plugin.activate',target:'.'},{action:'project-review',target:'.',options:{approve:true}}]){
  const response=await f.request('run',body);assert.equal(response.status,400);assert.doesNotMatch(await response.text(),/SECRET_OUTSIDE|ab-product-|stack|at Engine/)
 }
 assert.equal((await f.request('example',{path:'hello.txt'})).status,400)
 assert.equal((await f.request('catalog',undefined,{'x-armorbreak-session':'a'.repeat(64)})).status,403)
 assert.equal((await f.request('catalog',undefined,{origin:'https://attacker.invalid'})).status,403)
 for(const taskId of ['task_nonexistent','../private','task_x/../../secret'])assert.equal((await f.request('report?taskId='+encodeURIComponent(taskId))).status,400)
 assert.equal((await f.request('run',{action:'file-integrity',target:'hello.txt'})).status,200)
 const tasks=await(await f.request('tasks')).json()
 assert.ok(tasks.some(t=>t.state==='FAILED'));assert.ok(tasks.every(t=>!['EXECUTING','SCOPE_VALIDATION'].includes(t.state)))
})
test('canonical target scope refuses external directory links',async t=>{
 const f=await fixture(t),outside=join(f.root,'outside');await mkdir(outside);await writeFile(join(outside,'secret.txt'),'not authorized')
 await symlink(outside,join(f.workspace,'alias'),process.platform==='win32'?'junction':'dir')
 assert.equal((await f.request('run',{action:'file-integrity',target:'alias/secret.txt'})).status,400)
})
test('explicit workspace spelling remains usable through native HTTP on case-normalizing filesystems',async t=>{
 const f=await fixture(t),workspaceId=process.platform==='win32'?f.workspace.toLowerCase():f.workspace
 const server=await createWorkbenchServer({native:{workspaceId,stateRoot:join(f.root,'spelling-state')}});t.after(()=>server.close())
 const session=await(await fetch(server.url+'/api/native/session')).json()
 const response=await fetch(server.url+'/api/native/run',{method:'POST',headers:{'content-type':'application/json','x-armorbreak-session':session.csrf},body:JSON.stringify({capability:'configuration.preview',target:join(workspaceId,'overlay.json')})})
 // A missing file should be denied, then the same explicit spelling should work once valid.
 assert.equal(response.status,400)
 await writeFile(join(f.workspace,'overlay.json'),JSON.stringify({schema:'armorbreak.config-overlay/v1',base:{enabled:false},overlays:[]}))
 const valid=await fetch(server.url+'/api/native/run',{method:'POST',headers:{'content-type':'application/json','x-armorbreak-session':session.csrf},body:JSON.stringify({capability:'configuration.preview',target:join(workspaceId,'overlay.json')})})
 assert.equal(valid.status,200)
})
test('start creates the real workbench without required environment variables and returns a closable service',async t=>{
 const root=await mkdtemp(join(tmpdir(),'ab-start-'));t.after(()=>rm(root,{recursive:true,force:true}))
 const write=process.stdout.write;let output='';process.stdout.write=function(chunk){output+=chunk;return true}
 let server
 try{server=await runCli(['start','--workspace',root,'--state-root',join(root,'state'),'--no-open','--json'],{env:{}})}finally{process.stdout.write=write}
 t.after(()=>server.close());const value=JSON.parse(output)
 assert.equal(value.authentication,'NONE');assert.equal((await fetch(value.url)).status,200)
 await assert.rejects(()=>runCli(['start','--port','--no-open'],{env:{}}),/port/)
 await assert.rejects(()=>runCli(['start','--approve','true'],{env:{}}),/accepts/)
})
