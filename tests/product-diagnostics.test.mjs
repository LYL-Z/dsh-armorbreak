import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, rm, realpath } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createEngine } from '../packages/engine-node/index.js'
import { createProductApi } from '../workbench/product.mjs'
import { createWorkbenchServer } from '../workbench/server.mjs'

async function fixture(t) {
  const root=await realpath(await mkdtemp(join(tmpdir(),'ab-product-diagnostics-')))
  const workspace=join(root,'workspace'), resources=join(workspace,'resources'), plugin=join(workspace,'plugin')
  const hostDir=join(resources,'app','dsh','node_modules','@deepseek-ai','dsh-desktop-host')
  await mkdir(hostDir,{recursive:true});await mkdir(plugin)
  t.after(()=>rm(root,{recursive:true,force:true}))
  const hostFile=join(hostDir,'package.json'),pluginFile=join(plugin,'inert.txt'),overlay=join(workspace,'overlay.json')
  await writeFile(hostFile,JSON.stringify({name:'@deepseek-ai/dsh-desktop-host',version:'1.2.3',secret:'SYNTHETIC_HOST_SECRET'}))
  await writeFile(pluginFile,'inert sample\r\n')
  await writeFile(join(plugin,'armorbreak-plugin.json'),JSON.stringify({schema:'armorbreak.plugin-catalog/v1',plugins:[{id:'sample',version:'1.0.0',source:{repository:'https://github.com/example/inert',commit:'a'.repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux','darwin'],channel:'stable',enabled:false,files:[{path:'inert.txt',sha256:createHash('sha256').update('inert sample\r\n').digest('hex')}]}]}))
  await writeFile(overlay,JSON.stringify({schema:'armorbreak.config-overlay/v1',base:{apiPin:'SYNTHETIC_CONFIG_SECRET'},overlays:[]}))
  const principal={id:'product-diagnostics',kind:'local-user',workspaces:[workspace]}
  return {root,workspace,resources,plugin,hostFile,pluginFile,overlay,principal}
}
async function assertDiagnostics(run,f) {
  const original=await Promise.all([f.hostFile,f.pluginFile,f.overlay].map(p=>readFile(p)))
  const health=await run({action:'host-health',target:'resources'})
  assert.equal(health.state,'COMPLETED');assert.equal(health.data.observation,'DETECTED_ON_DISK');assert.equal(health.data.runtime,'UNKNOWN');assert.equal(health.data.identity.version,'1.2.3')
  assert.doesNotMatch(JSON.stringify(health),/SYNTHETIC_HOST_SECRET/)
  const plugin=await run({action:'plugin-closure',target:'plugin'})
  assert.equal(plugin.state,'COMPLETED');assert.equal(plugin.data.verificationStatus,'LOCAL_PACKAGE_CLOSURE_VERIFIED');assert.equal(plugin.data.packageClosureVerified,true)
  assert.equal(plugin.data.plugins[0].sourceAuthenticated,false);assert.equal(plugin.data.plugins[0].activationAuthorized,false);assert.equal(plugin.data.installationPerformed,false)
  const config=await run({action:'configuration-preview',target:'overlay.json'})
  assert.equal(config.state,'COMPLETED');assert.equal(config.data.applied,false);assert.equal(config.data.status,'PREVIEW_READY');assert.doesNotMatch(JSON.stringify(config),/apiPin|SYNTHETIC_CONFIG_SECRET/)
  for(const r of [health,plugin,config]) assert.ok(r.evidenceIds.length&&(r.reportAvailable===true||Boolean(r.reportPath)))
  assert.deepEqual(await Promise.all([f.hostFile,f.pluginFile,f.overlay].map(p=>readFile(p))),original)
  return [health,plugin,config]
}
test('direct Product API routes three diagnostic actions through real Core without execution or host changes',async t=>{
  const f=await fixture(t),engine=await createEngine({stateRoot:join(f.root,'state'),principals:[f.principal]})
  t.after(()=>engine.close())
  const ctx={principal:f.principal,workspaceId:f.workspace,requestId:'test',traceId:'test'}
  const product=createProductApi({engine,ctx}),catalog=await product.catalog()
  for(const id of ['host-health','plugin-closure','configuration-preview'])assert.ok(catalog.actions.some(a=>a.id===id&&a.permission==='L0_READ_ONLY'&&a.explicitTarget&&!a.runOptions))
  assert.equal(catalog.hostConnection,'NOT_CONNECTED')
  const results=await assertDiagnostics(input=>product.run(input),f)
  for(const result of results)assert.ok((await product.report(result.taskId)).markdown.length)
  await assert.rejects(()=>product.run({action:'plugin-closure',target:'plugin',options:{closure:false}}),/PRODUCT_INVALID_REQUEST/)
  await assert.rejects(()=>product.run({action:'host-health',target:'..'}))
  await writeFile(join(f.plugin,'extra.txt'),'undeclared')
  await assert.rejects(()=>product.run({action:'plugin-closure',target:'plugin'}),/undeclared/i)
})
test('HTTP Workbench diagnostics produce task evidence and report; caller cannot change verification options',async t=>{
  const f=await fixture(t),server=await createWorkbenchServer({native:{workspaceId:f.workspace,stateRoot:join(f.root,'http-state')}});t.after(()=>server.close())
  const session=await(await fetch(server.url+'/api/native/session')).json(),headers={'content-type':'application/json','x-armorbreak-session':session.csrf}
  const request=(path,input)=>fetch(server.url+'/api/product/'+path,{headers,...(input===undefined?{}:{method:'POST',body:JSON.stringify(input)})})
  const catalog=await(await request('catalog')).json();assert.equal(catalog.hostConnection,'NOT_CONNECTED')
  for(const id of ['host-health','plugin-closure','configuration-preview'])assert.ok(catalog.actions.some(a=>a.id===id&&a.permission==='L0_READ_ONLY'))
  const results=await assertDiagnostics(async input=>{const r=await request('run',input);assert.equal(r.status,200);return r.json()},f)
  for(const result of results){assert.equal(result.reportAvailable,true);const report=await request('report?taskId='+encodeURIComponent(result.taskId));assert.equal(report.status,200);assert.ok((await report.json()).markdown.length)}
  assert.equal((await request('run',{action:'plugin-closure',target:'plugin',options:{closure:false}})).status,400)
  assert.equal((await request('run',{action:'host-health',target:'..'})).status,400)
  await writeFile(join(f.plugin,'extra.txt'),'undeclared')
  const extra=await request('run',{action:'plugin-closure',target:'plugin'})
  assert.equal(extra.status,400)
  assert.match((await extra.json()).detail,/缺少清单声明的文件，或包含额外文件/)
  await rm(join(f.plugin,'extra.txt'))
  await writeFile(f.pluginFile,'different file bytes')
  const drift=await request('run',{action:'plugin-closure',target:'plugin'})
  assert.equal(drift.status,400)
  const problem=await drift.json()
  assert.match(problem.detail,/摘要不一致/)
  assert.doesNotMatch(JSON.stringify(problem),/inert\.txt|different file bytes|[a-f0-9]{64}/)
  await writeFile(f.pluginFile,'inert sample\r\n')
  assert.equal((await request('run',{action:'plugin-closure',target:'plugin'})).status,200)
})
