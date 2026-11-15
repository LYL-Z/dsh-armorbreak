import test from 'node:test'
import assert from 'node:assert/strict'
import { RuntimeObservation } from '../packages/core/src/runtimeObservation.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
import { createWorkbenchServer } from '../workbench/server.mjs'
import { mkdtemp,rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

test('self-process facts and adapter generations are independent from disk claims and never authenticate a client',()=>{
 const observation=new RuntimeObservation(),snapshot=observation.snapshot()
 assert.equal(snapshot.process.pid,process.pid);assert.equal(snapshot.process.node,process.version)
 assert.equal(snapshot.externalHostIdentity,'NOT_AUTHENTICATED');assert.equal(snapshot.osClientAuthentication,false)
 assert.equal(snapshot.dshFamily,'UNKNOWN');assert.equal(snapshot.dshVersion,'UNKNOWN');assert.deepEqual(snapshot.adapters,[])
 const old=observation.mount('DSH_TOOLS'),current=observation.mount('DSH_TOOLS');old.dispose();old.initialized();old.call(true)
 current.initialized();current.call(true);const ready=observation.snapshot();assert.equal(ready.adapters.length,1);assert.equal(ready.adapters[0].successfulCalls,1)
 ready.adapters[0].state='FORGED';assert.equal(observation.snapshot().adapters[0].state,'INITIALIZED')
 old.dispose();assert.equal(observation.snapshot().adapters.length,1);current.dispose();assert.deepEqual(observation.snapshot().adapters,[])
 assert.throws(()=>observation.mount('FORGED_AUTHENTICATED_HOST'),/ADAPTER_KIND/)
 assert.doesNotMatch(JSON.stringify(snapshot),/execPath|argv|HOME|PRIVATE_KEY|credential|commandLine/)
})
test('separate actual child processes have distinct instance identities and observed PIDs',()=>{
 const url=new URL('../packages/core/src/runtimeObservation.js',import.meta.url).href
 const run=()=>{const child=spawnSync(process.execPath,['--input-type=module','-e',`import {RuntimeObservation} from ${JSON.stringify(url)};console.log(JSON.stringify(new RuntimeObservation().snapshot()))`],{encoding:'utf8',timeout:10000});assert.equal(child.status,0,child.stderr);return {pid:child.pid,snapshot:JSON.parse(child.stdout)}}
 const a=run(),b=run();assert.equal(a.snapshot.process.pid,a.pid);assert.equal(b.snapshot.process.pid,b.pid)
 assert.notEqual(a.snapshot.process.instanceId,b.snapshot.process.instanceId);assert.notEqual(a.snapshot.process.instanceId,new RuntimeObservation().snapshot().process.instanceId)
})
test('MCP registration, handshake, successful and failed calls, and connection cleanup follow real adapter state',async t=>{
 const root=await mkdtemp(join(tmpdir(),'ab-observation-'));t.after(()=>rm(root,{recursive:true,force:true}))
 const options={stateRoot:join(root,'state'),workspaceId:root,principal:{id:'observer-test',kind:'local-user',workspaces:[root]}}
 const a=await createMcpServer(options),b=await createMcpServer(options);t.after(()=>a.engine.close());t.after(()=>b.engine.close())
 assert.equal(a.engine.runtime,b.engine.runtime);assert.equal(a.engine.runtime.runtimeObservation.snapshot().adapters.length,2)
 await a.server.dispatch({jsonrpc:'2.0',id:1,method:'initialize',params:{clientInfo:{name:'DSH_OFFICIAL_IDENTITY_CLAIM'}}})
 const response=await a.server.dispatch({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'armorbreak_health',arguments:{}}})
 const health=JSON.parse(response.result.content[0].text);assert.ok(health.runtimeObservation.adapters.some(x=>x.state==='INITIALIZED'))
 assert.equal(health.runtimeObservation.externalHostIdentity,'NOT_AUTHENTICATED');assert.doesNotMatch(JSON.stringify(health.runtimeObservation),/DSH_OFFICIAL_IDENTITY_CLAIM/)
 const rejected=await a.server.dispatch({jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'armorbreak_analyze',arguments:{capability:'forensics.hash',target:join(root,'missing')}}})
 assert.equal(rejected.result.isError,true)
 const counted=a.engine.runtime.runtimeObservation.snapshot().adapters.find(x=>x.state==='INITIALIZED');assert.equal(counted.successfulCalls,1);assert.equal(counted.failedCalls,1)
 await a.engine.close();assert.equal(b.engine.runtime.runtimeObservation.snapshot().adapters.length,1)
 a.server.runtimeLease?.initialized();assert.equal(b.engine.runtime.runtimeObservation.snapshot().adapters[0].state,'REGISTERED')
})
test('Workbench reports an actual local listener and real task calls without claiming DSH connection',async t=>{
 const root=await mkdtemp(join(tmpdir(),'ab-observation-http-'));t.after(()=>rm(root,{recursive:true,force:true}))
 const server=await createWorkbenchServer({native:{workspaceId:root,stateRoot:join(root,'state')}});t.after(()=>server.close())
 const session=await(await fetch(server.url+'/api/native/session')).json(),headers={'x-armorbreak-session':session.csrf,'content-type':'application/json'}
 const catalog=async()=>await(await fetch(server.url+'/api/product/catalog',{headers})).json()
 const first=await catalog();assert.equal(first.hostConnection,'NOT_CONNECTED');assert.equal(first.authentication,'NONE')
 assert.ok(first.runtimeObservation.adapters.some(x=>x.kind==='WORKBENCH_HTTP'&&x.state==='INITIALIZED'))
 assert.equal((await fetch(server.url+'/api/product/example',{method:'POST',headers,body:'{}'})).status,200)
 assert.equal((await catalog()).runtimeObservation.adapters.find(x=>x.kind==='WORKBENCH_HTTP').successfulCalls,1)
})
