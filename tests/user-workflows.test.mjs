import test from 'node:test'
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtemp,mkdir,writeFile,readFile,rm,symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { createEngine } from '../packages/engine-node/index.js'
import { createMcpServer } from '../packages/mcp-server/index.js'
import { createWorkbenchServer } from '../workbench/server.mjs'
import { getWorkflow } from '../lib/core/workflows.js'

function inertPcap(){
 // One generated DNS query between documentation-only addresses; no sockets.
 const dns=Buffer.from('123401000001000000000000076578616d706c6507696e76616c69640000010001','hex'),udp=Buffer.alloc(8)
 udp.writeUInt16BE(53000);udp.writeUInt16BE(53,2);udp.writeUInt16BE(8+dns.length,4)
 const ip=Buffer.alloc(20);ip[0]=0x45;ip.writeUInt16BE(28+dns.length,2);ip[8]=64;ip[9]=17;Buffer.from([192,0,2,1,192,0,2,53]).copy(ip,12)
 const eth=Buffer.alloc(14);eth.writeUInt16BE(0x0800,12);const frame=Buffer.concat([eth,ip,udp,dns])
 const header=Buffer.alloc(24);header.writeUInt32LE(0xa1b2c3d4);header.writeUInt16LE(2,4);header.writeUInt16LE(4,6);header.writeUInt32LE(65535,16);header.writeUInt32LE(1,20)
 const record=Buffer.alloc(16);record.writeUInt32LE(1700000000);record.writeUInt32LE(frame.length,8);record.writeUInt32LE(frame.length,12)
 return Buffer.concat([header,record,frame])
}
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'ab-user-workflows-')),workspace=join(root,'workspace'),stateRoot=join(root,'state');await mkdir(workspace)
 t.after(()=>rm(root,{recursive:true,force:true}))
 await writeFile(join(workspace,'capture.pcap'),inertPcap());await writeFile(join(workspace,'hello.txt'),'inert forensic input example.invalid\n');await writeFile(join(workspace,'app.js'),'export const inspect = value => eval(value)\n')
 await writeFile(join(workspace,'package.json'),' {"name":"inert-project","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}')
 const principal={id:'workflow-test',kind:'local-user',workspaces:[workspace]},engine=await createEngine({stateRoot,principals:[principal]});t.after(()=>engine.close())
 const ctx=()=>({principal:{id:principal.id,kind:principal.kind,sessionId:'session-a'},workspaceId:workspace,requestId:randomUUID(),traceId:randomUUID()})
 return {root,workspace,stateRoot,principal,engine,ctx}
}
test('one Core workflow produces seven real PCAP analyses, traceable evidence and a terminal combined report',async t=>{
 const f=await fixture(t),target=join(f.workspace,'capture.pcap'),before=await readFile(target),context=f.ctx()
 const result=await f.engine.startWorkflow(context,{workflow:'PCAPInvestigation',target})
 assert.equal(result.state,'COMPLETED');assert.equal(result.data.steps.length,7);assert.ok(result.data.steps.every(s=>s.status==='DONE'));assert.ok(result.evidenceIds.length>=7)
 const task=await f.engine.getTask(context,result.taskId);assert.deepEqual(task.steps.map(s=>s.capabilityId),getWorkflow('PCAPInvestigation').steps.map(s=>s.capabilityId))
 const report=await f.engine.getReport(context,result.taskId);assert.match(report.markdown,/任务状态：\*\*COMPLETED\*\*/);assert.match(report.markdown,/example.invalid/)
 assert.deepEqual(await readFile(target),before)
 await assert.rejects(()=>f.engine.getReport({...context,principal:{...context.principal,sessionId:'session-b'}},result.taskId),/session/)
 const replay=await f.engine.startWorkflow(context,{workflow:'PCAPInvestigation',target});assert.equal(replay.taskId,result.taskId);assert.equal(replay.evidenceIds.length,result.evidenceIds.length)
})
test('project and file reviews use the registered Core steps without custom plans or host writes',async t=>{
 const f=await fixture(t)
 for(const [workflow,target] of [['WebCodeSecurityReview',f.workspace],['ForensicFileReview',join(f.workspace,'hello.txt')]]){
  const result=await f.engine.startWorkflow(f.ctx(),{workflow,target});assert.equal(result.state,'COMPLETED');assert.ok(result.data.steps.every(s=>s.status==='DONE'));assert.ok(result.reportPath)
 }
})
test('a workflow whose capability is classified L1, plan injection, empty targets and directory escapes refuse',async t=>{
 const f=await fixture(t),get=f.engine.runtime.registry.get.bind(f.engine.runtime.registry)
 // Current shipped workflows are L0; simulate a trusted registry reclassification
 // rather than inventing a nonexistent production L1 workflow.
 f.engine.runtime.registry.get=id=>id==='network.pcap_overview'?{...get(id),riskLevel:'L1'}:get(id)
 await assert.rejects(()=>f.engine.startWorkflow(f.ctx(),{workflow:'PCAPInvestigation',target:join(f.workspace,'capture.pcap')}),/L0/)
 f.engine.runtime.registry.get=get
 for(const input of [{workflow:'PCAPInvestigation',target:''},{workflow:'PCAPInvestigation',target:join(f.root,'outside.pcap')},{workflow:'not-registered',target:f.workspace},{workflow:'PCAPInvestigation',target:f.workspace,steps:[]},{workflow:'PCAPInvestigation',target:f.workspace,approval:true}])await assert.rejects(()=>f.engine.startWorkflow(f.ctx(),input))
 const outside=join(f.root,'outside');await mkdir(outside);await writeFile(join(outside,'capture.pcap'),inertPcap());await symlink(outside,join(f.workspace,'alias'),process.platform==='win32'?'junction':'dir')
 await assert.rejects(()=>f.engine.startWorkflow(f.ctx(),{workflow:'PCAPInvestigation',target:join(f.workspace,'alias/capture.pcap')}))
})
test('malformed capture settles as failed with actual step statuses, never a fabricated successful report',async t=>{
 const f=await fixture(t),target=join(f.workspace,'bad.pcap');await writeFile(target,'not a capture')
 const result=await f.engine.startWorkflow(f.ctx(),{workflow:'PCAPInvestigation',target});assert.equal(result.state,'FAILED')
 assert.ok(result.data.steps.some(s=>s.status==='FAILED'));assert.ok(result.data.steps.every(s=>!['PENDING','RUNNING'].includes(s.status)))
 const report=await f.engine.getReport(f.ctx(),result.taskId);assert.match(report.markdown,/任务状态：\*\*FAILED\*\*/)
})
test('CLI, MCP and Workbench invoke the same workflow entry and expose results and reports',async t=>{
 const f=await fixture(t),target=join(f.workspace,'capture.pcap'),cli=fileURLToPath(new URL('../packages/cli/index.js',import.meta.url))
 const output=execFileSync(process.execPath,[cli,'workflow','start','--workflow','PCAPInvestigation','--target',target,'--json'],{encoding:'utf8',timeout:30000,env:{...process.env,ARMORBREAK_STATE_ROOT:join(f.root,'cli-state'),ARMORBREAK_WORKSPACE:f.workspace}})
 assert.equal(JSON.parse(output).data.steps.length,7)
 const mcp=await createMcpServer({stateRoot:join(f.root,'mcp-state'),workspaceId:f.workspace,principal:f.principal});t.after(()=>mcp.engine.close())
 await mcp.server.dispatch({jsonrpc:'2.0',id:1,method:'initialize'})
 const call=await mcp.server.dispatch({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'armorbreak_workflow',arguments:{action:'start',workflow:'PCAPInvestigation',target}}});assert.equal(call.result.isError,false);assert.equal(JSON.parse(call.result.content[0].text).state,'COMPLETED')
 const server=await createWorkbenchServer({native:{workspaceId:f.workspace,stateRoot:join(f.root,'http-state')}});t.after(()=>server.close())
 const session=await(await fetch(server.url+'/api/native/session')).json(),headers={'content-type':'application/json','x-armorbreak-session':session.csrf}
 const response=await fetch(server.url+'/api/product/run',{method:'POST',headers,body:JSON.stringify({action:'capture-investigation',target:'capture.pcap'})});assert.equal(response.status,200);const result=await response.json();assert.equal(result.state,'COMPLETED');assert.equal(result.data.steps.length,7);assert.ok(result.reportAvailable)
 const report=await(await fetch(server.url+'/api/product/report?taskId='+result.taskId,{headers})).json();assert.match(report.markdown,/example.invalid/)
})
