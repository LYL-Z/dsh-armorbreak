import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
async function fixture(t,failures=0){
 const root=await mkdtemp(join(tmpdir(),'ab-report-final-'));t.after(()=>rm(root,{recursive:true,force:true}));const workspace=join(root,'workspace');await mkdir(workspace)
 const runtime=new ArmorBreakRuntime({stateRoot:join(root,'state')});await runtime.init();const store=runtime.workspace(workspace).taskStore
 const target=join(workspace,'input.txt');await writeFile(target,'known bytes')
 const steps=[{id:'good',capabilityId:'forensics.hash'},...Array.from({length:failures},(_,i)=>({id:'bad'+i,capabilityId:'forensics.hash'}))]
 const task=await store.create({title:'report state regression',targetPath:target,steps})
 await runtime.runner.runCapability({task,capabilityId:'forensics.hash',targetPath:target,stepId:'good'})
 for(let i=0;i<failures;i++)await assert.rejects(()=>runtime.runner.runCapability({task,capabilityId:'forensics.hash',targetPath:join(workspace,'missing.txt'),stepId:'bad'+i}))
 return {root,runtime,store,task}
}
for(const failures of [0,1])test(`finalized report and persisted task agree; failed steps=${failures}`,async t=>{
 const {runtime,store,task}=await fixture(t,failures),observed=[],save=store.save.bind(store)
 store.save=async value=>{const r=await save(value);const persisted=await store.get(value.id);observed.push({state:persisted.state,report:persisted.report});return r}
 const done=await runtime.runner.finalizeTask(task),expected=failures?'PARTIAL_SUCCESS':'COMPLETED'
 assert.equal(done.state,expected);assert.equal((await store.get(task.id)).state,expected)
 const report=await readFile(done.report.path,'utf8');assert.ok(report.includes('任务状态：**'+expected+'**'))
 assert.ok(observed.every(s=>!s.report||['COMPLETED','PARTIAL_SUCCESS'].includes(s.state)))
 assert.match(report,/生成前已经记录/)
})
test('report write failure yields partial success without publishing a completed report reference',async t=>{
 const {runtime,store,task}=await fixture(t);await writeFile(join(store.taskDir(task.id),'reports'),'obstruct report directory')
 const done=await runtime.runner.finalizeTask(task);assert.equal(done.state,'PARTIAL_SUCCESS');assert.equal(Boolean((await store.get(task.id)).report),false)
 assert.ok(done.notes.some(n=>n.note.startsWith('report generation failed:')))
})
