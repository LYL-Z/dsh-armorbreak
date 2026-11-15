/** Presentation over the same Core. No independent scheduler, approval or host writer. */
import { resolve, basename } from 'node:path'
import { randomUUID } from 'node:crypto'
const ACTIONS=Object.freeze([
 {id:'file-integrity',capability:'forensics.hash',title:'检查文件完整性',description:'计算文件摘要，检查文件大小与类型，生成可下载的报告。',targetKind:'file',placeholder:'例如：downloads/package.tgz'},
 {id:'project-review',capability:'sast.scan',title:'检查项目代码',description:'离线查找危险代码模式。结果是排查线索，需要结合代码确认。',targetKind:'directory',placeholder:'例如：src 或 .'},
 {id:'dependency-review',capability:'sast.deps',title:'检查项目依赖',description:'读取项目依赖声明，检查本地规则支持的问题；不连接外部漏洞库。',targetKind:'directory',placeholder:'例如：. 或 my-project'},
])
export function createProductApi({engine,ctx,exampleCtx,exampleFile}){
 const contexts=()=>[{ctx,scope:'workspace'},...(exampleCtx?[{ctx:exampleCtx,scope:'example'}]:[])]
 async function owned(taskId){
  if(typeof taskId!=='string'||!/^task_[a-zA-Z0-9_:-]{1,150}$/.test(taskId))throw new Error('PRODUCT_TASK_NOT_AVAILABLE')
  for(const entry of contexts())try{return {...entry,task:await engine.getTask(entry.ctx,taskId)}}catch{}
  throw new Error('PRODUCT_TASK_NOT_AVAILABLE')
 }
 return Object.freeze({
  async catalog(){
   const caps=await engine.capabilities(ctx)
   return {schema:'armorbreak.product-catalog/v1',workspaceName:basename(ctx.workspaceId),mode:'OFFLINE_READ_ONLY',hostConnection:'NOT_CONNECTED',authentication:'NONE',
    actions:ACTIONS.filter(a=>caps.some(c=>c.id===a.capability&&c.riskLevel==='L0')).map(a=>({...a,permission:'L0_READ_ONLY'})),exampleAvailable:Boolean(exampleCtx),
    unavailable:[{id:'host-install',title:'安装到 DSH 宿主',reason:'真实宿主适配与可信身份尚未验收'}, {id:'plugin-activation',title:'启用宿主插件',reason:'隔离文件事务不等于真实加载'}, {id:'configuration-write',title:'应用宿主配置',reason:'本地网页不签发写入批准'}]}
  },
  async run(input){
   if(!input||Array.isArray(input)||Object.keys(input).some(k=>!['action','target'].includes(k))||typeof input.target!=='string'||!input.target.trim()||input.target.length>2048)throw new Error('PRODUCT_INVALID_REQUEST')
   const action=ACTIONS.find(a=>a.id===input.action);if(!action)throw new Error('PRODUCT_ACTION_UNAVAILABLE')
   const target=resolve(ctx.workspaceId,input.target)
   // Core performs lexical AND canonical workspace/identity checks; no HTTP principal is accepted.
   return engine.analyze({...ctx,requestId:randomUUID(),traceId:randomUUID()},{capability:action.capability,target})
  },
  async example(input){
   if(!exampleCtx||!input||Array.isArray(input)||Object.keys(input).length)throw new Error('PRODUCT_EXAMPLE_UNAVAILABLE')
   return engine.analyze({...exampleCtx,requestId:randomUUID(),traceId:randomUUID()},{capability:'forensics.hash',target:exampleFile})
  },
  async tasks(){
   const rows=[]
   for(const entry of contexts())for(const task of await engine.listTasks(entry.ctx))rows.push({taskId:task.id,state:task.state,title:task.title,capability:task.steps?.[0]?.capabilityId??null,createdAt:task.createdAt,scope:entry.scope,reportAvailable:Boolean(task.report?.path)})
   return rows.sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,20)
  },
  async report(taskId){const entry=await owned(taskId),report=await engine.getReport(entry.ctx,taskId);return {taskId,sha256:report.sha256,markdown:report.markdown}},
  async evidence(taskId){const entry=await owned(taskId);return engine.getEvidence(entry.ctx,taskId)},
 })
}
