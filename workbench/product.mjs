/** Presentation over the same Core. No independent scheduler, approval or host writer. */
import { resolve, basename } from 'node:path'
import { randomUUID } from 'node:crypto'
import { PRODUCT_VERSION } from '../lib/core/productVersion.js'
import { getWorkflow } from '../lib/core/workflows.js'
const ACTIONS=Object.freeze([
 {id:'file-integrity',capability:'forensics.hash',title:'检查文件完整性',description:'计算文件摘要，检查文件大小与类型，生成可下载的报告。',targetKind:'file',placeholder:'例如：downloads/package.tgz'},
 {id:'project-review',capability:'sast.scan',title:'检查项目代码',description:'离线查找危险代码模式。结果是排查线索，需要结合代码确认。',targetKind:'directory',placeholder:'例如：src 或 .'},
 {id:'dependency-review',capability:'sast.deps',title:'检查项目依赖',description:'读取项目依赖声明，检查本地规则支持的问题；不连接外部漏洞库。',targetKind:'directory',placeholder:'例如：. 或 my-project'},
 {id:'project-audit',workflow:'WebCodeSecurityReview',title:'项目综合审查',description:'一次运行代码、密钥线索、依赖和 SBOM 检查，形成同一份证据报告。所有分析均在本地完成。',targetKind:'directory',placeholder:'例如：my-project'},
 {id:'capture-investigation',workflow:'PCAPInvestigation',title:'分析离线抓包',description:'对已有 PCAP/PCAPNG 运行会话、DNS、TLS、HTTP、指标和异常分析。不抓取实时流量、不连接目标。',targetKind:'file',placeholder:'例如：capture.pcap'},
 {id:'file-review',workflow:'ForensicFileReview',title:'文件综合取证',description:'汇总类型、哈希、元数据、时间线、指标和规则线索，不运行文件，也不把线索当成已验证漏洞。',targetKind:'file',placeholder:'例如：sample.bin'},
 {id:'host-health',capability:'host.health',title:'检查 DSH 安装目录',description:'选择当前工作区内的 Desktop Resources 目录，只读识别磁盘包与版本，不代表宿主或模型已连接。',targetKind:'directory',targetLabel:'Resources 目录',explicitTarget:true,placeholder:'例如：DeepSeek Harness/resources'},
 {id:'plugin-closure',capability:'plugin.verify',title:'核对插件完整包',description:'选择含 armorbreak-plugin.json 的目录，校验声明的全部文件及额外文件；不安装、启用或认证来源。',targetKind:'directory',targetLabel:'插件包目录',explicitTarget:true,placeholder:'例如：my-plugin',runOptions:Object.freeze({closure:true})},
 {id:'configuration-preview',capability:'configuration.preview',title:'预览配置变更',description:'读取 ArmorBreak JSON 配置层叠请求，汇总变更和冲突，不展示配置值、不写入宿主。',targetKind:'file',targetLabel:'配置请求文件',explicitTarget:true,placeholder:'例如：overlay.json'},
 {id:'backup-usage',capability:'maintenance.backup_usage',title:'查看备份占用',description:'统计备份副本中的快照与对象，帮助判断存储占用。',targetKind:'directory',targetLabel:'备份副本目录',explicitTarget:true,placeholder:'例如：backup-copy'},
])
function available(action,caps){return action.workflow?getWorkflow(action.workflow).steps.every(s=>caps.some(c=>c.id===s.capabilityId&&c.riskLevel==='L0')):caps.some(c=>c.id===action.capability&&c.riskLevel==='L0')}
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
   return {schema:'armorbreak.product-catalog/v1',productVersion:PRODUCT_VERSION,runtimeObservation:engine.runtime?.runtimeObservation?.snapshot(),workspaceName:basename(ctx.workspaceId),mode:'OFFLINE_READ_ONLY',hostConnection:'NOT_CONNECTED',authentication:'NONE',
    actions:ACTIONS.filter(a=>available(a,caps)).map(({runOptions,...a})=>({...a,permission:'L0_READ_ONLY'})),exampleAvailable:Boolean(exampleCtx),
    unavailable:[{id:'host-install',title:'安装到 DSH 宿主',reason:'真实宿主适配与可信身份尚未验收'}, {id:'plugin-activation',title:'启用宿主插件',reason:'隔离文件事务不等于真实加载'}, {id:'configuration-write',title:'应用宿主配置',reason:'本地网页不签发写入批准'}]}
  },
  async run(input){
   if(!input||Array.isArray(input)||Object.keys(input).some(k=>!['action','target'].includes(k))||typeof input.target!=='string'||!input.target.trim()||input.target.length>2048)throw new Error('PRODUCT_INVALID_REQUEST')
   const action=ACTIONS.find(a=>a.id===input.action);if(!action||!available(action,await engine.capabilities(ctx)))throw new Error('PRODUCT_ACTION_UNAVAILABLE')
   const target=resolve(ctx.workspaceId,input.target)
   if(action.workflow)return engine.startWorkflow({...ctx,requestId:randomUUID(),traceId:randomUUID()},{workflow:action.workflow,target})
   // Core performs lexical AND canonical workspace/identity checks; no HTTP principal is accepted.
   return engine.analyze({...ctx,requestId:randomUUID(),traceId:randomUUID()},{capability:action.capability,target,...(action.runOptions?{options:action.runOptions}:{})})
  },
  async example(input){
   if(!exampleCtx||!input||Array.isArray(input)||Object.keys(input).length)throw new Error('PRODUCT_EXAMPLE_UNAVAILABLE')
   return engine.analyze({...exampleCtx,requestId:randomUUID(),traceId:randomUUID()},{capability:'forensics.hash',target:exampleFile})
  },
  async tasks(){
   const rows=[]
   for(const entry of contexts())for(const task of await engine.listTasks(entry.ctx))rows.push({taskId:task.id,state:task.state,title:task.title,workflowId:task.workflowId??null,capability:task.steps?.[0]?.capabilityId??null,createdAt:task.createdAt,scope:entry.scope,reportAvailable:Boolean(task.report?.path)})
   return rows.sort((a,b)=>String(b.createdAt).localeCompare(String(a.createdAt))).slice(0,20)
  },
  async report(taskId){const entry=await owned(taskId),report=await engine.getReport(entry.ctx,taskId);return {taskId,sha256:report.sha256,markdown:report.markdown}},
  async evidence(taskId){const entry=await owned(taskId);return engine.getEvidence(entry.ctx,taskId)},
 })
}
