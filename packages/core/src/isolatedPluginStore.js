/** Trusted-host quarantine installation. Physical files, fresh roots, no plugin execution. */
import { createHash } from 'node:crypto'
import { mkdir, open, lstat, readdir, realpath } from 'node:fs/promises'
import { join } from 'node:path'
import { canonicalConfig } from '../../../lib/integrations/configOverlay.js'
import { verifyPluginClosure } from '../../../lib/catalog/pluginPackage.js'
import { maintenancePath } from '../../installer/maintenancePlan.js'
import { createSyntheticMaintenance, reopenSyntheticMaintenance } from './syntheticMaintenance.js'
import { readBounded } from './util.js'
import { sameFilesystemPath } from '../../../lib/core/pathBoundary.js'
const TOKEN=Symbol('fresh quarantine transaction'),digest=bytes=>createHash('sha256').update(bytes).digest('hex')
// A module-private capability, never a public method or caller-controlled option.
const historicalReaders=new WeakMap()
const id=stat=>({dev:stat.dev,ino:stat.ino}),same=(a,b)=>a.dev===b.dev&&a.ino===b.ino
const EMPTY={schema:'armorbreak.quarantined-install/v1',status:'NOT_INSTALLED',closure:null,executionAllowed:false}
async function writeNew(path,bytes){const file=await open(path,'wx',0o600);try{await file.writeFile(bytes);await file.sync()}finally{await file.close()}}
async function capture(input,receipts){
 const snapshot=await verifyPluginClosure(input),files=[];let total=0
 for(const item of snapshot.closure){
  const bytes=await input.env.readFile(join(input.targetPath,...maintenancePath(item.path)),65537)
  total+=bytes.length;if(bytes.length>65536||total>65536||files.length>=128||digest(bytes)!==item.sha256)throw new Error('PLUGIN_STORE_CAPTURE_LIMIT_OR_DRIFT')
  files.push({path:item.path,bytes:Buffer.from(bytes)})
 }
 return {snapshot,files,receipts:structuredClone(receipts)}
}
function independent(reviewer){if(reviewer?.kind!=='INDEPENDENT_SCOPED_PLUGIN_REVIEWER_V1'||typeof reviewer.review!=='function')throw new Error('PLUGIN_STORE_INDEPENDENT_REVIEWER_REQUIRED')}
function compareVersion(a,b){
 if(a.length>128||b.length>128)throw new Error('PLUGIN_STORE_VERSION_INVALID')
 const split=v=>{const [core,...tail]=v.split('-');return {core:core.split('.').map(BigInt),pre:tail.join('-').split('.').filter(Boolean)}}
 const x=split(a),y=split(b)
 for(let i=0;i<3;i++)if(x.core[i]!==y.core[i])return x.core[i]>y.core[i]?1:-1
 if(!x.pre.length||!y.pre.length)return x.pre.length===y.pre.length?0:x.pre.length?-1:1
 for(let i=0;i<Math.max(x.pre.length,y.pre.length);i++){
  const l=x.pre[i],r=y.pre[i];if(l===r)continue;if(l===undefined||r===undefined)return l===undefined?-1:1
  const ln=/^\d+$/.test(l),rn=/^\d+$/.test(r)
  if(ln&&rn){if(BigInt(l)!==BigInt(r))return BigInt(l)>BigInt(r)?1:-1;continue}
  if(ln!==rn)return ln?-1:1;return l>r?1:-1
 }return 0
}

export class IsolatedPluginTransaction{
 #lab;#record;#reviewer
 constructor(token,lab,record,reviewer){if(token!==TOKEN)throw new Error('PLUGIN_STORE_CONSTRUCTOR_DENIED');this.#lab=lab;this.#record=record;this.#reviewer=reviewer;historicalReaders.set(this,()=>this.#copySnapshot(true));Object.freeze(this)}
 get root(){return this.#lab.root}get planId(){return this.#record.planId}
 async #verify(){
  await this.#lab.boundary()
  const record=await this.#lab.readSealed('plugin-store.json')
  if(canonicalConfig(record)!==canonicalConfig(this.#record))throw new Error('PLUGIN_STORE_RECORD_DRIFT')
  const payloadRoot=join(this.#lab.control,'payloads'),payloadStat=await lstat(payloadRoot)
  if(!payloadStat.isDirectory()||payloadStat.isSymbolicLink()||!same(id(payloadStat),record.payloadsId)||!sameFilesystemPath(await realpath(payloadRoot),payloadRoot))throw new Error('PLUGIN_STORE_DIRECTORY_DRIFT')
  if(canonicalConfig((await readdir(payloadRoot)).sort())!==canonicalConfig(record.versions.map(v=>v.snapshot.closureSha256).sort()))throw new Error('PLUGIN_STORE_MEMBERS_DRIFT')
  for(const version of record.versions){
   const base=join(this.#lab.control,'payloads',version.snapshot.closureSha256),actual=[]
   for(const directory of version.directories){const stat=await lstat(join(base,...directory.path.split('/').filter(Boolean)));if(!stat.isDirectory()||stat.isSymbolicLink()||!same(id(stat),directory.identity))throw new Error('PLUGIN_STORE_DIRECTORY_DRIFT')}
   const walk=async(path,rel='')=>{for(const entry of await readdir(path,{withFileTypes:true})){
    const name=rel?rel+'/'+entry.name:entry.name,p=join(path,entry.name)
    if(entry.isSymbolicLink())throw new Error('PLUGIN_STORE_LINK_DENIED')
    if(entry.isDirectory()){if(!version.directories.some(d=>d.path===name))throw new Error('PLUGIN_STORE_MEMBERS_DRIFT');await walk(p,name)}
    else if(entry.isFile())actual.push(name);else throw new Error('PLUGIN_STORE_SPECIAL_FILE')
   }}
   await walk(base)
   if(canonicalConfig(actual.sort())!==canonicalConfig(version.files.map(f=>f.path).sort()))throw new Error('PLUGIN_STORE_MEMBERS_DRIFT')
   for(const file of version.files){
    const path=join(base,...maintenancePath(file.path)),stat=await lstat(path)
    if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||!same(id(stat),file.identity))throw new Error('PLUGIN_STORE_FILE_DRIFT')
    const read=await readBounded(path,65536)
    if(read.truncated||digest(read.buffer)!==file.sha256||!same(id(await lstat(path)),file.identity))throw new Error('PLUGIN_STORE_CONTENT_DRIFT')
   }
  }
  return record
 }
 async #inspect(){
  const record=await this.#verify()
  const events=await this.#lab.events(),last=events.at(-1)
  if(last?.planId!==record.planId)throw new Error('PLUGIN_STORE_PLAN_BINDING')
  const bytes=await this.#lab.file('installation.txt',async file=>{const stat=await file.stat();if(stat.size>65536)throw new Error('PLUGIN_STORE_STATE_LIMIT');return file.readFile()})
  if(![canonicalConfig(record.previous),canonicalConfig(record.desired)].includes(bytes.toString()))throw new Error('PLUGIN_STORE_STATE_DRIFT')
  const state=JSON.parse(bytes),version=record.versions.find(v=>v.snapshot.closureSha256===state.closure)
  const review=version?this.#reviewer.review(version.snapshot,version.receipts):null
  const finalized=['COMMITTED','ROLLED_BACK'].includes(last.state)
  return {mode:'ISOLATED_QUARANTINE_FILES_ONLY',state,packages:version?.snapshot.plugins.map(p=>({id:p.id,version:p.version}))??[],dependencyOrder:version?.snapshot.dependencyOrder??[],fileCount:version?.files.length??0,
   transactionState:last.state,transactionFinalized:finalized,selectionAvailable:finalized&&state.status==='INSTALLED_QUARANTINED'&&review?.state==='READY_FOR_SYNTHETIC_STAGING_APPROVAL',
   currentTrust:review?.state??'NO_PACKAGE',activationAuthorized:false,hostWrites:false,productionInstallation:false}
 }
 async inspect(){return this.#inspect()}
 async #recheckSelection(before,historical=false){
  const after=await this.#inspect()
  if(!after.transactionFinalized||canonicalConfig({state:before.state,transactionState:before.transactionState})!==canonicalConfig({state:after.state,transactionState:after.transactionState})||(!historical&&!after.selectionAvailable))throw new Error('PLUGIN_STORE_SELECTION_CHANGED_OR_UNTRUSTED')
 }
 async readInstalled(path){return this.#reviewer.withCommitLease?this.#reviewer.withCommitLease(()=>this.#readInstalled(path)):this.#readInstalled(path)}
 async #readInstalled(path){
  const current=await this.#inspect()
  if(!current.selectionAvailable)throw new Error('PLUGIN_STORE_DISABLED_OR_UNTRUSTED')
  maintenancePath(path)
  const version=this.#record.versions.find(v=>v.snapshot.closureSha256===current.state.closure),file=version.files.find(f=>f.path===path)
  if(!file)throw new Error('PLUGIN_STORE_PATH_DENIED')
  const bytes=await readBounded(join(this.#lab.control,'payloads',current.state.closure,...maintenancePath(path)),65536)
  if(bytes.truncated||digest(bytes.buffer)!==file.sha256)throw new Error('PLUGIN_STORE_CONTENT_DRIFT')
  await this.#recheckSelection(current)
  return bytes.buffer
 }
 async apply(provider,checkpoint){
  const execute=async()=>{
  await this.#verify()
  const record=this.#record
  const check=()=>{if(record.operation!=='disable'){
   const version=record.versions.find(v=>v.snapshot.closureSha256===record.desired.closure)
   if(this.#reviewer.review(version.snapshot,version.receipts).state!=='READY_FOR_SYNTHETIC_STAGING_APPROVAL')throw new Error('PLUGIN_STORE_REVIEW_REVOKED_OR_DENIED')
  }}
  check()
  // Recheck after delayed host approval. This is not production revocation/commit linearization.
  const wrapped={request:async request=>{if(!provider||typeof provider.request!=='function')throw new Error('TRUSTED_APPROVAL_PROVIDER_REQUIRED');const outcome=await provider.request(request);await this.#verify();check();return outcome}}
  const result=await this.#lab.apply(record.planId,wrapped,checkpoint);await this.#verify();return {...result,...await this.#inspect()}
  }
  // Durable policy writers and this complete synthetic commit use one exclusive lease.
  // A competing revocation receives BUSY and must retry; it is never reported as committed.
  return this.#reviewer.withCommitLease?this.#reviewer.withCommitLease(execute):execute()
 }
 async rollback(provider){await this.#verify();const result=await this.#lab.rollback(this.planId,provider);return {...result,...await this.#inspect()}}
 async copySelected(){return this.#reviewer.withCommitLease?this.#reviewer.withCommitLease(()=>this.#copySnapshot(false)):this.#copySnapshot(false)}
 async #copySnapshot(historical){
  const current=await this.#inspect()
  if(!current.transactionFinalized)throw new Error('PLUGIN_STORE_TRANSACTION_NOT_FINAL')
  if(!current.state.closure)throw new Error('PLUGIN_STORE_NOT_INSTALLED')
  if(!historical&&!current.selectionAvailable)throw new Error('PLUGIN_STORE_DISABLED_OR_UNTRUSTED')
  const version=this.#record.versions.find(v=>v.snapshot.closureSha256===current.state.closure),files=[]
  for(const file of version.files){const read=await readBounded(join(this.#lab.control,'payloads',current.state.closure,...maintenancePath(file.path)),65536);if(read.truncated||digest(read.buffer)!==file.sha256)throw new Error('PLUGIN_STORE_CONTENT_DRIFT');files.push({path:file.path,bytes:read.buffer})}
  await this.#recheckSelection(current,historical)
  return {state:current.state,snapshot:structuredClone(version.snapshot),receipts:structuredClone(version.receipts),files}
 }
}

/** A new bounded root per transaction; never accepts a destination directory or a DSH root. */
export async function planIsolatedPluginInstall(runtime,options){
 if(!options||Object.keys(options).some(k=>!['operation','candidate','current','reviewer','receipts','operator','sessionId'].includes(k)))throw new Error('PLUGIN_STORE_OPERATION_INVALID')
 const {operation='install',candidate,current,reviewer,receipts,operator,sessionId}=options
 independent(reviewer)
 if(!['install','update','disable'].includes(operation)||(operation==='install'&&current)||(operation!=='install'&&!(current instanceof IsolatedPluginTransaction))||(operation==='disable'&&candidate)||(operation!=='disable'&&!candidate))throw new Error('PLUGIN_STORE_OPERATION_INVALID')
 if(current){const previousLab=await reopenSyntheticMaintenance(runtime,current.root,{operator,sessionId});await previousLab.events()}
 const previous=current?await historicalReaders.get(current)():null,next=operation==='disable'?null:await capture(candidate,receipts)
 if(next&&reviewer.review(next.snapshot,receipts).state!=='READY_FOR_SYNTHETIC_STAGING_APPROVAL')throw new Error('PLUGIN_STORE_REVIEW_DENIED')
 if(operation==='update'){
  if(previous.snapshot.closureSha256===next.snapshot.closureSha256)throw new Error('PLUGIN_STORE_NO_CHANGE')
  const old=previous.snapshot.plugins,newer=next.snapshot.plugins
  if(canonicalConfig(old.map(p=>p.id).sort())!==canonicalConfig(newer.map(p=>p.id).sort()))throw new Error('PLUGIN_STORE_PACKAGE_SET_CHANGE')
  let advanced=false
  for(const plugin of newer){const prior=old.find(p=>p.id===plugin.id);if(prior.source.repository!==plugin.source.repository)throw new Error('PLUGIN_STORE_SOURCE_CHANGE');const cmp=compareVersion(plugin.version,prior.version);if(cmp<0)throw new Error('PLUGIN_STORE_DOWNGRADE_DENIED');advanced||=cmp>0}
  if(!advanced)throw new Error('PLUGIN_STORE_VERSION_NOT_ADVANCED')
 }
 const before=previous?.state??EMPTY,desired=operation==='disable'?{...before,status:'DISABLED'}:{...EMPTY,status:before.status==='DISABLED'?'DISABLED':'INSTALLED_QUARANTINED',closure:next.snapshot.closureSha256}
 const lab=await createSyntheticMaintenance(runtime,{operator,sessionId,seeds:{'installation.txt':canonicalConfig(before)}})
 const payloads=join(lab.control,'payloads');await mkdir(payloads,{mode:0o700})
 const versions=[]
 for(const input of [previous,next].filter(Boolean)){
  if(versions.some(v=>v.snapshot.closureSha256===input.snapshot.closureSha256))continue
  const base=join(payloads,input.snapshot.closureSha256);await mkdir(base,{mode:0o700})
  const directories=new Map([['',id(await lstat(base))]]),files=[]
  for(const file of input.files){
   const parts=maintenancePath(file.path)
   for(let n=1;n<parts.length;n++){const rel=parts.slice(0,n).join('/');if(!directories.has(rel)){const path=join(base,...parts.slice(0,n));await mkdir(path,{mode:0o700});directories.set(rel,id(await lstat(path)))}}
   await lab.boundary();const path=join(base,...parts);await writeNew(path,file.bytes)
   files.push({path:file.path,sha256:digest(file.bytes),identity:id(await lstat(path))})
  }
  versions.push({snapshot:input.snapshot,receipts:input.receipts,files,directories:[...directories].map(([path,identity])=>({path,identity}))})
 }
 const plan=await lab.plan([{name:'installation.txt',content:canonicalConfig(desired)}])
 const record={schema:'armorbreak.isolated-plugin-store/v1',planId:plan.planId,operation,previous:before,desired,versions,payloadsId:id(await lstat(payloads))}
 await writeNew(join(lab.control,'plugin-store.json'),lab.seal(record))
 const store=new IsolatedPluginTransaction(TOKEN,lab,record,reviewer);await store.inspect()
 return {store,plan,mode:'ISOLATED_QUARANTINE_FILES_ONLY',approvalRequired:true,activationAuthorized:false,hostWrites:false}
}
export async function reopenIsolatedPluginInstall(runtime,root,{operator,sessionId,reviewer}){
 independent(reviewer);const lab=await reopenSyntheticMaintenance(runtime,root,{operator,sessionId}),record=await lab.readSealed('plugin-store.json')
 if(record.schema!=='armorbreak.isolated-plugin-store/v1')throw new Error('PLUGIN_STORE_RECORD_INVALID')
 const store=new IsolatedPluginTransaction(TOKEN,lab,record,reviewer);await store.inspect();return store
}
