import { open, unlink, readFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
export function githubApi(token, fetchImpl=fetch) {
  return async (path,method='GET',body) => {
    if(!/^(repos\/|app(?:\/|$)|installation\/)/.test(path) || path.includes('..')) throw new Error('API path refused')
    let r
    try {r=await fetchImpl(`https://api.github.com/${path}`,{method,headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},body:body&&JSON.stringify(body),signal:AbortSignal.timeout(30000),redirect:'error'})}catch{throw new Error('GitHub network/timeout failure; no success decision')}
    if(!r.ok) throw new Error(`GitHub API ${r.status}; no success decision`)
    try{return await r.json()}catch{throw new Error('invalid GitHub JSON')}
  }
}
export async function paged(api,path,field,totalField='total_count') {
 const out=[],ids=new Set();let expected
 for(let page=1;page<=20;page++){
  const d=await api(`${path}${path.includes('?')?'&':'?'}per_page=100&page=${page}`)
  if(!Number.isSafeInteger(d[totalField]) || d[totalField]<0 || !Array.isArray(d[field]) || (expected!==undefined&&expected!==d[totalField])) throw new Error('inconsistent pagination')
  expected=d[totalField]
  for(const x of d[field]){if(!Number.isSafeInteger(x.id)||ids.has(x.id))throw new Error('duplicate/missing page identity');ids.add(x.id);out.push(x)}
  if(out.length===expected)return out
  if(out.length>expected || !d[field].length)throw new Error('incomplete pagination')
 }
 throw new Error('pagination limit exceeded')
}
const permissions={contents:'read',actions:'read',pull_requests:'read',checks:'write',metadata:'read'}
function leastPermissions(actual){return actual && Object.entries(actual).every(([k,v])=>permissions[k]===v)&&Object.entries(permissions).every(([k,v])=>actual[k]===v)}
export async function issueToken(appApi,config,now=Date.now()) {
 if(!Number.isSafeInteger(config?.appId)||config.appId<=0||config.appId===15368||!Number.isSafeInteger(config.installationId)||!Number.isSafeInteger(config.repositoryId)||!Number.isSafeInteger(config.accountId))throw new Error('independent App configuration required')
 const app=await appApi('app');if(app.id!==config.appId)throw new Error('preflight App identity mismatch')
 const installation=await appApi(`app/installations/${config.installationId}`)
 if(installation.id!==config.installationId||installation.repository_selection!=='selected'||installation.app_id!==config.appId||installation.account?.id!==config.accountId||installation.suspended_at||!leastPermissions(installation.permissions))throw new Error('installation identity/permissions mismatch')
 const issued=await appApi(`app/installations/${config.installationId}/access_tokens`,'POST',{repository_ids:[config.repositoryId],permissions})
 if(!issued.token||!leastPermissions(issued.permissions)||!Array.isArray(issued.repositories)||issued.repositories.length!==1||issued.repositories[0].id!==config.repositoryId||Date.parse(issued.expires_at)<=now||Date.parse(issued.expires_at)>now+3600000||!Number.isFinite(Date.parse(issued.expires_at)))throw new Error('installation token scope/expiry mismatch')
 return issued.token
}
export async function verifyTokenScope(api,config){const repos=await paged(api,'installation/repositories','repositories');if(repos.length!==1||repos[0].id!==config.repositoryId)throw new Error('token repository scope mismatch')}
const hash = value => createHash('sha256').update(value).digest('hex')
const bindingFor = a => ({ externalId:a.externalId, repository:a.repository, target:a.target, appId:a.config.appId, name:a.decision.context, conclusion:a.decision.errors.length?'failure':'success', decisionHash:hash(JSON.stringify(a.decision)) })
function journalPaths(a) {
 if(!a.stateDirectory || !a.externalId)throw new Error('durable publication state directory and full external_id required')
 const key=hash(a.externalId)
 return {file:join(a.stateDirectory,`${key}.jsonl`),lease:join(a.stateDirectory,`${key}.lock`)}
}
async function journal(file,binding) {
 let text
 try{text=await readFile(file,'utf8')}catch(e){if(e.code==='ENOENT')return [];throw e}
 if(!text.endsWith('\n'))throw new Error('RECONCILIATION_REQUIRED: torn/empty publication journal')
 const rows=[]
 for(const line of text.trimEnd().split('\n')){
  let row;try{row=JSON.parse(line)}catch{throw new Error('RECONCILIATION_REQUIRED: invalid journal')}
  const {hash:stored,...body}=row
  if(row.seq!==rows.length || row.previous!==(rows.at(-1)?.hash??null) || stored!==hash(JSON.stringify(body)) || JSON.stringify(row.binding)!==JSON.stringify(binding))throw new Error('RECONCILIATION_REQUIRED: journal identity/chain mismatch')
  rows.push(row)
 }
 return rows
}
async function append(file,rows,binding,event) {
 const body={version:1,seq:rows.length,previous:rows.at(-1)?.hash??null,binding,...event}
 const row={...body,hash:hash(JSON.stringify(body))}
 const h=await open(file,rows.length?'a':'ax',0o600)
 try{await h.writeFile(JSON.stringify(row)+'\n');await h.sync()}finally{await h.close()}
 rows.push(row)
 return row
}
function identity(check,a) {
 if(!Number.isSafeInteger(check?.id)||check.name!==a.decision.context||check.app?.id!==a.config.appId||check.head_sha!==a.target||check.external_id!==a.externalId)throw new Error('check issuer/binding mismatch')
}
function completed(check,a) {
 try{identity(check,a)}catch{throw new Error('post-publication readback issuer/binding mismatch')}
 if(check.status!=='completed'||check.conclusion!==(a.decision.errors.length?'failure':'success'))throw new Error('post-publication readback status/conclusion mismatch')
}
async function remoteMatches(api,a) {
 const checks=await paged(api,`repos/${a.repository}/commits/${a.target}/check-runs?filter=all`,'check_runs')
 // A wrong-App match is a conflict, not proof that no prior request exists.
 const matches=checks.filter(x=>x.external_id===a.externalId)
 if(matches.length>1)throw new Error('duplicate check receipts require recovery')
 if(matches.length)identity(matches[0],a)
 return matches
}
export async function publish(api,a) {
 const paths=journalPaths(a)
 return withLease(paths.lease,async()=>{
  const binding=bindingFor(a), rows=await journal(paths.file,binding)
  const record=(state,extra={})=>append(paths.file,rows,binding,{state,...extra})
  let last=rows.at(-1)
  if(last && !['PREPARED','READY_TO_COMPLETE','COMPLETED'].includes(last.state)){
   if(last.state!=='RECONCILIATION_REQUIRED')await record('RECONCILIATION_REQUIRED',{pending:last.pending??last.state,checkId:last.checkId??null})
   throw new Error('RECONCILIATION_REQUIRED: unresolved durable publication intent; read-only reconciliation required')
  }
  if(!last){await record('PREPARED');last=rows.at(-1)}
  try{
   await verifyTokenScope(api,a.config)
   await a.recheck()
   if(last.state==='COMPLETED'){
    const check=await api(`repos/${a.repository}/check-runs/${last.checkId}`)
    completed(check,a);return check
   }
   let check
   if(last.state==='READY_TO_COMPLETE'){
    check=await api(`repos/${a.repository}/check-runs/${last.checkId}`);identity(check,a)
   }else{
    check=(await remoteMatches(api,a))[0]
    if(!check){
     await record('POST_INTENT',{pending:'POST'}) // fsync BEFORE remote mutation
     check=await api(`repos/${a.repository}/check-runs`,'POST',{name:a.decision.context,head_sha:a.target,status:'in_progress',external_id:a.externalId})
     identity(check,a)
     await record('POST_CONFIRMED',{checkId:check.id})
    }
   }
   identity(check,a)
   if(check.status==='completed'){
    completed(check,a);await a.recheck();await record('COMPLETED',{checkId:check.id,status:check.status,conclusion:check.conclusion});return check
   }
   if(check.status!=='in_progress'||check.conclusion!=null)throw new Error('unexpected incomplete check status')
   await a.recheck()
   await record('PATCH_INTENT',{pending:'PATCH',checkId:check.id})
   await api(`repos/${a.repository}/check-runs/${check.id}`,'PATCH',{status:'completed',conclusion:binding.conclusion,output:{title:binding.conclusion,summary:JSON.stringify(a.decision)}})
   const readback=await api(`repos/${a.repository}/check-runs/${check.id}`)
   completed(readback,a)
   await record('COMPLETED',{checkId:check.id,status:readback.status,conclusion:readback.conclusion})
   return readback
  }catch(error){
   const prior=rows.at(-1)
   await record('RECONCILIATION_REQUIRED',{checkId:prior.checkId??null,pending:prior.pending??prior.state,reason:error.message})
   throw error
  }
 })
}
export async function reconcile(api,a) {
 const paths=journalPaths(a)
 return withLease(paths.lease,async()=>{
  const binding=bindingFor(a),rows=await journal(paths.file,binding)
  if(!rows.length)throw new Error('no durable intent to reconcile; publication refused')
  const record=(state,extra={})=>append(paths.file,rows,binding,{state,...extra})
  try{
   await verifyTokenScope(api,a.config);await a.recheck()
   const matches=await remoteMatches(api,a)
   if(matches.length!==1)throw new Error('RECONCILIATION_REQUIRED: prior request may exist but is not yet visible; no retry allowed')
   const check=await api(`repos/${a.repository}/check-runs/${matches[0].id}`)
   identity(check,a);await a.recheck()
   const recordedIds=rows.filter(x=>x.checkId!=null).map(x=>x.checkId)
   if(recordedIds.some(id=>id!==check.id))throw new Error('remote receipt differs from durable identity')
   if(check.status==='completed'){
    completed(check,a);await record('COMPLETED',{checkId:check.id,status:check.status,conclusion:check.conclusion});return {state:'COMPLETED',check}
   }
   // Once PATCH may have been sent, an incomplete read is not proof of failure.
   // Never retry PATCH on eventual-consistency evidence.
   if(rows.some(x=>x.state==='PATCH_INTENT'||x.state==='COMPLETED'))throw new Error('RECONCILIATION_REQUIRED: uncertain completion; wait for authoritative completed record')
   if(check.status!=='in_progress'||check.conclusion!=null)throw new Error('inconsistent remote incomplete status')
   await record('READY_TO_COMPLETE',{checkId:check.id})
   return {state:'READY_TO_COMPLETE',check}
  }catch(error){await record('RECONCILIATION_REQUIRED',{reason:error.message});throw error}
 })
}
export async function withLease(path,action){let handle;try{handle=await open(path,'wx',0o600)}catch{throw new Error('controller lease exists; explicit recovery required')}try{return await action()}finally{await handle.close();await unlink(path)}}




