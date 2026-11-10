import { open, unlink } from 'node:fs/promises'
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
export async function publish(api,{config,repository,target,decision,externalId,recheck}){
 await verifyTokenScope(api,config)
 const path=`repos/${repository}`
 const checks=await paged(api,`${path}/commits/${target}/check-runs?filter=all`,'check_runs')
 const matches=checks.filter(x=>x.app?.id===config.appId&&x.external_id===externalId)
 if(matches.length>1)throw new Error('duplicate check receipts require recovery')
 const check=matches[0]??await api(`${path}/check-runs`,'POST',{name:decision.context,head_sha:target,status:'in_progress',external_id:externalId})
 if(check.name!==decision.context||check.app?.id!==config.appId||check.head_sha!==target||check.external_id!==externalId)throw new Error('pre-completion check issuer/binding mismatch')
 await recheck()
 const conclusion=decision.errors.length?'failure':'success'
 await api(`${path}/check-runs/${check.id}`,'PATCH',{status:'completed',conclusion,output:{title:conclusion,summary:JSON.stringify(decision)}})
 const readback=await api(`${path}/check-runs/${check.id}`)
 if(readback.name!==decision.context||readback.app?.id!==config.appId||readback.head_sha!==target||readback.external_id!==externalId||readback.conclusion!==conclusion)throw new Error('post-publication readback mismatch; operator recovery required')
 return readback
}
export async function withLease(path,action){let handle;try{handle=await open(path,'wx',0o600)}catch{throw new Error('controller lease exists; explicit recovery required')}try{return await action()}finally{await handle.close();await unlink(path)}}


