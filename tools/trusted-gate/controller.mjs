import { realpathSync } from 'node:fs'
import { createSign } from 'node:crypto'
import { resolve, isAbsolute } from 'node:path'
import { evaluate, context } from './evaluate.mjs'
import { candidateFromPr, sameCandidate, mergeTarget } from './binding.mjs'
import { githubApi, paged, issueToken, publish, reconcile } from './runtime.mjs'
import { readRootFile, digest } from './trust.mjs'
export async function control({trust,number,runId,mode,root}) {
 const {policy,manifest,policyDigest}=trust
 const repoPath=`repos/${policy.repository}`
 let api
 if(mode!=='--dry-run'){
  const now=Math.floor(Date.now()/1000), app=manifest.app
  const enc=x=>Buffer.from(JSON.stringify(x)).toString('base64url')
  const message=`${enc({alg:'RS256',typ:'JWT'})}.${enc({iat:now-60,exp:now+540,iss:app?.appId})}`
  const signer=createSign('RSA-SHA256');signer.update(message)
  const jwt=`${message}.${signer.sign(readRootFile(root,'app-private-key.pem'),'base64url')}`
  const token=await issueToken(githubApi(jwt),app)
  api=githubApi(token)
 }else{
  const token=process.env.ARMORBREAK_CONTROLLER_READ_TOKEN
  if(!token)throw new Error('read-only replay token required')
  api=githubApi(token)
 }
 const pr=await api(`${repoPath}/pulls/${number}`)
 if(pr.number!==number||pr.state!=='open'||pr.base?.repo?.full_name!==policy.repository)throw new Error('not the selected open repository PR')
 const candidate=candidateFromPr(pr)
 const run=await api(`${repoPath}/actions/runs/${runId}`)
 const tree=await api(`${repoPath}/git/trees/${candidate.sha}?recursive=1`)
 const jobs=await paged(api,`${repoPath}/actions/runs/${runId}/attempts/${run.run_attempt}/jobs`,'jobs')
 const errors=evaluate({policy,candidate,run,jobs,tree})
 let target
 try{
  const merge=await api(`${repoPath}/git/commits/${pr.merge_commit_sha}`)
  const head=await api(`${repoPath}/git/commits/${candidate.sha}`)
  target=mergeTarget(pr,merge,head)
 }catch(error){errors.push(error.message)}
 const recheck=async()=>{
  const current=await api(`${repoPath}/pulls/${number}`)
  if(!sameCandidate(candidate,candidateFromPr(current))||current.merge_commit_sha!==pr.merge_commit_sha||current.state!=='open')throw new Error('PR head/base/target changed during evaluation')
  const latest=await api(`${repoPath}/actions/runs/${runId}`)
  if(latest.run_attempt!==run.run_attempt||latest.status!=='completed'||latest.conclusion!=='success')throw new Error('run attempt changed or not successful')
 }
 await recheck()
 const tuple={repository:policy.repository,pr:number,head:candidate.sha,base:candidate.baseSha,baseRef:candidate.baseRef,merge:pr.merge_commit_sha,policy:policyDigest,controllerVersion:manifest.controllerVersion,run:runId,attempt:run.run_attempt}
 const externalId=digest(JSON.stringify(tuple))
 const decision={context,...tuple,externalId,target:target?.sha,conclusion:errors.length?'failure':'success',errors}
 if(mode!=='--dry-run'){
  if(!target)throw new Error('no verified merge target; publication refused')
  // Fixed external service root only. Duplicate delivery is serialized; a
  // surviving lock requires operator recovery, not an automatic timeout bypass.
  const state=process.env.ARMORBREAK_CONTROLLER_STATE
  if(!state||!isAbsolute(state)||realpathSync(state)!==resolve(state)||resolve(state)===resolve(root))throw new Error('separate protected state directory required')
  const operation=mode==='--reconcile'?reconcile:publish
  await operation(api,{config:manifest.app,repository:policy.repository,target:target.sha,decision,externalId,recheck,stateDirectory:state})
 }
 console.log(JSON.stringify(decision,null,2))
 if(errors.length)process.exitCode=1
 return decision
}

