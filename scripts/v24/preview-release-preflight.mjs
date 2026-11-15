#!/usr/bin/env node
/** Exact-main, exact-job Preview admission. Never changes repository settings or releases. */
import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
export const REPOSITORY='LYL-Z/dsh-armorbreak'
export const FROZEN_V231_TAG='7b7056f43c5c9c1e96572619c7e5eb2cab854c8c'
const REQUIRED={
 '.github/workflows/development-gate.yml':['Node 22 / ubuntu-latest (common development)','Node 24 / ubuntu-latest (common development)','Node 22 / windows-latest (common development)','Node 24 / windows-latest (common development)','Common development L0','Common development L1','ArmorBreak development gate (required)'],
 '.github/workflows/v24-package-validation.yml':['install (ubuntu-latest, 22)','install (ubuntu-latest, 24)','install (windows-latest, 22)','install (windows-latest, 24)'],
}
export function validatePreviewRuns(commit,runs,jobsById){
 if(!/^[a-f0-9]{40}$/.test(commit))throw new Error('PREVIEW_COMMIT_INVALID')
 return Object.entries(REQUIRED).map(([path,names])=>{
  const run=runs.filter(r=>r.path===path&&r.event==='push'&&r.head_sha===commit).sort((a,b)=>b.id-a.id)[0]
  if(!run||run.status!=='completed'||run.conclusion!=='success')throw new Error('PREVIEW_EXACT_MAIN_CI_REQUIRED: '+path)
  const jobs=jobsById[run.id]??[]
  for(const name of names){const matches=jobs.filter(j=>j.name===name);if(matches.length!==1||matches[0].status!=='completed'||matches[0].conclusion!=='success')throw new Error('PREVIEW_JOB_NOT_SUCCESS: '+name)}
  return {path,runId:run.id,head:commit,jobs:names.map(name=>({name,conclusion:'success'}))}
 })
}
export function githubJson(path){return JSON.parse(execFileSync('gh',['api',path],{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024}))}
export function assertMain(commit){if(githubJson(`repos/${REPOSITORY}/branches/main`).commit.sha!==commit)throw new Error('PREVIEW_MAIN_CHANGED')}
export function previewPreflight(commit){
 if(!/^[a-f0-9]{40}$/.test(commit))throw new Error('PREVIEW_COMMIT_INVALID')
 if(process.env.GITHUB_ACTIONS==='true'&&(process.env.GITHUB_REF!=='refs/heads/main'||process.env.GITHUB_SHA!==commit||process.env.GITHUB_EVENT_NAME!=='workflow_dispatch'||process.env.GITHUB_ACTOR!=='LYL-Z'))throw new Error('PREVIEW_OWNER_DISPATCH_ON_EXACT_MAIN_REQUIRED')
 const pkg=JSON.parse(readFileSync(new URL('../../package.json',import.meta.url),'utf8'))
 if(!/^2\.4\.0-preview\.[1-9]\d*$/.test(pkg.version))throw new Error('PREVIEW_VERSION_REQUIRED')
 if(githubJson(`repos/${REPOSITORY}`).private!==false)throw new Error('PREVIEW_PUBLIC_ZERO_PAID_SCOPE_REQUIRED')
 assertMain(commit)
 if(githubJson(`repos/${REPOSITORY}/git/ref/tags/v2.3.1`).object.sha!==FROZEN_V231_TAG)throw new Error('FROZEN_V231_TAG_CHANGED')
 const tag='v'+pkg.version
 let existing=false
 try{githubJson(`repos/${REPOSITORY}/git/ref/tags/${tag}`);existing=true}catch(error){if(!String(error.stderr??'').includes('(HTTP 404)'))throw error}
 if(existing)throw new Error('PREVIEW_REFUSE_EXISTING_TAG')
 const releases=githubJson(`repos/${REPOSITORY}/releases?per_page=100`)
 if(releases.some(r=>r.tag_name===tag))throw new Error('PREVIEW_REFUSE_EXISTING_RELEASE_OR_DRAFT')
 const runs=githubJson(`repos/${REPOSITORY}/actions/runs?head_sha=${commit}&event=push&per_page=100`).workflow_runs,jobs={}
 for(const path of Object.keys(REQUIRED)){
  const run=runs.filter(r=>r.path===path&&r.event==='push'&&r.head_sha===commit).sort((a,b)=>b.id-a.id)[0]
  if(run)jobs[run.id]=githubJson(`repos/${REPOSITORY}/actions/runs/${run.id}/jobs?filter=latest&per_page=100`).jobs
 }
 return {schema:'armorbreak.preview-admission/v1',repository:REPOSITORY,commit,version:pkg.version,tag,channel:'PREVIEW_ONLY',checks:validatePreviewRuns(commit,runs,jobs),frozenV231Tag:FROZEN_V231_TAG,stableApproved:false,productionAppGate:false,fullMigrationComplete:false}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const i=process.argv.indexOf('--commit');if(i<0)throw new Error('--commit is required')
 const result=previewPreflight(process.argv[i+1]);if(process.argv.includes('--out'))writeFileSync(resolve(process.argv[process.argv.indexOf('--out')+1]),JSON.stringify(result,null,2)+'\n')
 console.log(JSON.stringify(result,null,2))
}
