import test from 'node:test'
import assert from 'node:assert/strict'
import { validatePreviewRuns } from '../scripts/v24/preview-release-preflight.mjs'
import { publishPreview } from '../scripts/v24/publish-preview.mjs'
const commit='a'.repeat(40)
function fixture(){const paths=['.github/workflows/development-gate.yml','.github/workflows/v24-package-validation.yml'],names=[['Node 22 / ubuntu-latest (common development)','Node 24 / ubuntu-latest (common development)','Node 22 / windows-latest (common development)','Node 24 / windows-latest (common development)','Common development L0','Common development L1','ArmorBreak development gate (required)'],['install (ubuntu-latest, 22)','install (ubuntu-latest, 24)','install (windows-latest, 22)','install (windows-latest, 24)']];return {runs:paths.map((path,id)=>({path,id:id+1,head_sha:commit,event:'push',status:'completed',conclusion:'success'})),jobs:Object.fromEntries(names.map((rows,i)=>[i+1,rows.map(name=>({name,status:'completed',conclusion:'success'}))]))}}
test('Preview admission requires every real exact-main matrix and L0/L1 job',()=>{const f=fixture();assert.equal(validatePreviewRuns(commit,f.runs,f.jobs).length,2)})
for(const conclusion of ['skipped','failure','cancelled',null])test(`Preview admission rejects ${conclusion} instead of upgrading it to success`,()=>{const f=fixture();f.jobs[1][0].conclusion=conclusion;assert.throws(()=>validatePreviewRuns(commit,f.runs,f.jobs),/JOB_NOT_SUCCESS/)})
test('PR, old SHA, missing matrix and a newer failed rerun cannot supply Preview admission',()=>{
 for(const modify of [f=>f.runs[0].event='pull_request',f=>f.runs[0].head_sha='b'.repeat(40),f=>f.jobs[2].pop(),f=>f.runs.push({...f.runs[0],id:100,conclusion:'failure'})]){const f=fixture();modify(f);assert.throws(()=>validatePreviewRuns(commit,f.runs,f.jobs))}
})
test('publication API is unavailable in ordinary local execution',()=>{const before=process.env.GITHUB_ACTIONS;delete process.env.GITHUB_ACTIONS;try{assert.throws(()=>publishPreview({commit,directory:'.'}),/HOSTED_OWNER/)}finally{if(before!==undefined)process.env.GITHUB_ACTIONS=before}})
