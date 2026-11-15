#!/usr/bin/env node
/** Real CMD launch and HTTP task acceptance from an assembled, installed Windows folder. */
import assert from 'node:assert/strict'
import { spawn,execFileSync } from 'node:child_process'
import { once } from 'node:events'
import { createHash } from 'node:crypto'
import { readFileSync,writeFileSync } from 'node:fs'
import { resolve,join } from 'node:path'
import { fileURLToPath } from 'node:url'
export async function verifyWindowsExperience(root){
 if(process.platform!=='win32')throw new Error('WINDOWS_EXECUTION_REQUIRED')
 const manifest=JSON.parse(readFileSync(join(root,'experience-files.json'),'utf8'))
 if(manifest.schema!=='armorbreak.windows-experience/v1'||manifest.nodeBundled!==false)throw new Error('EXPERIENCE_MANIFEST_INVALID')
 for(const file of manifest.files){
  if(!/^[^\\:]+$/.test(file.path)||file.path.split('/').some(p=>!p||p==='.'||p==='..'))throw new Error('EXPERIENCE_MANIFEST_PATH')
  const bytes=readFileSync(join(root,file.path));if(bytes.length!==file.bytes||createHash('sha256').update(bytes).digest('hex')!==file.sha256)throw new Error('EXPERIENCE_FILE_DRIFT')
 }
 const system=join(process.env.SystemRoot??'C:/Windows','System32'),launcher=join(root,'Start ArmorBreak.cmd')
 const started=performance.now(),child=spawn(join(system,'cmd.exe'),['/d','/s','/c',`""${launcher}" --no-open"`],{cwd:root,windowsVerbatimArguments:true,windowsHide:true,stdio:['ignore','pipe','pipe']})
 let output='',stderr='',timer
 child.stderr.on('data',b=>stderr+=b.toString('utf8'))
 const exited=once(child,'close')
 const startup=new Promise((resolveStartup,reject)=>{
  timer=setTimeout(()=>reject(new Error('EXPERIENCE_START_TIMEOUT')),20000)
  child.stdout.on('data',bytes=>{output+=bytes.toString('utf8');if(output.length>65536)return reject(new Error('EXPERIENCE_START_OUTPUT_LIMIT'));const match=/http:\/\/127\.0\.0\.1:\d+/.exec(output);if(match)resolveStartup(match[0])})
  child.once('error',reject)
  child.once('exit',()=>reject(new Error('EXPERIENCE_START_FAILED: '+stderr.slice(0,2000))))
 })
 try{
  const url=await startup,readyMs=Math.round(performance.now()-started);clearTimeout(timer)
  assert.equal((await fetch(url)).status,200)
  const session=await(await fetch(url+'/api/native/session')).json(),headers={'content-type':'application/json','x-armorbreak-session':session.csrf}
  assert.equal(session.authentication,'NONE')
  const catalog=await(await fetch(url+'/api/product/catalog',{headers})).json();assert.equal(catalog.productVersion,manifest.version);assert.equal(catalog.hostConnection,'NOT_CONNECTED')
  const response=await fetch(url+'/api/product/example',{method:'POST',headers,body:'{}'});assert.equal(response.status,200);const task=await response.json();assert.equal(task.state,'COMPLETED');assert.ok(task.evidenceIds.length)
  const report=await(await fetch(url+'/api/product/report?taskId='+task.taskId,{headers})).json();assert.match(report.markdown,/任务状态：\*\*COMPLETED\*\*/)
  const result={schema:'armorbreak.windows-experience-acceptance/v1',commit:manifest.commit,version:manifest.version,entry:'ACTUAL_CMD_LAUNCH_INSTALLED_NODE_MODULES',readyMs,totalMs:Math.round(performance.now()-started),taskState:task.state,evidenceCount:task.evidenceIds.length,runtimeNode:catalog.runtimeObservation.process.node,nodePrerequisiteAlreadyInstalled:true,graphicalInstaller:'NOT_IMPLEMENTED',browserInteraction:'NOT_TESTED_BY_THIS_PROBE',dshCompatibility:'NOT_TESTED',productionIdentity:'NOT_VERIFIED'}
  return result
 }finally{
  clearTimeout(timer)
  // Terminate only the CMD process tree this probe just spawned, never a name
  // match or a user service. No filesystem cleanup or host writes occur here.
  if(child.exitCode===null)try{execFileSync(join(system,'taskkill.exe'),['/pid',String(child.pid),'/t','/f'],{windowsHide:true,stdio:'ignore'})}catch{}
  await exited
 }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const i=process.argv.indexOf('--root');if(i<0)throw new Error('--root is required')
 const root=resolve(process.argv[i+1]),result=await verifyWindowsExperience(root)
 if(process.argv.includes('--out'))writeFileSync(resolve(process.argv[process.argv.indexOf('--out')+1]),JSON.stringify(result,null,2)+'\n')
 console.log(JSON.stringify(result,null,2))
}
