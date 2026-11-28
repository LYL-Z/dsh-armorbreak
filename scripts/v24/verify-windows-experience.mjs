#!/usr/bin/env node
/** Real CMD launch and HTTP task acceptance from an assembled, installed Windows folder. */
import assert from 'node:assert/strict'
import { spawn,execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync,writeFileSync } from 'node:fs'
import { resolve,join } from 'node:path'
import { fileURLToPath } from 'node:url'

const LAUNCHER_READY = 'DSH is not connected. No privileged approval or host installation is available.'
const URL_LABEL = 'ArmorBreak 工作台：'
const STREAM_LIMIT_BYTES = 65536

export function waitForWindowsWorkbench(child, timeoutMs = 20000){
 return new Promise((resolveStartup,reject)=>{
  let stdout='',stderr='',spawned=false,exit,stdoutBytes=0,stderrBytes=0
  const phase=()=>{
   if(!spawned)return 'CMD_SPAWN_PENDING'
   if(stdout.includes(URL_LABEL))return 'WORKBENCH_URL_INCOMPLETE'
   if(stdout.includes(LAUNCHER_READY))return 'WORKBENCH_URL_PENDING'
   return 'CMD_NODE_PREFLIGHT_PENDING'
  }
  const failure=(code,detail='')=>new Error(`${code} phase=${phase()} stdoutBytes=${stdoutBytes} stderrBytes=${stderrBytes}${detail}`)
  const unexpectedExit=()=>failure('EXPERIENCE_START_EXITED',` exitCode=${exit?.[0]??'none'} signal=${exit?.[1]??'none'}`)
  const onSpawn=()=>{spawned=true}
  const onError=error=>settle(failure('EXPERIENCE_CMD_SPAWN_FAILED',` code=${error.code??'UNKNOWN'}`))
  const onExit=(code,signal)=>{exit=[code,signal]}
  const onClose=()=>settle(unexpectedExit())
  const onStdout=chunk=>receive(chunk,'stdout')
  const onStderr=chunk=>receive(chunk,'stderr')
  const timer=setTimeout(()=>settle(exit?unexpectedExit():failure('EXPERIENCE_START_TIMEOUT')),timeoutMs)

  function settle(error,url){
   clearTimeout(timer)
   child.stdout.off('data',onStdout).resume()
   child.stderr.off('data',onStderr).resume()
   child.off('spawn',onSpawn).off('error',onError).off('exit',onExit).off('close',onClose)
   if(error)reject(error);else resolveStartup(url)
  }

  function receive(chunk,stream){
   if(stream==='stdout')stdoutBytes+=Buffer.byteLength(chunk);else stderrBytes+=Buffer.byteLength(chunk)
   if(stdoutBytes+stderrBytes>STREAM_LIMIT_BYTES)return settle(failure('EXPERIENCE_START_OUTPUT_LIMIT'))
   if(stream==='stdout')stdout+=chunk;else stderr+=chunk
   if(stdout.includes('Node.js 22 or newer is required.')||stderr.includes('Node.js 22 or newer is required.')){
    return settle(failure('EXPERIENCE_NODE_PREREQUISITE_FAILED'))
   }
   if(stdout.includes('Startup failed. Check the message above. No administrator permission is required.')){
    const code=/\b(?:ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND|EADDRINUSE|EACCES|EPERM)\b/.exec(stderr)?.[0]
    return settle(failure('EXPERIENCE_START_FAILED',code?` code=${code}`:''))
   }
   const announcement=stdout.split('\n').slice(0,-1).find(line=>line.startsWith(URL_LABEL))
   if(announcement===undefined)return
   const match=/^http:\/\/127\.0\.0\.1:([1-9]\d{0,4})\r?$/.exec(announcement.slice(URL_LABEL.length))
   if(!match||Number(match[1])>65535)return settle(failure('EXPERIENCE_START_BAD_ENDPOINT'))
   if(exit)return settle(unexpectedExit())
   settle(null,`http://127.0.0.1:${match[1]}`)
  }

  child.on('spawn',onSpawn).on('error',onError).on('exit',onExit).on('close',onClose)
  child.stdout.setEncoding('utf8').on('data',onStdout)
  child.stderr.setEncoding('utf8').on('data',onStderr)
 })
}

async function stopWindowsProbe(child,closed,system){
 // Use only the PID of the launcher that this probe created.
 if(child.pid&&child.exitCode===null&&child.signalCode===null){
  try{execFileSync(join(system,'taskkill.exe'),['/pid',String(child.pid),'/t','/f'],{windowsHide:true,stdio:'ignore',timeout:5000})}catch{}
 }
 let timer
 try{
  await Promise.race([closed,new Promise((_,reject)=>{
   timer=setTimeout(()=>reject(new Error('EXPERIENCE_CLEANUP_TIMEOUT')),5000)
  })])
 }finally{
  clearTimeout(timer)
  child.stdout.destroy()
  child.stderr.destroy()
  child.unref()
 }
}

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
 const closed=new Promise(resolveClosed=>child.once('close',resolveClosed))
 // Consume child errors after the startup observer removes its own listener.
 child.on('error',()=>{})
 let failure
 try{
  const url=await waitForWindowsWorkbench(child)
  const signal=AbortSignal.timeout(10000)
  const request=async(path,options={},json=false)=>{
   const stage=path.split('?')[0]||'/';let response
   try{response=await fetch(url+path,{...options,signal,redirect:'error'})}catch{
    throw new Error(`${signal.aborted?'EXPERIENCE_HTTP_TIMEOUT':'EXPERIENCE_HTTP_REQUEST_FAILED'} endpoint=${stage}`)
   }
   assert.equal(response.status,200,`EXPERIENCE_HTTP_STATUS endpoint=${stage}`)
   if(!json){await response.body?.cancel();return}
   try{return await response.json()}catch{
    throw new Error(`${signal.aborted?'EXPERIENCE_HTTP_TIMEOUT':'EXPERIENCE_HTTP_INVALID_JSON'} endpoint=${stage}`)
   }
  }
  await request('')
  const readyMs=Math.round(performance.now()-started)
  const session=await request('/api/native/session',{},true),headers={'content-type':'application/json','x-armorbreak-session':session.csrf}
  assert.equal(session.authentication,'NONE')
  const catalog=await request('/api/product/catalog',{headers},true);assert.equal(catalog.productVersion,manifest.version);assert.equal(catalog.hostConnection,'NOT_CONNECTED')
  const task=await request('/api/product/example',{method:'POST',headers,body:'{}'},true);assert.equal(task.state,'COMPLETED');assert.ok(task.evidenceIds.length)
  const report=await request('/api/product/report?taskId='+encodeURIComponent(task.taskId),{headers},true);assert.match(report.markdown,/任务状态：\*\*COMPLETED\*\*/)
  const result={schema:'armorbreak.windows-experience-acceptance/v1',commit:manifest.commit,version:manifest.version,entry:'ACTUAL_CMD_LAUNCH_INSTALLED_NODE_MODULES',readyMs,totalMs:Math.round(performance.now()-started),taskState:task.state,evidenceCount:task.evidenceIds.length,runtimeNode:catalog.runtimeObservation.process.node,nodePrerequisiteAlreadyInstalled:true,graphicalInstaller:'NOT_IMPLEMENTED',browserInteraction:'NOT_TESTED_BY_THIS_PROBE',dshCompatibility:'NOT_TESTED',productionIdentity:'NOT_VERIFIED'}
  return result
 }catch(error){failure=error;throw error}
 finally{
  try{await stopWindowsProbe(child,closed,system)}catch(error){
   if(!failure)throw error
   failure.message+=` (${error.message})`
  }
 }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const i=process.argv.indexOf('--root');if(i<0)throw new Error('--root is required')
 const root=resolve(process.argv[i+1]),result=await verifyWindowsExperience(root)
 if(process.argv.includes('--out'))writeFileSync(resolve(process.argv[process.argv.indexOf('--out')+1]),JSON.stringify(result,null,2)+'\n')
 console.log(JSON.stringify(result,null,2))
}
