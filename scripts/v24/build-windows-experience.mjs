#!/usr/bin/env node
/** Assemble a local Windows experience from a verified installed TGZ, never a development checkout. */
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync, readdirSync, lstatSync, copyFileSync, existsSync } from 'node:fs'
import { join, resolve, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildPreviewMetadata } from './preview-metadata.mjs'
const hash=bytes=>createHash('sha256').update(bytes).digest('hex')
export function buildWindowsExperience({validationRoot,outputRoot}){
 if(existsSync(outputRoot))throw new Error('REFUSE_EXISTING_OUTPUT')
 const report=JSON.parse(readFileSync(join(validationRoot,'validation.json'),'utf8'))
 if(report.environment?.platform!=='win32')throw new Error('WINDOWS_PACKAGE_VALIDATION_REQUIRED')
 // Validates actual TGZ digest, committed source/installed file equality,
 // root version, complete direct dependency lock and installed license texts.
 const record=buildPreviewMetadata({validationRoot,outputRoot:join(outputRoot,'verification')})
 const files=[]
 function copy(source,target,path){
  const stat=lstatSync(source)
  if(stat.isSymbolicLink()||stat.nlink>1&&!stat.isDirectory())throw new Error('EXPERIENCE_LINK_DENIED')
  if(stat.isDirectory()){mkdirSync(target,{recursive:true});for(const name of readdirSync(source).sort())copy(join(source,name),join(target,name),path+'/'+name);return}
  if(!stat.isFile()||stat.size>64*1024*1024||files.length>=5000)throw new Error('EXPERIENCE_FILE_LIMIT')
  const bytes=readFileSync(source)
  if(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]/.test(bytes.toString('utf8')))throw new Error('EXPERIENCE_PRIVATE_KEY_DENIED')
  copyFileSync(source,target);if(hash(readFileSync(target))!==hash(bytes))throw new Error('EXPERIENCE_COPY_DRIFT')
  files.push({path,bytes:bytes.length,sha256:hash(bytes)})
 }
 const modules=join(validationRoot,'consumer/node_modules')
 for(const name of ['dsh-armorbreak','typescript','yaml'])copy(join(modules,name),join(outputRoot,'app/node_modules',name),'app/node_modules/'+name)
 mkdirSync(join(outputRoot,'workspace'));writeFileSync(join(outputRoot,'workspace/README.txt'),'Place a COPY of files or a project you want to inspect in this folder.\r\nArmorBreak performs offline read-only checks. Do not place secrets here.\r\n')
 const launcher=`@echo off
setlocal
chcp 65001 >nul
set "AB_NODE=%ProgramFiles%\\nodejs\\node.exe"
if exist "%AB_NODE%" goto node_found
set "AB_NODE="
for /f "delims=" %%N in ('"%SystemRoot%\\System32\\where.exe" node.exe 2^>nul') do if not defined AB_NODE set "AB_NODE=%%N"
if defined AB_NODE goto node_found
echo Node.js 22 or newer is required. Install the official Node.js LTS, then try again.
echo https://nodejs.org/en/download
pause
exit /b 2
:node_found
"%AB_NODE%" -e "if(Number(process.versions.node.split('.')[0])<22){console.error('Node.js 22 or newer is required.');process.exit(2)}"
if errorlevel 1 goto failed
set "AB_EXTRA="
if "%~1"=="--no-open" set "AB_EXTRA=--no-open"
if not "%~1"=="" if not "%~1"=="--no-open" goto failed
echo ArmorBreak ${record.version} - offline development Preview
echo Keep this window open. Press Ctrl+C to stop the local service.
echo DSH is not connected. No privileged approval or host installation is available.
"%AB_NODE%" "%~dp0app\\node_modules\\dsh-armorbreak\\packages\\cli\\index.js" start --workspace "%~dp0workspace" --state-root "%~dp0state" %AB_EXTRA%
if errorlevel 1 goto failed
exit /b 0
:failed
echo Startup failed. Check the message above. No administrator permission is required.
pause
exit /b 1
`
 writeFileSync(join(outputRoot,'Start ArmorBreak.cmd'),launcher.replace(/\r?\n/g,'\r\n'),'utf8')
 writeFileSync(join(outputRoot,'README.txt'),`ArmorBreak ${record.version} - Windows development Preview\r\n\r\n1. Extract this entire folder to a user-writable location.\r\n2. Double-click "Start ArmorBreak.cmd". Requires an existing official Node.js 22+ installation; Node is not bundled. No npm command or administrator elevation is needed.\r\n3. The browser opens the local Workbench. Run the safe example first.\r\n4. Put COPIES of your files/projects into workspace, then choose a check and a relative path.\r\n5. View results and download the actual report. Keep the console open until finished; Ctrl+C stops it.\r\n\r\nThe app, dependency files, original TGZ, licenses and build record are included. Startup does not install anything globally or contact a model provider. Initial app dependencies are already present; Node installation is a separate prerequisite.\r\nState is stored in this folder's state directory. Keep it when upgrading. Do not overwrite an existing folder or delete your work to uninstall; stop the service and preserve workspace/state before removing the app. No automatic upgrade or user-data deletion is implemented.\r\n\r\nBoundaries: CSRF_ONLY local HTTP, not OS authentication. No production keys, L2 writes, approval signing or DSH modification. Real DSH integration and a full novice-user study are NOT_TESTED. This is not v2.4 Stable or full migration.\r\nSource commit: ${record.commit}\r\nTGZ SHA-256: ${record.artifact.sha256}\r\n`,'utf8')
 // Include launchers, instructions and verification material, not only modules.
 const recorded=new Set(files.map(f=>f.path))
 function extra(directory){for(const name of readdirSync(directory).sort()){
  const path=join(directory,name),stat=lstatSync(path),rel=relative(outputRoot,path).split(sep).join('/')
  if(stat.isDirectory())extra(path)
  else if(!recorded.has(rel)){const bytes=readFileSync(path);files.push({path:rel,bytes:bytes.length,sha256:hash(bytes)})}
 }}
 extra(outputRoot);files.sort((a,b)=>a.path.localeCompare(b.path))
 const manifest={schema:'armorbreak.windows-experience/v1',version:record.version,commit:record.commit,artifact:record.artifact,platform:'win32',nodeBundled:false,nodeMinimumMajor:22,activationAuthorized:false,hostWrites:false,osClientAuthentication:false,fullMigrationComplete:false,fileManifestSelfExcluded:true,files}
 writeFileSync(join(outputRoot,'experience-files.json'),JSON.stringify(manifest,null,2)+'\n')
 return manifest
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const arg=k=>process.argv[process.argv.indexOf(k)+1]
 if(!process.argv.includes('--validation')||!process.argv.includes('--out'))throw new Error('--validation and --out are required')
 const result=buildWindowsExperience({validationRoot:resolve(arg('--validation')),outputRoot:resolve(arg('--out'))})
 console.log(JSON.stringify({version:result.version,commit:result.commit,files:result.files.length,nodeBundled:result.nodeBundled,outputRoot:resolve(arg('--out'))},null,2))
}
