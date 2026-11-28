/** Runs only in a new consumer directory, resolving the installed package by its public name. */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'
import { createInterface } from 'node:readline'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join, dirname, relative, isAbsolute } from 'node:path'
import { pathToFileURL } from 'node:url'
const require = createRequire(import.meta.url)
const pkg = require('dsh-armorbreak/package.json'), root = dirname(require.resolve('dsh-armorbreak/package.json'))
const insideConsumer = path => { const rel = relative(process.cwd(),path); assert.ok(rel && !isAbsolute(rel) && rel !== '..' && !rel.startsWith('../') && !rel.startsWith('..\\')) }
insideConsumer(root)
const imported = []
let clientRegistration
globalThis.window = { __ModuleLoader__: { load(value) { clientRegistration = value } } }
for (const [name, path] of Object.entries(pkg.exports)) {
  if (name.includes('*')) {
    for (const locale of ['en','zh']) { const value = require(`dsh-armorbreak/locale/${locale}.json`); assert.equal(typeof value, 'object'); imported.push(`./locale/${locale}.json`) }
  } else if (path.endsWith('.json')) { require(name === '.' ? pkg.name : pkg.name + name.slice(1)); imported.push(name) }
  else if (path.endsWith('.svg')) { assert.match(await readFile(join(root, path), 'utf8'), /<svg/); imported.push(name + ':asset-read') }
  else { await import(name === '.' ? pkg.name : pkg.name + name.slice(1)); imported.push(name) }
}
assert.equal(clientRegistration.id, 'dsh-armorbreak'); delete globalThis.window
const shrinkwrap = JSON.parse(await readFile(join(root, 'npm-shrinkwrap.json'), 'utf8'))
for (const [name, version] of Object.entries(pkg.dependencies)) {
  const path=require.resolve(name + '/package.json');insideConsumer(path)
  const installed = JSON.parse(await readFile(path, 'utf8'))
  assert.equal(installed.version, version); assert.equal(shrinkwrap.packages['node_modules/' + name].version, version)
}
const workspace = join(process.cwd(), 'workspace'), stateRoot = join(process.cwd(), 'state')
await mkdir(workspace)
await writeFile(join(workspace, 'inert.txt'), 'package acceptance fixture\n')
const env = { ...process.env, ARMORBREAK_WORKSPACE: workspace, ARMORBREAK_STATE_ROOT: stateRoot, ARMORBREAK_PRINCIPAL_ID: 'installed-test' }
const cli = (...args) => JSON.parse(execFileSync(process.execPath, [join(root, pkg.bin.armorbreak), ...args, '--json'], { env, encoding: 'utf8', timeout: 30000 }))
assert.equal(cli('capabilities').length, 63)
assert.equal(cli('doctor').version,pkg.version)
const npm=process.env.ARMORBREAK_ACCEPTANCE_NPM_CLI
assert.ok(npm)
assert.equal(JSON.parse(execFileSync(process.execPath,[npm,'exec','--offline','--no','--','armorbreak','capabilities','--json'],{env,encoding:'utf8',timeout:30000})).length,63)
const hash = cli('analyze','--capability','forensics.hash','--target',join(workspace,'inert.txt')); assert.equal(hash.state, 'COMPLETED')
const combined=cli('workflow','start','--workflow','ForensicFileReview','--target',join(workspace,'inert.txt'));assert.equal(combined.state,'COMPLETED');assert.equal(combined.data.steps.length,6);assert.ok(combined.data.steps.every(s=>s.status==='DONE'))
const bundle = { schema: 'armorbreak.configuration-lab-request/v1', configuration: { schema: 'armorbreak.configuration-import/v1', format: 'yaml', source: '# installed YAML comment\r\nvalue: "old" # preserve this note\r\nfuture: false\r\n' }, overlays: [{ id: 'inert', values: { value: 'new' } }], conflictPolicy: 'last-wins' }
const requestPath = join(workspace,'request.json'); await writeFile(requestPath,JSON.stringify(bundle))
const convertPath = join(workspace,'convert.json'); await writeFile(convertPath,JSON.stringify(bundle.configuration))
assert.equal(cli('config','convert','--bundle',convertPath).state,'COMPLETED')
const { runCli } = await import('dsh-armorbreak/cli')
const dependencies = { env, agent: 'installed-test', callId: 'installed-test', sessionId: 'installed-session', approvalProvider: { request: async () => 'allowed-once' } }
async function hostCli(args) { let output=''; const write=process.stdout.write; process.stdout.write=function(chunk){output+=chunk;return true}; try { await runCli(['config',...args,'--json'],dependencies); return JSON.parse(output) } finally {process.stdout.write=write} }
const staged=await hostCli(['stage','--bundle',requestPath])
try {
  assert.equal((await hostCli(['apply','--lab',staged.lab,'--plan',staged.planId])).state,'COMMITTED')
  assert.match(await readFile(join(staged.lab,'data/config.txt'),'utf8'),/new/)
  assert.match(await readFile(join(staged.lab,'data/config.txt'),'utf8'),/# installed YAML comment\r\nvalue: "new" # preserve this note/)
  assert.equal((await hostCli(['revert','--lab',staged.lab,'--plan',staged.planId])).state,'ROLLED_BACK')
  assert.deepEqual(await readFile(join(staged.lab,'data/config.txt')),Buffer.from(bundle.configuration.source))
} finally { await rm(staged.lab,{recursive:true,force:true}) }
// Actual stdio child process, not an in-process protocol mock.
const child=spawn(process.execPath,[npm,'exec','--offline','--no','--','armorbreak-mcp'],{env,stdio:['pipe','pipe','pipe']})
let err='',nextId=0;child.stderr.on('data',b=>err+=b)
const exit=once(child,'exit'), timer=setTimeout(()=>child.kill(),30000)
const frames=createInterface({input:child.stdout}),pending=new Map()
frames.on('line',line=>{try{const frame=JSON.parse(line),callback=pending.get(frame.id);if(callback){pending.delete(frame.id);callback(frame)}}catch{child.kill()}})
const rpc=(method,params)=>new Promise((resolve,reject)=>{
 const id=++nextId;pending.set(id,response=>response.error?reject(new Error(JSON.stringify(response.error))):resolve(response.result))
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n')
})
child.once('exit',()=>{for(const callback of pending.values())callback({error:'MCP_CHILD_EXITED'});pending.clear()})
const tool=async(name,args={})=>{const result=await rpc('tools/call',{name,arguments:args});assert.equal(result.isError,false,JSON.stringify(result));return JSON.parse(result.content[0].text)}
try{
 assert.equal((await rpc('initialize',{protocolVersion:'2025-06-18'})).protocolVersion,'2025-06-18')
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n')
 assert.ok((await rpc('tools/list',{})).tools.some(t=>t.name==='armorbreak_analyze'))
 const health=await tool('armorbreak_health');assert.equal(health.version,pkg.version)
 assert.ok(health.runtimeObservation.process.pid>0);assert.equal(health.runtimeObservation.scope,'SELF_PROCESS_ONLY')
 assert.ok(health.runtimeObservation.adapters.some(a=>a.kind==='MCP_STDIO'&&a.state==='INITIALIZED'))
 const analyzed=await tool('armorbreak_analyze',{capability:'forensics.hash',target:join(workspace,'inert.txt')})
 assert.equal(analyzed.state,'COMPLETED');assert.equal(analyzed.data.digests.sha256,createHash('sha256').update('package acceptance fixture\n').digest('hex'))
 assert.ok((await tool('armorbreak_evidence',{taskId:analyzed.taskId})).evidence.length)
 assert.match((await tool('armorbreak_report',{taskId:analyzed.taskId})).markdown,/任务状态：\*\*COMPLETED\*\*/)
 const multi=await tool('armorbreak_workflow',{action:'start',workflow:'ForensicFileReview',target:join(workspace,'inert.txt')});assert.equal(multi.state,'COMPLETED');assert.equal(multi.data.steps.length,6)
 assert.match((await tool('armorbreak_report',{taskId:multi.taskId})).markdown,/任务状态：\*\*COMPLETED\*\*/)
 assert.ok((await tool('armorbreak_health')).runtimeObservation.adapters.some(a=>a.kind==='MCP_STDIO'&&a.successfulCalls>=4))
 const refused=await rpc('tools/call',{name:'armorbreak_analyze',arguments:{capability:'forensics.hash',target:join(process.cwd(),'package.json')}})
 assert.equal(refused.isError,true)
 child.stdin.end();const [code]=await exit;assert.equal(code,0,err)
}finally{clearTimeout(timer);frames.close();if(child.exitCode===null)child.kill()}
const { createWorkbenchServer }=await import('dsh-armorbreak/workbench')
const server=await createWorkbenchServer({root,port:0,native:{workspaceId:workspace,stateRoot}})
try {
 assert.equal((await fetch(server.url)).status,200);const session=await(await fetch(server.url+'/api/native/session')).json();assert.equal(session.authentication,'NONE')
 const headers={'content-type':'application/json','x-armorbreak-session':session.csrf}
 const catalog=await(await fetch(server.url+'/api/product/catalog',{headers})).json();assert.ok(catalog.actions.some(a=>a.id==='file-integrity'))
 const result=await(await fetch(server.url+'/api/product/example',{method:'POST',headers,body:'{}'})).json();assert.equal(result.state,'COMPLETED');assert.ok(result.evidenceIds.length)
 const report=await(await fetch(server.url+'/api/product/report?taskId='+result.taskId,{headers})).json();assert.match(report.markdown,/任务状态：\*\*COMPLETED\*\*/)
 const multi=await(await fetch(server.url+'/api/product/run',{method:'POST',headers,body:JSON.stringify({action:'file-review',target:'inert.txt'})})).json();assert.equal(multi.state,'COMPLETED');assert.equal(multi.data.steps.length,6);assert.ok(multi.reportAvailable)
 const runDiagnostic=async(action,target)=>{const response=await fetch(server.url+'/api/product/run',{method:'POST',headers,body:JSON.stringify({action,target})});assert.equal(response.status,200);const result=await response.json();assert.equal(result.state,'COMPLETED');assert.ok(result.reportAvailable&&result.evidenceIds.length);return result.data}
 const hostDir=join(workspace,'diagnostic-resources','app','dsh','node_modules','@deepseek-ai','dsh-desktop-host');await mkdir(hostDir,{recursive:true});await writeFile(join(hostDir,'package.json'),JSON.stringify({name:'@deepseek-ai/dsh-desktop-host',version:'1.2.3'}))
 const host=await runDiagnostic('host-health','diagnostic-resources');assert.equal(host.observation,'DETECTED_ON_DISK');assert.equal(host.runtime,'UNKNOWN')
 const pluginDir=join(workspace,'diagnostic-plugin');await mkdir(pluginDir);await writeFile(join(pluginDir,'inert.txt'),'diagnostic inert bytes')
 await writeFile(join(pluginDir,'armorbreak-plugin.json'),JSON.stringify({schema:'armorbreak.plugin-catalog/v1',plugins:[{id:'diagnostic',version:'1.0.0',source:{repository:'https://github.com/example/inert',commit:'a'.repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux','darwin'],channel:'stable',enabled:false,files:[{path:'inert.txt',sha256:createHash('sha256').update('diagnostic inert bytes').digest('hex')}]}]}))
 const plugin=await runDiagnostic('plugin-closure','diagnostic-plugin');assert.equal(plugin.verificationStatus,'LOCAL_PACKAGE_CLOSURE_VERIFIED');assert.equal(plugin.plugins[0].activationAuthorized,false)
 await writeFile(join(workspace,'diagnostic-overlay.json'),JSON.stringify({schema:'armorbreak.config-overlay/v1',base:{apiPin:'TEST_PRIVATE_VALUE'},overlays:[]}))
 const config=await runDiagnostic('configuration-preview','diagnostic-overlay.json');assert.equal(config.applied,false);assert.doesNotMatch(JSON.stringify(config),/apiPin|TEST_PRIVATE_VALUE/)
 const backup=join(workspace,'backup-copy','backups','2026-11-26T120000Z-abcd');await mkdir(backup,{recursive:true});await writeFile(join(backup,'manifest.json'),'{"complete":true}')
 const usage=await runDiagnostic('backup-usage','backup-copy');assert.equal(usage.count,1);assert.equal(usage.bytes,17);assert.equal(usage.restoreVerified,false)
 const snapshotId='2026-11-26T120000Z-abcd',backupRoot=join(workspace,'backup-copy'),manifest=join(backup,'manifest.json')
 const bytes='installed backup fixture',digest=createHash('sha256').update(bytes).digest('hex')
 await mkdir(join(backupRoot,'objects'))
 await writeFile(join(backup,'document.txt'),bytes)
 await writeFile(join(backupRoot,'objects',digest),bytes)
 await writeFile(manifest,JSON.stringify({schema:2,id:snapshotId,complete:true,sums:{'document.txt':digest},blobs:{'object-only.txt':digest}}))
 const verification=cli('maintenance','verify-snapshot','--root',backupRoot,'--snapshot',snapshotId)
 assert.equal(verification.state,'COMPLETED');assert.equal(verification.data.status,'DECLARED_CONTENT_MATCH');assert.equal(verification.data.referencedObjects,1);assert.equal(verification.data.restoreVerified,false)
 const installedBrowserApi=await fetch(server.url+'/api/product/run',{method:'POST',headers,body:JSON.stringify({action:'backup-usage',target:'backup-copy',snapshotId})})
 assert.equal(installedBrowserApi.status,200)
 const snapshotResult=await installedBrowserApi.json()
 assert.equal(snapshotResult.data.status,'DECLARED_CONTENT_MATCH')
 assert.equal(snapshotResult.data.restoreVerified,false)
 assert.ok(snapshotResult.reportAvailable&&snapshotResult.evidenceIds.length)
} finally {await server.close()}
let pluginStore='NOT_DECLARED_IN_THIS_PACKAGE'
if(pkg.exports['./isolated-plugin-store']){
 const {ArmorBreakRuntime}=await import('dsh-armorbreak/core'),{createIndependentPluginReviewer,pluginAttestationPayload}=await import('dsh-armorbreak/plugin-lifecycle'),{planIsolatedPluginInstall}=await import('dsh-armorbreak/isolated-plugin-store')
 const runtime=new ArmorBreakRuntime({stateRoot:join(process.cwd(),'store-state')});await runtime.init()
 const target=join(workspace,'package');await mkdir(target)
 const task=await runtime.workspace(workspace).taskStore.create({title:'installed package quarantine acceptance',targetPath:target,steps:[]})
 const repository='https://github.com/example/self-authored-fixture',keys={source:generateKeyPairSync('ed25519'),rights:generateKeyPairSync('ed25519')}
 const reviewer=createIndependentPluginReviewer({roots:Object.keys(keys).map(role=>({keyId:role,authorityId:role+'-reviewer',role,repositories:[repository],publicKey:keys[role].publicKey.export({type:'spki',format:'pem'})}))})
 const canonical=v=>JSON.stringify(v,(_key,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.keys(value).sort().map(k=>[k,value[k]])):value)
 let durableReviewer,durablePolicyKey
 if(pkg.exports['./plugin-trust-store']){
  const {createPersistentPluginReviewer}=await import('dsh-armorbreak/plugin-trust-store'),issuer=generateKeyPairSync('ed25519')
  const payload={schema:'armorbreak.plugin-trust-policy/v1',policyId:'installed-synthetic-policy',version:1,notBefore:Date.now()-60000,expiresAt:Date.now()+600000,roots:Object.keys(keys).map(role=>({keyId:role,authorityId:role+'-reviewer',role,repositories:[repository],publicKey:keys[role].publicKey.export({type:'spki',format:'pem'})}))}
  durablePolicyKey=issuer.publicKey.export({type:'spki',format:'pem'})
  durableReviewer=createPersistentPluginReviewer({directory:join(process.cwd(),'installed-trust'),policyPublicKey:issuer.publicKey.export({type:'spki',format:'pem'}),policy:{payload,signature:sign(null,Buffer.from(canonical(payload)),issuer.privateKey).toString('base64')}})
 }
 const {verifyPluginClosure}=await import(pathToFileURL(join(root,'lib/catalog/pluginPackage.js')).href)
 const fixture=async(version,bytes)=>{
  await writeFile(join(target,'inert.js'),bytes)
  await writeFile(join(target,'armorbreak-plugin.json'),JSON.stringify({schema:'armorbreak.plugin-catalog/v1',plugins:[{id:'inert',version,source:{repository,commit:(version==='1.0.0'?'a':'b').repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux'],channel:'stable',enabled:false,files:[{path:'inert.js',sha256:createHash('sha256').update(bytes).digest('hex')}]}]}))
  const candidate=await runtime.runner.buildCapabilityInput({task,capability:runtime.registry.get('plugin.verify'),targetPath:target,options:{closure:true},controller:new AbortController(),log:[]}),snapshot=await verifyPluginClosure(candidate),receipts={}
  for(const role of Object.keys(keys)){const payload=pluginAttestationPayload(snapshot,role);receipts[role+'Receipt']={keyId:role,payload,signature:sign(null,Buffer.from(canonical(payload)),keys[role].privateKey).toString('base64')}}
  return {candidate,receipts}
 }
 const stores=[],plan=async options=>{const x=await planIsolatedPluginInstall(runtime,{...options,reviewer:durableReviewer??reviewer,operator:'installed-store',sessionId:'installed-session'});stores.push(x.store);return x.store}
 try{
  const installed=await plan(await fixture('1.0.0','throw new Error("V1_NEVER_RUN")\r\n'));await installed.apply(dependencies.approvalProvider)
  const updated=await plan({...await fixture('2.0.0','throw new Error("V2_NEVER_RUN")\r\n'),operation:'update',current:installed});await updated.apply(dependencies.approvalProvider)
  assert.deepEqual(await updated.readInstalled('inert.js'),Buffer.from('throw new Error("V2_NEVER_RUN")\r\n'))
  const disabled=await plan({operation:'disable',current:updated});await disabled.apply(dependencies.approvalProvider);await assert.rejects(()=>disabled.readInstalled('inert.js'),/DISABLED/)
  await assert.rejects(()=>disabled.copySelected(),/DISABLED/)
  const reenabled=await plan({operation:'enable',current:disabled});await assert.rejects(()=>reenabled.copySelected(),/TRANSACTION_NOT_FINAL/)
  await reenabled.apply(dependencies.approvalProvider);assert.equal((await reenabled.inspect()).activationAuthorized,false)
  assert.deepEqual(await reenabled.readInstalled('inert.js'),Buffer.from('throw new Error("V2_NEVER_RUN")\r\n'))
  await reenabled.rollback(dependencies.approvalProvider);await assert.rejects(()=>reenabled.copySelected(),/DISABLED/)
  await disabled.rollback(dependencies.approvalProvider);await updated.rollback(dependencies.approvalProvider)
  assert.deepEqual(await updated.readInstalled('inert.js'),Buffer.from('throw new Error("V1_NEVER_RUN")\r\n'))
  const removed=await plan({operation:'uninstall',current:updated});await removed.apply(dependencies.approvalProvider)
  assert.equal((await removed.inspect()).state.status,'NOT_INSTALLED');await assert.rejects(()=>removed.copySelected(),/NOT_INSTALLED/)
  await removed.rollback(dependencies.approvalProvider);assert.deepEqual(await removed.readInstalled('inert.js'),Buffer.from('throw new Error("V1_NEVER_RUN")\r\n'))
  const activeReviewer=durableReviewer??reviewer;activeReviewer.revokeKey('source');await assert.rejects(()=>updated.copySelected(),/DISABLED_OR_UNTRUSTED/)
  if(durableReviewer){const {openPersistentPluginReviewer}=await import('dsh-armorbreak/plugin-trust-store');assert.ok(durableReviewer.checkpoint().sequence>=2);assert.ok(openPersistentPluginReviewer({directory:join(process.cwd(),'installed-trust'),policyPublicKey:durablePolicyKey}).exportRevocations().keys.includes('source'))}
  pluginStore='INSTALLED_PACKAGE_PHYSICAL_QUARANTINE_INSTALL_UPDATE_DISABLE_REENABLE_UNINSTALL_RESTORE'
 }finally{for(const store of stores)await rm(store.root,{recursive:true,force:true});await runtime.close?.()}
}
let backupRecovery = 'NOT_DECLARED_IN_THIS_PACKAGE'
if (pkg.exports['./backup-recovery-lab']) {
  const { ArmorBreakRuntime } = await import('dsh-armorbreak/core')
  const { planSyntheticBackupRecovery } = await import('dsh-armorbreak/backup-recovery-lab')
  const runtime = new ArmorBreakRuntime({ stateRoot: join(process.cwd(), 'backup-test-state') })
  const snapshotId = '2026-11-26T120000Z-abcd'
  const original = Buffer.from([0, 255, 13, 10])
  const digest = createHash('sha256').update(original).digest('hex')
  const { lab, plan } = await planSyntheticBackupRecovery(runtime, {
    operator: 'installed-probe', sessionId: 'installed-backup-test', snapshotId,
    manifestJson: JSON.stringify({ schema: 2, id: snapshotId, complete: true, sums: {}, blobs: { 'test.txt': digest } }),
    inline: {}, objects: { [digest]: original }, seeds: { 'test.txt': 'seed\r\n' },
  })
  try {
    const provider = { request: async () => 'allowed-once' }
    assert.equal((await lab.apply(plan.planId, provider)).state, 'COMMITTED')
    assert.deepEqual(await readFile(join(lab.data, 'test.txt')), original)
    assert.equal((await lab.rollback(plan.planId, provider)).state, 'ROLLED_BACK')
    assert.equal(await readFile(join(lab.data, 'test.txt'), 'utf8'), 'seed\r\n')
    backupRecovery = 'INSTALLED_APPROVED_SYNTHETIC_RESTORE_AND_EXACT_ROLLBACK'
  } finally {
    await rm(lab.root, { recursive: true, force: true })
    await runtime.close?.()
  }
}
console.log(JSON.stringify({exports:imported,client:'MODULE_REGISTRATION_SIMULATED_DSH_NOT_TESTED',cli:'ACTUAL_CHILD_PROCESS',mcp:'ACTUAL_STDIO_CHILD_PROCESS',core:'ACTUAL_INSTALLED_RUNTIME',workbench:'ACTUAL_HTTP_OS_AUTHENTICATION_NONE',yaml:pkg.dependencies.yaml,configuration:'INSTALLED_APPROVED_SYNTHETIC_APPLY_AND_EXACT_RESTORE',pluginStore,backupRecovery,privateKeyScan:'PASS',runtimeVersion:pkg.version}))
