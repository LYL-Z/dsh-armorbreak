/** Runs only in a new consumer directory, resolving the installed package by its public name. */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'
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
assert.equal(cli('capabilities').length, 61)
const npm=process.env.ARMORBREAK_ACCEPTANCE_NPM_CLI
assert.ok(npm)
assert.equal(JSON.parse(execFileSync(process.execPath,[npm,'exec','--offline','--no','--','armorbreak','capabilities','--json'],{env,encoding:'utf8',timeout:30000})).length,61)
const hash = cli('analyze','--capability','forensics.hash','--target',join(workspace,'inert.txt')); assert.equal(hash.state, 'COMPLETED')
const bundle = { schema: 'armorbreak.configuration-lab-request/v1', configuration: { schema: 'armorbreak.configuration-import/v1', format: 'yaml', source: 'value: old\r\nfuture: false\r\n' }, overlays: [{ id: 'inert', values: { value: 'new' } }], conflictPolicy: 'last-wins' }
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
  assert.equal((await hostCli(['revert','--lab',staged.lab,'--plan',staged.planId])).state,'ROLLED_BACK')
  assert.deepEqual(await readFile(join(staged.lab,'data/config.txt')),Buffer.from(bundle.configuration.source))
} finally { await rm(staged.lab,{recursive:true,force:true}) }
// Actual stdio child process, not an in-process protocol mock.
const child=spawn(process.execPath,[npm,'exec','--offline','--no','--','armorbreak-mcp'],{env,stdio:['pipe','pipe','pipe']})
let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b)
const exit=once(child,'exit'), timer=setTimeout(()=>child.kill(),30000)
child.stdin.end(JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-06-18'}})+'\n')
const [code]=await exit;clearTimeout(timer);assert.equal(code,0,err)
assert.equal(JSON.parse(out.trim()).result.protocolVersion,'2025-06-18')
const { createWorkbenchServer }=await import('dsh-armorbreak/workbench')
const server=await createWorkbenchServer({root,port:0,native:{workspaceId:workspace,stateRoot}})
try {assert.equal((await fetch(server.url)).status,200);const session=await(await fetch(server.url+'/api/native/session')).json();assert.equal(session.authentication,'NONE')} finally {await server.close()}
let pluginStore='NOT_DECLARED_IN_THIS_PACKAGE'
if(pkg.exports['./isolated-plugin-store']){
 const {ArmorBreakRuntime}=await import('dsh-armorbreak/core'),{createIndependentPluginReviewer,pluginAttestationPayload}=await import('dsh-armorbreak/plugin-lifecycle'),{planIsolatedPluginInstall}=await import('dsh-armorbreak/isolated-plugin-store')
 const runtime=new ArmorBreakRuntime({stateRoot:join(process.cwd(),'store-state')});await runtime.init()
 const target=join(workspace,'package');await mkdir(target)
 const task=await runtime.workspace(workspace).taskStore.create({title:'installed package quarantine acceptance',targetPath:target,steps:[]})
 const repository='https://github.com/example/self-authored-fixture',keys={source:generateKeyPairSync('ed25519'),rights:generateKeyPairSync('ed25519')}
 const reviewer=createIndependentPluginReviewer({roots:Object.keys(keys).map(role=>({keyId:role,authorityId:role+'-reviewer',role,repositories:[repository],publicKey:keys[role].publicKey.export({type:'spki',format:'pem'})}))})
 const canonical=v=>JSON.stringify(v,(_key,value)=>value&&typeof value==='object'&&!Array.isArray(value)?Object.fromEntries(Object.keys(value).sort().map(k=>[k,value[k]])):value)
 const {verifyPluginClosure}=await import(pathToFileURL(join(root,'lib/catalog/pluginPackage.js')).href)
 const fixture=async(version,bytes)=>{
  await writeFile(join(target,'inert.js'),bytes)
  await writeFile(join(target,'armorbreak-plugin.json'),JSON.stringify({schema:'armorbreak.plugin-catalog/v1',plugins:[{id:'inert',version,source:{repository,commit:(version==='1.0.0'?'a':'b').repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux'],channel:'stable',enabled:false,files:[{path:'inert.js',sha256:createHash('sha256').update(bytes).digest('hex')}]}]}))
  const candidate=await runtime.runner.buildCapabilityInput({task,capability:runtime.registry.get('plugin.verify'),targetPath:target,options:{closure:true},controller:new AbortController(),log:[]}),snapshot=await verifyPluginClosure(candidate),receipts={}
  for(const role of Object.keys(keys)){const payload=pluginAttestationPayload(snapshot,role);receipts[role+'Receipt']={keyId:role,payload,signature:sign(null,Buffer.from(canonical(payload)),keys[role].privateKey).toString('base64')}}
  return {candidate,receipts}
 }
 const stores=[],plan=async options=>{const x=await planIsolatedPluginInstall(runtime,{...options,reviewer,operator:'installed-store',sessionId:'installed-session'});stores.push(x.store);return x.store}
 try{
  const installed=await plan(await fixture('1.0.0','throw new Error("V1_NEVER_RUN")\r\n'));await installed.apply(dependencies.approvalProvider)
  const updated=await plan({...await fixture('2.0.0','throw new Error("V2_NEVER_RUN")\r\n'),operation:'update',current:installed});await updated.apply(dependencies.approvalProvider)
  assert.deepEqual(await updated.readInstalled('inert.js'),Buffer.from('throw new Error("V2_NEVER_RUN")\r\n'))
  const disabled=await plan({operation:'disable',current:updated});await disabled.apply(dependencies.approvalProvider);await assert.rejects(()=>disabled.readInstalled('inert.js'),/DISABLED/)
  await disabled.rollback(dependencies.approvalProvider);await updated.rollback(dependencies.approvalProvider)
  assert.deepEqual(await updated.readInstalled('inert.js'),Buffer.from('throw new Error("V1_NEVER_RUN")\r\n'))
  pluginStore='INSTALLED_PACKAGE_PHYSICAL_QUARANTINE_INSTALL_UPDATE_DISABLE_RESTORE'
 }finally{for(const store of stores)await rm(store.root,{recursive:true,force:true});await runtime.close()}
}
console.log(JSON.stringify({exports:imported,client:'MODULE_REGISTRATION_SIMULATED_DSH_NOT_TESTED',cli:'ACTUAL_CHILD_PROCESS',mcp:'ACTUAL_STDIO_CHILD_PROCESS',core:'ACTUAL_INSTALLED_RUNTIME',workbench:'ACTUAL_HTTP_OS_AUTHENTICATION_NONE',yaml:pkg.dependencies.yaml,configuration:'INSTALLED_APPROVED_SYNTHETIC_APPLY_AND_EXACT_RESTORE',pluginStore,privateKeyScan:'PASS',runtimeVersion:pkg.version}))
