import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign, createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, readFile, rm, link, rename, symlink } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
import { createIndependentPluginReviewer, createPluginReviewer, pluginAttestationPayload } from '../lib/catalog/pluginLifecycle.js'
import { verifyPluginClosure } from '../lib/catalog/pluginPackage.js'
import { canonicalConfig } from '../lib/integrations/configOverlay.js'
import { planIsolatedPluginInstall, reopenIsolatedPluginInstall } from '../packages/core/src/isolatedPluginStore.js'
const approved={request:async()=> 'allowed-once'},context={operator:'quarantine-owner',sessionId:'quarantine-session'}
const repository='https://github.com/example/self-authored-fixture',sha=b=>createHash('sha256').update(b).digest('hex')
async function setup(t){
 const root=await mkdtemp(join(tmpdir(),'ab-plugin-store-r3-')),workspace=join(root,'workspace'),target=join(workspace,'candidate')
 await mkdir(join(target,'assets'),{recursive:true});t.after(()=>rm(root,{recursive:true,force:true}))
 const runtime=new ArmorBreakRuntime({stateRoot:join(root,'state')});await runtime.init()
 const task=await runtime.workspace(workspace).taskStore.create({title:'quarantine fixture',targetPath:target,steps:[]})
 const keys={source:generateKeyPairSync('ed25519'),rights:generateKeyPairSync('ed25519')}
 const roots=Object.keys(keys).map(role=>({keyId:role,role,authorityId:role+'-reviewer',repositories:[repository],publicKey:keys[role].publicKey.export({type:'spki',format:'pem'})}))
 const reviewer=createIndependentPluginReviewer({roots})
 async function candidate(version='1.0.0',text='throw new Error("MUST_NOT_EXECUTE_V1")\r\n'){
  const data='{ "inert": true }\r\n';await writeFile(join(target,'inert.js'),text);await writeFile(join(target,'assets/settings.json'),data)
  const dependent='throw new Error("DEPENDENT_MUST_NOT_EXECUTE")\n';await writeFile(join(target,'dependent.js'),dependent)
  const main={id:'inert',version,source:{repository,commit:(version[0]==='1'?'a':'b').repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux'],channel:'stable',enabled:false,files:[{path:'inert.js',sha256:sha(text)},{path:'assets/settings.json',sha256:sha(data)}]}
  await writeFile(join(target,'armorbreak-plugin.json'),JSON.stringify({schema:'armorbreak.plugin-catalog/v1',plugins:[main,{...main,id:'dependent',dependencies:[{id:'inert',version}],files:[{path:'dependent.js',sha256:sha(dependent)}]}]}))
  const input=await runtime.runner.buildCapabilityInput({task,capability:runtime.registry.get('plugin.verify'),targetPath:target,options:{closure:true},controller:new AbortController(),log:[]})
  const snapshot=await verifyPluginClosure(input),receipts={}
  for(const role of Object.keys(keys)){const payload=pluginAttestationPayload(snapshot,role);receipts[role+'Receipt']={keyId:role,payload,signature:sign(null,Buffer.from(canonicalConfig(payload)),keys[role].privateKey).toString('base64')}}
  return {candidate:input,receipts,text}
 }
 async function plan(options){const {text,...input}=options;const result=await planIsolatedPluginInstall(runtime,{...context,reviewer,...input});t.after(()=>rm(result.store.root,{recursive:true,force:true}));return result.store}
 return {root,target,runtime,reviewer,roots,candidate,plan}
}
test('actual quarantine files install, update, disable and independently restore without executing JS',async t=>{
 const f=await setup(t),v1=await f.candidate(),installed=await f.plan(v1)
 await assert.rejects(()=>installed.readInstalled('inert.js'),/DISABLED_OR_UNTRUSTED/)
 await assert.rejects(()=>installed.apply(),/PROVIDER_REQUIRED/)
 await assert.rejects(()=>installed.apply({request:async()=> 'denied'}),/APPROVAL_DENIED/)
 assert.equal((await installed.apply(approved)).state.status,'INSTALLED_QUARANTINED')
 assert.deepEqual((await installed.inspect()).dependencyOrder,['inert','dependent'])
 assert.match((await installed.readInstalled('dependent.js')).toString(),/DEPENDENT_MUST_NOT_EXECUTE/)
 assert.deepEqual(await installed.readInstalled('inert.js'),Buffer.from(v1.text))
 const v2=await f.candidate('2.0.0','throw new Error("MUST_NOT_EXECUTE_V2")\r\n'),updated=await f.plan({...v2,current:installed,operation:'update'})
 await updated.apply(approved);assert.deepEqual(await updated.readInstalled('inert.js'),Buffer.from(v2.text))
 const current=await updated.inspect(),physical=join(updated.root,'control/payloads',current.state.closure,'inert.js')
 assert.deepEqual(await readFile(physical),Buffer.from(v2.text))
 const disabled=await f.plan({current:updated,operation:'disable'});await disabled.apply(approved)
 assert.equal((await disabled.inspect()).state.status,'DISABLED');await assert.rejects(()=>disabled.readInstalled('inert.js'),/DISABLED_OR_UNTRUSTED/)
 await disabled.rollback(approved);assert.deepEqual(await disabled.readInstalled('inert.js'),Buffer.from(v2.text))
 await updated.rollback(approved);assert.deepEqual(await updated.readInstalled('inert.js'),Buffer.from(v1.text))
 assert.equal((await updated.inspect()).activationAuthorized,false)
 await installed.rollback(approved);assert.equal((await installed.inspect()).state.status,'NOT_INSTALLED')
 assert.deepEqual(await readFile(join(f.target,'inert.js')),Buffer.from(v2.text))
})
test('revocation after planning and during host approval blocks the selector write',async t=>{
 for(const when of ['planned','during-approval']){
  const f=await setup(t),store=await f.plan(await f.candidate())
  if(when==='planned')f.reviewer.revokeKey('source')
  const provider=when==='during-approval'?{request:async()=>{f.reviewer.revokeAuthority('rights-reviewer');return 'allowed-once'}}:approved
  await assert.rejects(()=>store.apply(provider),/REVIEW_REVOKED_OR_DENIED/)
  assert.equal((await store.inspect()).state.status,'NOT_INSTALLED')
 }
})
test('existing destinations, legacy same-signer reviewer, foreign sessions and unknown paths are refused',async t=>{
 const f=await setup(t),input=await f.candidate()
 await assert.rejects(()=>f.plan({...input,destination:f.target}),/OPERATION_INVALID/)
 await assert.rejects(()=>f.plan({...input,reviewer:createPluginReviewer(f.roots)}),/INDEPENDENT_REVIEWER_REQUIRED/)
 const store=await f.plan(input);await store.apply(approved)
 await assert.rejects(()=>store.readInstalled('../outside'),/maintenance relative path/)
 await assert.rejects(()=>store.readInstalled('unlisted.js'),/PATH_DENIED/)
 await assert.rejects(()=>reopenIsolatedPluginInstall(f.runtime,store.root,{...context,sessionId:'foreign',reviewer:f.reviewer}),/CONTEXT_BINDING/)
})
test('payload drift, extra files, hardlinks and directory junctions block store use',async t=>{
 const f=await setup(t),input=await f.candidate(),store=await f.plan(input);await store.apply(approved)
 const info=await store.inspect(),base=join(store.root,'control/payloads',info.state.closure),file=join(base,'inert.js')
 await writeFile(file,'unknown');await assert.rejects(()=>store.inspect(),/CONTENT_DRIFT/);await writeFile(file,input.text)
 await writeFile(join(base,'extra.txt'),'extra');await assert.rejects(()=>store.inspect(),/MEMBERS_DRIFT/);await rm(join(base,'extra.txt'))
 const extra=join(store.root,'control/hardlink');await link(file,extra);await assert.rejects(()=>store.inspect(),/FILE_DRIFT/);await rm(extra)
 const moved=join(store.root,'saved-payloads'),original=join(store.root,'control/payloads');await rename(original,moved)
 await symlink(moved,original,process.platform==='win32'?'junction':'dir');await assert.rejects(()=>store.inspect(),/DIRECTORY_DRIFT/)
 await rm(original);await rename(moved,original)
})
test('post-selector failure reopens with sealed identities and restores the exact old selected bytes',async t=>{
 const f=await setup(t),v1=await f.candidate(),installed=await f.plan(v1);await installed.apply(approved)
 const updated=await f.plan({...await f.candidate('2.0.0','throw new Error("V2_NEVER_RUN")\n'),current:installed,operation:'update'})
 await assert.rejects(()=>updated.apply(approved,()=>{throw new Error('INJECTED_AFTER_SELECTOR')}),/INJECTED_AFTER_SELECTOR/)
 assert.equal((await updated.inspect()).selectionAvailable,false)
 await assert.rejects(()=>updated.readInstalled('inert.js'),/DISABLED_OR_UNTRUSTED/)
 const reopened=await reopenIsolatedPluginInstall(f.runtime,updated.root,{...context,reviewer:f.reviewer})
 await assert.rejects(()=>reopened.rollback({request:async()=> 'denied'}),/APPROVAL_DENIED/)
 await reopened.rollback(approved);assert.deepEqual(await reopened.readInstalled('inert.js'),Buffer.from(v1.text))
 assert.deepEqual(await installed.readInstalled('inert.js'),Buffer.from(v1.text))
})
test('version downgrade, identical closure and changed bytes without version advance are rejected',async t=>{
 const f=await setup(t),v2=await f.candidate('2.0.0','inert v2'),store=await f.plan(v2);await store.apply(approved)
 await assert.rejects(()=>f.plan({...v2,current:store,operation:'update'}),/NO_CHANGE/)
 await assert.rejects(async()=>f.plan({...await f.candidate('1.0.0'),current:store,operation:'update'}),/DOWNGRADE_DENIED/)
 await assert.rejects(async()=>f.plan({...await f.candidate('2.0.0','changed v2'),current:store,operation:'update'}),/VERSION_NOT_ADVANCED/)
})
