import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { ArmorBreakRuntime } from '../../packages/core/src/runtime.js'
import { createIndependentPluginReviewer, pluginAttestationPayload } from '../../lib/catalog/pluginLifecycle.js'
import { verifyPluginClosure } from '../../lib/catalog/pluginPackage.js'
import { canonicalConfig } from '../../lib/integrations/configOverlay.js'
import { planIsolatedPluginInstall } from '../../packages/core/src/isolatedPluginStore.js'
export const approved={request:async()=> 'allowed-once'}
export const context={operator:'selection-owner',sessionId:'selection-session'}
export async function storeFixture(t,{wrapReviewer,reviewerFactory}={}){
 const root=await mkdtemp(join(tmpdir(),'ab-selection-r4-')),workspace=join(root,'workspace'),target=join(workspace,'candidate')
 await mkdir(target,{recursive:true});t.after(()=>rm(root,{recursive:true,force:true}))
 const runtime=new ArmorBreakRuntime({stateRoot:join(root,'state')});await runtime.init()
 const task=await runtime.workspace(workspace).taskStore.create({title:'selection fixture',targetPath:target,steps:[]})
 const repository='https://github.com/example/self-authored-fixture',keys={source:generateKeyPairSync('ed25519'),rights:generateKeyPairSync('ed25519')}
 const roots=Object.keys(keys).map(role=>({keyId:role,authorityId:role+'-reviewer',role,repositories:[repository],publicKey:keys[role].publicKey.export({type:'spki',format:'pem'})}))
 const baseReviewer=reviewerFactory?await reviewerFactory({roots,root}):createIndependentPluginReviewer({roots}),reviewer=wrapReviewer?wrapReviewer(baseReviewer):baseReviewer
 async function candidate(version='1.0.0'){
  const bytes=`throw new Error("NEVER_EXECUTE_${version}")\r\n`
  await writeFile(join(target,'inert.js'),bytes)
  await writeFile(join(target,'armorbreak-plugin.json'),JSON.stringify({schema:'armorbreak.plugin-catalog/v1',plugins:[{id:'inert',version,source:{repository,commit:'a'.repeat(40)},license:'MIT',dependencies:[],permissions:['workspace.read'],platforms:['win32','linux'],channel:'stable',enabled:false,files:[{path:'inert.js',sha256:createHash('sha256').update(bytes).digest('hex')}]}]}))
  const input=await runtime.runner.buildCapabilityInput({task,capability:runtime.registry.get('plugin.verify'),targetPath:target,options:{closure:true},controller:new AbortController(),log:[]}),snapshot=await verifyPluginClosure(input),receipts={}
  for(const role of Object.keys(keys)){const payload=pluginAttestationPayload(snapshot,role);receipts[role+'Receipt']={keyId:role,payload,signature:sign(null,Buffer.from(canonicalConfig(payload)),keys[role].privateKey).toString('base64')}}
  return {candidate:input,receipts}
 }
 async function plan(options){const result=await planIsolatedPluginInstall(runtime,{...context,reviewer,...options});t.after(()=>rm(result.store.root,{recursive:true,force:true}));return result.store}
 return {root,runtime,roots,keys,reviewer,baseReviewer,candidate,plan}
}
