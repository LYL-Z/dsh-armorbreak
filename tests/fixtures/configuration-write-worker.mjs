import { ArmorBreakRuntime } from '../../packages/core/src/runtime.js'
import { planSyntheticConfiguration } from '../../packages/core/src/syntheticConfiguration.js'
const runtime=new ArmorBreakRuntime({stateRoot:process.argv[2]});await runtime.init()
const {lab,plan}=await planSyntheticConfiguration(runtime,{configuration:{schema:'armorbreak.configuration-import/v1',format:'yaml',source:'value: "old"\r\nfuture: false\r\n'},overlays:[{id:'inert',values:{value:'new'}}],conflictPolicy:'last-wins',operator:'fault-owner',sessionId:'fault-session'})
await lab.apply(plan.planId,{request:async()=> 'allowed-once'},undefined,{maxWriteBytes:2,onWritePhase:async event=>{
  if(event.phase===process.argv[3]){process.send({root:lab.root,planId:plan.planId,phase:event.phase});await new Promise(()=>setInterval(()=>{},1000))}
}})
