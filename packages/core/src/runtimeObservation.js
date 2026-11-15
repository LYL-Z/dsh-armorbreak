/** Live, process-local observations. Never authenticate a remote client or infer another process. */
import { randomUUID } from 'node:crypto'
import { PRODUCT_VERSION } from '../../../lib/core/productVersion.js'
const PROCESS = Object.freeze({ instanceId:randomUUID(),pid:process.pid,node:process.version,platform:process.platform,arch:process.arch,
  startedAt:new Date(Date.now()-process.uptime()*1000).toISOString(),productVersion:PRODUCT_VERSION })
const ADAPTERS=new Set(['MCP_STDIO','WORKBENCH_HTTP','DSH_TOOLS','DSH_WEB_ROUTES'])

export class RuntimeObservation {
  #mounts=new Map()
  mount(kind) {
    if(!ADAPTERS.has(kind))throw new Error('RUNTIME_ADAPTER_KIND')
    if(this.#mounts.size>=64)throw new Error('RUNTIME_ADAPTER_LIMIT')
    const id=randomUUID(),row={id,kind,registeredAt:new Date().toISOString(),state:'REGISTERED',successfulCalls:0,failedCalls:0}
    this.#mounts.set(id,row)
    // A stale disposer only owns its own lease, never a replacement generation.
    return Object.freeze({
      initialized:()=>{if(this.#mounts.get(id)===row)row.state='INITIALIZED'},
      call:ok=>{if(this.#mounts.get(id)===row){row[ok===true?'successfulCalls':'failedCalls']++;row.lastCallAt=new Date().toISOString()}},
      dispose:()=>{if(this.#mounts.get(id)===row)this.#mounts.delete(id)},
    })
  }
  snapshot() {
    return {schema:'armorbreak.runtime-observation/v1',scope:'SELF_PROCESS_ONLY',process:{...PROCESS,uptimeSeconds:Math.floor(process.uptime())},
      adapters:[...this.#mounts.values()].map(row=>({...row})),
      source:'EXECUTED_ARMORBREAK_ADAPTER_CODE_NOT_DISK_METADATA',externalHostIdentity:'NOT_AUTHENTICATED',
      dshFamily:'UNKNOWN',dshVersion:'UNKNOWN',modelDelivery:'NOT_TESTED',osClientAuthentication:false,
      limitations:['An adapter registration proves only that this process executed its registration path; it does not authenticate DSH or any client.',
        'No process list, command line, environment, executable path, other user data or installed-package claim is imported.',
        'No observation grants Core approval, plugin activation, production signing or host mutation rights.']}
  }
}
