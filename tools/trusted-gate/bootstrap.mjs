import { loadTrust } from './trust.mjs'
// The service launcher pins this immutable release and its separate read-only
// trust mount. Event/caller arguments can select PR/run, never policy/key/root.
const [number, runId, mode='--dry-run', ...extra]=process.argv.slice(2)
if(extra.length || !/^\d+$/.test(number??'') || !/^\d+$/.test(runId??'') || !['--dry-run','--publish'].includes(mode)) throw new Error('usage: bootstrap PR RUN [--dry-run|--publish]; arbitrary policy paths prohibited')
const trust=loadTrust(process.env.ARMORBREAK_TRUST_ROOT)
const { control }=await import('./controller.mjs')
try { await control({trust,number:Number(number),runId:Number(runId),mode,root:process.env.ARMORBREAK_TRUST_ROOT}) }
catch(error){console.error(error.message);process.exitCode=1}
