import { readFileSync,writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
const arg=k=>process.argv[process.argv.indexOf(k)+1]
for(const k of ['--commit','--first','--second','--out'])if(!process.argv.includes(k))throw new Error('missing '+k)
if(!/^[a-f0-9]{40}$/.test(arg('--commit')))throw new Error('PREVIEW_COMMIT_INVALID')
const a=readFileSync(arg('--first')),b=readFileSync(arg('--second'))
if(!a.equals(b))throw new Error('PREVIEW_BUILD_NOT_REPRODUCIBLE')
writeFileSync(arg('--out'),JSON.stringify({commit:arg('--commit'),identical:true,sha256:createHash('sha256').update(a).digest('hex')},null,2)+'\n')
