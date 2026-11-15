import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { importConfiguration, exportConfiguration } from '../lib/integrations/configFormats.js'
import { planSyntheticConfiguration } from '../packages/core/src/syntheticConfiguration.js'
import { ArmorBreakRuntime } from '../packages/core/src/runtime.js'
const input=(format,source)=>({schema:'armorbreak.configuration-import/v1',format,source})
const yaml='# Keep this header\r\nfeature: false # explicit false\r\nprivatePin: "1234" # operator note\r\nfuture: {enabled: false, option: null}\r\ntext: |\r\n  first line\r\n  second line\r\n'
test('unchanged YAML is byte-exact; changed values keep comments, map order, quoting, CRLF and unknown false/null data',()=>{
 const {document}=importConfiguration(input('yaml',yaml))
 assert.equal(exportConfiguration(document,{preserveSource:yaml}),yaml)
 document.data.privatePin='5678'
 const output=exportConfiguration(document,{preserveSource:yaml}),parsed=importConfiguration(input('yaml',output)).document.data
 assert.match(output,/^# Keep this header\r\nfeature: false # explicit false\r\nprivatePin: "5678" # operator note/)
 assert.doesNotMatch(output,/(?<!\r)\n/);assert.deepEqual(parsed,document.data);assert.equal(parsed.future.enabled,false);assert.equal(parsed.future.option,null)
 assert.match(output,/text: \|/)
})
test('Cordis component reorder keeps each identity comment and rejects executable/ambiguous source syntax',()=>{
 const source='- id: first # first component\n  name: example/one\n  disabled: false\n- id: second # second component\n  name: example/two\n  disabled: true\n'
 const {document}=importConfiguration(input('cordis',source));document.data.reverse()
 const output=exportConfiguration(document,{preserveSource:source})
 assert.match(output,/^- id: second # second component/);assert.match(output,/- id: first # first component/)
 for(const bad of ['x: &a 1\ny: *a\n','x: !execute hi\n','x: 1\nx: 2\n','__proto__: {x: 1}\n'])assert.throws(()=>exportConfiguration(importConfiguration(input('yaml','x: 1\n')).document,{preserveSource:bad}),/configuration import rejected/)
})
test('fresh approved YAML transaction preserves presentation and separately restores original raw bytes without public secret fingerprints',async t=>{
 const root=await mkdtemp(join(tmpdir(),'ab-yaml-style-'));t.after(()=>rm(root,{recursive:true,force:true}));const runtime=new ArmorBreakRuntime({stateRoot:join(root,'state')});await runtime.init()
 const {lab,plan,preview}=await planSyntheticConfiguration(runtime,{configuration:input('yaml',yaml),overlays:[{id:'secret-profile',values:{privatePin:'5678'}}],conflictPolicy:'last-wins',operator:'style-user',sessionId:'style-session'});t.after(()=>rm(lab.root,{recursive:true,force:true}))
 assert.doesNotMatch(JSON.stringify({plan,preview}),/privatePin|secret-profile|1234|5678|operator note|beforeSha256|afterSha256/)
 await assert.rejects(()=>lab.apply(plan.planId),/PROVIDER_REQUIRED/)
 await lab.apply(plan.planId,{request:async()=> 'allowed-once'})
 assert.match(await readFile(join(lab.data,'config.txt'),'utf8'),/"5678" # operator note/)
 await lab.rollback(plan.planId,{request:async()=> 'allowed-once'})
 assert.deepEqual(await readFile(join(lab.data,'config.txt')),Buffer.from(yaml))
})
test('two-file preset preserves both private YAML presentations and makes type changes explicit in output semantics',()=>{
 const source={preset:'# preset\nname: "mine" # keep\nfuture: false\n',agent:'# agents\n- id: first\n  name: example/one\n  config:\n    setting: "old" # typed\n'}
 const {document}=importConfiguration(input('purge-preset',source));document.data.metadata.name='updated';document.data.composition[0].config.setting={enabled:false}
 const result=exportConfiguration(document,{preserveSource:source})
 assert.match(result.preset,/# preset/);assert.match(result.preset,/name: "updated" # keep/);assert.match(result.agent,/# agents/)
 assert.deepEqual(importConfiguration(input('purge-preset',result)).document.data,document.data)
})
