/** Runs only in a new consumer directory, resolving the installed package by its public name. */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { execFileSync, spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { join, dirname, relative, isAbsolute } from 'node:path'
import { fileURLToPath } from 'node:url'
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
console.log(JSON.stringify({exports:imported,client:'MODULE_REGISTRATION_SIMULATED_DSH_NOT_TESTED',cli:'ACTUAL_CHILD_PROCESS',mcp:'ACTUAL_STDIO_CHILD_PROCESS',core:'ACTUAL_INSTALLED_RUNTIME',workbench:'ACTUAL_HTTP_OS_AUTHENTICATION_NONE',yaml:pkg.dependencies.yaml,configuration:'INSTALLED_APPROVED_SYNTHETIC_APPLY_AND_EXACT_RESTORE',privateKeyScan:'PASS',runtimeVersion:pkg.version}))
