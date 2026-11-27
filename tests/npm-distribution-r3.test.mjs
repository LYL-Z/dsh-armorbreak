import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { verifyNpmDistribution } from '../scripts/v24/verify-npm-distribution.mjs'
import { checkDistributionAttribution, checkDistributionPaths } from '../scripts/v24/distribution-policy.mjs'
import { buildPreviewMetadata } from '../scripts/v24/preview-metadata.mjs'
import { readFile, writeFile } from 'node:fs/promises'
import { buildWindowsExperience } from '../scripts/v24/build-windows-experience.mjs'
import { verifyWindowsExperience } from '../scripts/v24/verify-windows-experience.mjs'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

test('frozen actual npm pack installs and runs all declared runtime surfaces in a fresh consumer', {timeout:120000}, async t => {
  const parent=await mkdtemp(join(tmpdir(),'ab-npm-r3-'));t.after(()=>rm(parent,{recursive:true,force:true}))
  const result=await verifyNpmDistribution({repositoryRoot:process.cwd(),outputRoot:join(parent,'acceptance')})
  assert.equal(result.status,'PASS_ACTUAL_PACK_INSTALL_IMPORT_RUNTIME')
  assert.equal(result.checks.yaml,'2.9.1')
  assert.equal(result.checks.configuration,'INSTALLED_APPROVED_SYNTHETIC_APPLY_AND_EXACT_RESTORE')
  const validationRoot=join(parent,'acceptance')
  const source=join(validationRoot,'frozen-source')
  const installed=join(validationRoot,'consumer/node_modules/dsh-armorbreak')
  const paths=result.packFiles
  assert.ok(result.attribution.notices.some(row=>row.path==='NOTICE'))
  assert.ok(result.attribution.internalPackages.some(row=>row.name==='@armorbreak/core' && row.licenseDeclared==='MIT'))
  for(const path of ['NOTICE','LICENSE','LICENSES/MIT.txt','THIRD_PARTY_NOTICES.txt']){
    assert.throws(()=>checkDistributionPaths(paths.filter(p=>p!==path)), /DISTRIBUTION_MISSING/)
  }
  for(const path of ['private.txt','lib/fixtures/sample.json','lib/../private.txt','lib/.env','notice']){
    assert.throws(()=>checkDistributionPaths([...paths,path]),/DISTRIBUTION_(FILE_LIST_INVALID|PATH)|UNRELATED_DISTRIBUTION_FILE/)
  }
  const pkg=JSON.parse(await readFile(join(validationRoot,'consumer/node_modules/dsh-armorbreak/package.json'),'utf8'))
  const check=()=>checkDistributionAttribution({source,installed,paths,packVersion:pkg.version})
  const cases=[
    ['package.json', bytes=>JSON.stringify({...JSON.parse(bytes),license:'UNLICENSED'}),/DISTRIBUTION_PROJECT_LICENSE_INVALID/],
    ['packages/core/package.json', bytes=>JSON.stringify({...JSON.parse(bytes),license:''}),/DISTRIBUTION_INTERNAL_LICENSE_INVALID/],
    ['npm-shrinkwrap.json', bytes=>JSON.stringify({...JSON.parse(bytes),version:'0.0.0'}),/DISTRIBUTION_VERSION_OR_LOCK_MISMATCH/],
    ['NOTICE', ()=>'',/DISTRIBUTION_NOTICE_EMPTY/],
    ['LICENSE', ()=> 'unrelated license text',/DISTRIBUTION_PROJECT_LICENSE_TEXT_CHANGED/],
  ]
  for(const [path,change,message] of cases){
    const original=await readFile(join(source,path))
    try{
      await writeFile(join(installed,path),change(original))
      assert.throws(check,/DISTRIBUTION_SOURCE_MISMATCH/)
      await writeFile(join(source,path),change(original))
      assert.throws(check,message)
    }finally{
      await writeFile(join(source,path),original)
      await writeFile(join(installed,path),original)
    }
  }
  if(pkg.version.startsWith('2.4.0-preview.')){
    const outputRoot=join(parent,'metadata'),manifest=buildPreviewMetadata({validationRoot,outputRoot})
    assert.equal(manifest.version,pkg.version);assert.equal(manifest.stableEligible,false);assert.equal(manifest.fullMigrationComplete,false)
    const sbom=JSON.parse(await readFile(join(outputRoot,'sbom.spdx.json'),'utf8'));assert.equal(sbom.packages.length,3)
    assert.ok(sbom.packages.some(p=>p.name==='yaml'&&p.versionInfo==='2.9.1'));assert.equal(sbom.files.length,result.packFiles.length)
    assert.match(await readFile(join(outputRoot,'THIRD_PARTY_NOTICES.txt'),'utf8'),/TypeScript|Microsoft/)
    assert.match(await readFile(join(outputRoot,'THIRD_PARTY_NOTICES.txt'),'utf8'),/033e6bd1e0f101352b39075ecd0d758ffef26b76/)
    assert.throws(()=>buildPreviewMetadata({validationRoot,outputRoot}),/REFUSE_EXISTING_OUTPUT/)
    if(process.platform==='win32'){
      const experience=join(parent,'experience 体验 & files')
      const built=buildWindowsExperience({validationRoot,outputRoot:experience});assert.equal(built.nodeBundled,false)
      const archiver=fileURLToPath(new URL('../scripts/v24/windows-experience-archive.py',import.meta.url)),zip=join(parent,'experience.zip'),extracted=join(parent,'extracted 体验 & files')
      execFileSync('python',[archiver,'pack',experience,zip],{stdio:'pipe',timeout:30000})
      const repeat=join(parent,'repeat experience'),repeatZip=join(parent,'repeat.zip')
      buildWindowsExperience({validationRoot,outputRoot:repeat});execFileSync('python',[archiver,'pack',repeat,repeatZip],{stdio:'pipe',timeout:30000})
      assert.deepEqual(await readFile(zip),await readFile(repeatZip),'same frozen inputs must reproduce every Windows ZIP byte')
      execFileSync('python',[archiver,'extract',zip,extracted],{stdio:'pipe',timeout:30000})
      const accepted=await verifyWindowsExperience(extracted);assert.equal(accepted.taskState,'COMPLETED');assert.ok(accepted.evidenceCount>0)
      await writeFile(join(extracted,'Start ArmorBreak.cmd'),'echo replaced')
      await assert.rejects(()=>verifyWindowsExperience(extracted),/EXPERIENCE_FILE_DRIFT/)
      execFileSync('python',['-c',"import sys,zipfile;z=zipfile.ZipFile(sys.argv[1],'a');z.writestr('../outside.txt','denied');z.close()",zip])
      assert.throws(()=>execFileSync('python',[archiver,'extract',zip,join(parent,'bad-zip')],{stdio:'pipe'}))
    }
    const artifact=join(validationRoot,result.artifact.file),before=await readFile(artifact);await writeFile(artifact,Buffer.concat([before,Buffer.from('corrupt')]))
    assert.throws(()=>buildPreviewMetadata({validationRoot,outputRoot:join(parent,'bad-artifact')}),/ARTIFACT_MISMATCH/)
    await writeFile(artifact,before)
    const dependency=join(validationRoot,'consumer/node_modules/yaml/package.json'),original=await readFile(dependency);await writeFile(dependency,JSON.stringify({...JSON.parse(original),version:'0.0.0'}))
    assert.throws(()=>buildPreviewMetadata({validationRoot,outputRoot:join(parent,'bad-lock')}),/DEPENDENCY_LOCK_MISMATCH/)
  }
})
