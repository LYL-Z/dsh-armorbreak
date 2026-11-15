import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { verifyNpmDistribution } from '../scripts/v24/verify-npm-distribution.mjs'
import { buildPreviewMetadata } from '../scripts/v24/preview-metadata.mjs'
import { readFile, writeFile } from 'node:fs/promises'

test('frozen actual npm pack installs and runs all declared runtime surfaces in a fresh consumer', {timeout:120000}, async t => {
  const parent=await mkdtemp(join(tmpdir(),'ab-npm-r3-'));t.after(()=>rm(parent,{recursive:true,force:true}))
  const result=await verifyNpmDistribution({repositoryRoot:process.cwd(),outputRoot:join(parent,'acceptance')})
  assert.equal(result.status,'PASS_ACTUAL_PACK_INSTALL_IMPORT_RUNTIME')
  assert.equal(result.checks.yaml,'2.9.1')
  assert.equal(result.checks.configuration,'INSTALLED_APPROVED_SYNTHETIC_APPLY_AND_EXACT_RESTORE')
  const validationRoot=join(parent,'acceptance')
  const pkg=JSON.parse(await readFile(join(validationRoot,'consumer/node_modules/dsh-armorbreak/package.json'),'utf8'))
  if(pkg.version.startsWith('2.4.0-preview.')){
    const outputRoot=join(parent,'metadata'),manifest=buildPreviewMetadata({validationRoot,outputRoot})
    assert.equal(manifest.version,pkg.version);assert.equal(manifest.stableEligible,false);assert.equal(manifest.fullMigrationComplete,false)
    const sbom=JSON.parse(await readFile(join(outputRoot,'sbom.spdx.json'),'utf8'));assert.equal(sbom.packages.length,3)
    assert.ok(sbom.packages.some(p=>p.name==='yaml'&&p.versionInfo==='2.9.1'));assert.equal(sbom.files.length,result.packFiles.length)
    assert.match(await readFile(join(outputRoot,'THIRD_PARTY_NOTICES.txt'),'utf8'),/TypeScript|Microsoft/)
    assert.throws(()=>buildPreviewMetadata({validationRoot,outputRoot}),/REFUSE_EXISTING_OUTPUT/)
    const artifact=join(validationRoot,result.artifact.file),before=await readFile(artifact);await writeFile(artifact,Buffer.concat([before,Buffer.from('corrupt')]))
    assert.throws(()=>buildPreviewMetadata({validationRoot,outputRoot:join(parent,'bad-artifact')}),/ARTIFACT_MISMATCH/)
    await writeFile(artifact,before)
    const dependency=join(validationRoot,'consumer/node_modules/yaml/package.json'),original=await readFile(dependency);await writeFile(dependency,JSON.stringify({...JSON.parse(original),version:'0.0.0'}))
    assert.throws(()=>buildPreviewMetadata({validationRoot,outputRoot:join(parent,'bad-lock')}),/DEPENDENCY_LOCK_MISMATCH/)
  }
})
