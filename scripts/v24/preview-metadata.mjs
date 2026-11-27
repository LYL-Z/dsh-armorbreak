#!/usr/bin/env node
/** Describe an actually installed Preview TGZ. This is not a signing or publication grant. */
import { createHash } from 'node:crypto'
import { readFileSync, mkdirSync, writeFileSync, existsSync, copyFileSync } from 'node:fs'
import { join, resolve, basename } from 'node:path'
import { fileURLToPath } from 'node:url'
import { checkDistributionAttribution } from './distribution-policy.mjs'
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const json = path => JSON.parse(readFileSync(path, 'utf8'))
const safe = path => typeof path === 'string' && !path.includes('\\') && !path.startsWith('/') && path.split('/').every(p=>p && p!=='.' && p!=='..')

export function buildPreviewMetadata({ validationRoot, outputRoot }) {
  const validation = json(join(validationRoot,'validation.json'))
  if (validation.schema!=='armorbreak.npm-distribution-validation/v1' || validation.status!=='PASS_ACTUAL_PACK_INSTALL_IMPORT_RUNTIME' || !/^[a-f0-9]{40}$/.test(validation.commit)) throw new Error('PREVIEW_ACTUAL_INSTALL_REQUIRED')
  const artifact=validation.artifact
  if (!artifact || basename(artifact.file)!==artifact.file || !safe(artifact.file)) throw new Error('PREVIEW_ARTIFACT_PATH')
  const artifactPath=join(validationRoot,artifact.file), bytes=readFileSync(artifactPath)
  if (bytes.length!==artifact.bytes || digest(bytes)!==artifact.sha256) throw new Error('PREVIEW_ARTIFACT_MISMATCH')
  const root=join(validationRoot,'consumer/node_modules/dsh-armorbreak'), pkg=json(join(root,'package.json'))
  if(pkg.name!=='dsh-armorbreak' || !/^2\.4\.0-preview\.[1-9]\d*$/.test(pkg.version)) throw new Error('PREVIEW_VERSION_REQUIRED')
  const frozen=json(join(validationRoot,'frozen-source/package.json')), lock=json(join(root,'npm-shrinkwrap.json'))
  const attribution = checkDistributionAttribution({source:join(validationRoot,'frozen-source'),installed:root,paths:validation.packFiles,packVersion:pkg.version})
  if(frozen.version!==pkg.version || lock.version!==pkg.version || lock.packages[''].version!==pkg.version || JSON.stringify(frozen.dependencies)!==JSON.stringify(pkg.dependencies)) throw new Error('PREVIEW_VERSION_OR_LOCK_MISMATCH')
  if(!Array.isArray(validation.packFiles) || new Set(validation.packFiles).size!==validation.packFiles.length || !validation.packFiles.includes('packages/core/index.js')) throw new Error('PREVIEW_PACK_FILE_LIST')
  const files=validation.packFiles.slice().sort().map((path,index)=>{
    if(!safe(path)) throw new Error('PREVIEW_FILE_PATH')
    const actual=readFileSync(join(root,path)), original=readFileSync(join(validationRoot,'frozen-source',path))
    if(!actual.equals(original)) throw new Error('PREVIEW_SOURCE_FILE_MISMATCH: '+path)
    return {fileName:'./'+path,SPDXID:'SPDXRef-File-'+(index+1),checksums:[
      {algorithm:'SHA1',checksumValue:createHash('sha1').update(actual).digest('hex')},
      {algorithm:'SHA256',checksumValue:digest(actual)},
    ],licenseConcluded:'NOASSERTION',licenseInfoInFiles:['NOASSERTION'],copyrightText:'NOASSERTION'}
  })
  const dependencyNames=Object.keys(pkg.dependencies).sort(), lockNames=Object.keys(lock.packages).filter(n=>n).sort()
  if(JSON.stringify(lockNames)!==JSON.stringify(dependencyNames.map(n=>'node_modules/'+n))) throw new Error('PREVIEW_DEPENDENCY_CLOSURE_NOT_COVERED')
  const notices=[{name:pkg.name,version:pkg.version,license:pkg.license,text:readFileSync(join(root,'LICENSE'),'utf8')}]
  const dependencies=dependencyNames.map((name,index)=>{
    if(!/^[a-z][a-z0-9-]*$/.test(name))throw new Error('PREVIEW_DEPENDENCY_NAME')
    const entry=lock.packages['node_modules/'+name], directory=join(validationRoot,'consumer/node_modules',name), installed=json(join(directory,'package.json'))
    if(installed.version!==pkg.dependencies[name] || entry.version!==installed.version || entry.license!==installed.license || !/^sha512-[A-Za-z0-9+/]+=*$/.test(entry.integrity) || entry.resolved!==`https://registry.npmjs.org/${name}/-/${name}-${installed.version}.tgz`) throw new Error('PREVIEW_DEPENDENCY_LOCK_MISMATCH')
    const licensePath=['LICENSE','LICENSE.txt'].find(p=>existsSync(join(directory,p)))
    if(!licensePath)throw new Error('PREVIEW_DEPENDENCY_LICENSE_MISSING')
    let text=readFileSync(join(directory,licensePath),'utf8')
    const thirdParty=join(directory,'ThirdPartyNoticeText.txt');if(existsSync(thirdParty))text+='\n\n'+readFileSync(thirdParty,'utf8')
    notices.push({name,version:installed.version,license:installed.license,text})
    return {name,versionInfo:installed.version,SPDXID:'SPDXRef-Dependency-'+(index+1),downloadLocation:entry.resolved,filesAnalyzed:false,licenseDeclared:installed.license,licenseConcluded:'NOASSERTION',externalRefs:[{referenceCategory:'PACKAGE-MANAGER',referenceType:'purl',referenceLocator:`pkg:npm/${name}@${installed.version}`}],sourceInfo:`npm shrinkwrap integrity: ${entry.integrity}. Fetched separately by npm; not embedded in the ArmorBreak TGZ.`}
  })
  if(existsSync(outputRoot))throw new Error('REFUSE_EXISTING_OUTPUT')
  mkdirSync(outputRoot,{recursive:true})
  const write=(name,value)=>writeFileSync(join(outputRoot,name),typeof value==='string'?value:JSON.stringify(value,null,2)+'\n')
  const rootId='SPDXRef-Package-dsh-armorbreak', created=new Date(validation.sourceDate??Date.now()).toISOString()
  // SPDX 2.3 prescribes SHA-1 for the package verification code.
  // The actual artifact and every file retain SHA-256 integrity digests.
  const packageVerificationCodeValue=createHash('sha1').update(files.map(file=>file.checksums[0].checksumValue).sort().join('')).digest('hex')
  const project={name:pkg.name,versionInfo:pkg.version,SPDXID:rootId,packageFileName:artifact.file,
    downloadLocation:'NOASSERTION',filesAnalyzed:true,packageVerificationCode:{packageVerificationCodeValue},
    licenseDeclared:pkg.license,licenseConcluded:'NOASSERTION',copyrightText:'NOASSERTION',
    licenseInfoFromFiles:['NOASSERTION'],checksums:[{algorithm:'SHA256',checksumValue:artifact.sha256}]}
  const sbom={spdxVersion:'SPDX-2.3',dataLicense:'CC0-1.0',SPDXID:'SPDXRef-DOCUMENT',name:`${pkg.name}-${pkg.version}`,documentNamespace:`https://github.com/LYL-Z/dsh-armorbreak/sbom/${validation.commit}/${artifact.sha256}`,creationInfo:{created,creators:['Tool: scripts/v24/preview-metadata.mjs']},packages:[project,...dependencies],files,relationships:[{spdxElementId:'SPDXRef-DOCUMENT',relationshipType:'DESCRIBES',relatedSpdxElement:rootId},...files.map(f=>({spdxElementId:rootId,relationshipType:'CONTAINS',relatedSpdxElement:f.SPDXID})),...dependencies.map(d=>({spdxElementId:rootId,relationshipType:'DEPENDS_ON',relatedSpdxElement:d.SPDXID}))]}
  copyFileSync(artifactPath,join(outputRoot,artifact.file))
  write('THIRD_PARTY_NOTICES.txt',[
    readFileSync(join(root,'NOTICE'),'utf8'),
    readFileSync(join(root,'THIRD_PARTY_NOTICES.txt'),'utf8'),
    readFileSync(join(root,'LICENSES/CC-BY-4.0.txt'),'utf8'),
    ...notices.map(n=>`${n.name}@${n.version} (${n.license})\n${n.text}`),
  ].join('\n\n---\n\n'))
  const manifest={schema:'armorbreak.preview-build/v1',version:pkg.version,commit:validation.commit,artifact,platformValidation:validation.environment,packageValidation:validation.status,sourceBinding:'FROZEN_GIT_SOURCE_TO_INSTALLED_PACK_FILES_BYTE_EQUAL',fileCount:files.length,dependencyCount:dependencies.length,provenance:'LOCAL_UNSIGNED_BUILD_RECORD_NOT_GITHUB_ATTESTATION',publicationAuthorized:false,stableEligible:false,fullMigrationComplete:false,realDshCompatibility:'NOT_TESTED',productionIdentity:'NOT_VERIFIED'}
  manifest.metadataTimestampOrigin=validation.sourceDate?'FROZEN_GIT_COMMIT_SOURCE_DATE_EPOCH':'LEGACY_BUILD_CLOCK'
  manifest.attribution=attribution
  sbom.creationInfo.comment='Reproducible metadata uses the frozen Git commit timestamp as SOURCE_DATE_EPOCH; actual build timing belongs to the hosted workflow record.'
  write('sbom.spdx.json',sbom)
  write('preview-build.json',manifest)
  const outputs=[artifact.file,'sbom.spdx.json','THIRD_PARTY_NOTICES.txt','preview-build.json']
  write('SHA256SUMS.txt',outputs.map(p=>digest(readFileSync(join(outputRoot,p)))+'  '+p).join('\n')+'\n')
  return manifest
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const arg=name=>process.argv[process.argv.indexOf(name)+1]
  if(!process.argv.includes('--validation')||!process.argv.includes('--out'))throw new Error('--validation and --out are required')
  console.log(JSON.stringify(buildPreviewMetadata({validationRoot:resolve(arg('--validation')),outputRoot:resolve(arg('--out'))}),null,2))
}
