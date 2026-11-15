#!/usr/bin/env node
/** Only owner-dispatched hosted workflow may create a new bounded prerelease. */
import { execFileSync } from 'node:child_process'
import { readFileSync,readdirSync,mkdirSync,writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve,join,basename } from 'node:path'
import { fileURLToPath } from 'node:url'
import { previewPreflight,assertMain,githubJson,REPOSITORY } from './preview-release-preflight.mjs'
const hash=b=>createHash('sha256').update(b).digest('hex')
export function publishPreview({commit,directory}){
 if(process.env.GITHUB_ACTIONS!=='true')throw new Error('HOSTED_OWNER_PREVIEW_WORKFLOW_REQUIRED')
 const admission=previewPreflight(commit),tag=admission.tag
 const gh=(...args)=>execFileSync('gh',args,{encoding:'utf8',timeout:120000,maxBuffer:4*1024*1024})
 const manifest=JSON.parse(readFileSync(join(directory,'preview-build.json'),'utf8')),windows=JSON.parse(readFileSync(join(directory,'windows-experience-zip.json'),'utf8'))
 if(manifest.commit!==commit||manifest.version!==admission.version||manifest.metadataTimestampOrigin!=='FROZEN_GIT_COMMIT_SOURCE_DATE_EPOCH'||windows.commit!==commit||windows.version!==admission.version)throw new Error('PREVIEW_ASSET_SOURCE_BINDING')
 const names=readdirSync(directory).sort()
 const required=[manifest.artifact.file,'ArmorBreak-Windows-Preview.zip','sbom.spdx.json','THIRD_PARTY_NOTICES.txt','preview-build.json','windows-experience-zip.json','windows-experience-acceptance.json','windows-experience-reproducibility.json','admission.json','github-attestation.sigstore.json','attestation-tgz.json','attestation-windows.json','SHA256SUMS.txt']
 if(JSON.stringify(names)!==JSON.stringify(required.slice().sort())||names.some(n=>basename(n)!==n||!/^[-a-zA-Z0-9_.]+$/.test(n)))throw new Error('PREVIEW_RELEASE_ASSET_ALLOWLIST')
 for(const [name,expected] of [[manifest.artifact.file,manifest.artifact.sha256],['ArmorBreak-Windows-Preview.zip',windows.sha256]])if(hash(readFileSync(join(directory,name)))!==expected)throw new Error('PREVIEW_ASSET_DIGEST')
 const reproduced=JSON.parse(readFileSync(join(directory,'windows-experience-reproducibility.json'),'utf8'))
 if(reproduced.commit!==commit||reproduced.identical!==true||reproduced.sha256!==windows.sha256)throw new Error('PREVIEW_REPRODUCIBILITY_REQUIRED')
 const sums=names.filter(n=>n!=='SHA256SUMS.txt').map(name=>hash(readFileSync(join(directory,name)))+'  '+name).join('\n')+'\n'
 writeFileSync(join(directory,'SHA256SUMS.txt'),sums)
 const notes=fileURLToPath(new URL('../../docs/releases/v2.4.0-preview.1.md',import.meta.url))
 assertMain(commit)
 gh('release','create',tag,'--repo',REPOSITORY,'--target',commit,'--draft','--prerelease','--latest=false','--title',`ArmorBreak ${admission.version} — 开发预览`,'--notes-file',notes,...names.map(n=>join(directory,n)))
 // Verify freshly downloaded assets before making the new draft public.
 const download=join(directory,'downloaded-draft');mkdirSync(download)
 gh('release','download',tag,'--repo',REPOSITORY,'--dir',download)
 for(const name of names)if(hash(readFileSync(join(download,name)))!==hash(readFileSync(join(directory,name))))throw new Error('PREVIEW_REMOTE_ASSET_MISMATCH')
 assertMain(commit)
 gh('release','edit',tag,'--repo',REPOSITORY,'--draft=false','--prerelease','--latest=false')
 const published=githubJson(`repos/${REPOSITORY}/releases/tags/${tag}`)
 if(published.draft||!published.prerelease||published.target_commitish!==commit)throw new Error('PREVIEW_PUBLISHED_SCOPE_MISMATCH')
 let ref=githubJson(`repos/${REPOSITORY}/git/ref/tags/${tag}`).object
 for(let n=0;ref.type==='tag'&&n<2;n++)ref=githubJson(`repos/${REPOSITORY}/git/tags/${ref.sha}`).object
 if(ref.type!=='commit'||ref.sha!==commit)throw new Error('PREVIEW_PUBLISHED_TAG_MISMATCH')
 if(githubJson(`repos/${REPOSITORY}/releases/latest`).tag_name!=='v2.3.1')throw new Error('PREVIEW_STABLE_ALIAS_CHANGED')
 if(githubJson(`repos/${REPOSITORY}/git/ref/tags/v2.3.1`).object.sha!==admission.frozenV231Tag)throw new Error('FROZEN_V231_TAG_CHANGED')
 return {schema:'armorbreak.preview-publication/v1',tag,commit,url:published.html_url,prerelease:true,stableApproved:false,productionAppGate:false,fullMigrationComplete:false,remoteAssetsHashVerified:true,assets:published.assets.map(a=>({name:a.name,bytes:a.size,url:a.browser_download_url}))}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const arg=k=>process.argv[process.argv.indexOf(k)+1]
 if(!process.argv.includes('--commit')||!process.argv.includes('--dir'))throw new Error('--commit and --dir required')
 const result=publishPreview({commit:arg('--commit'),directory:resolve(arg('--dir'))});writeFileSync('preview-publication.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2))
}
