import { readFileSync, lstatSync, realpathSync } from 'node:fs'
import { resolve, isAbsolute, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash, verify } from 'node:crypto'
export const controllerVersion = 'f03r-1'
export const digest = bytes => createHash('sha256').update(bytes).digest('hex')
export function verifyApproval({ manifestBytes, signature, publicKey, policyBytes, minimum, code }) {
  if (!verify(null, manifestBytes, publicKey, signature)) throw new Error('approval signature mismatch')
  const m = JSON.parse(manifestBytes)
  if (digest(policyBytes) !== m.policySha256) throw new Error('approved policy digest mismatch')
  const p = JSON.parse(policyBytes.toString('utf8').replace(/^\uFEFF/, ''))
  if (m.controllerVersion !== controllerVersion || m.controllerVersion !== minimum.controllerVersion || m.policyVersion !== minimum.policyVersion || p.version !== m.policyVersion || !Number.isSafeInteger(p.version)) throw new Error('unapproved controller/policy version')
  if (digest(policyBytes) !== m.policySha256 || m.trustCommit !== p.trustCommit || !/^[a-f0-9]{40}$/.test(p.trustCommit ?? '')) throw new Error('approved policy digest/commit mismatch')
  if (!m.approval?.id || !m.approval?.reason || !m.approval?.date) throw new Error('approval record missing')
  for (const name of ['bootstrap.mjs','controller.mjs','evaluate.mjs','binding.mjs','trust.mjs','runtime.mjs']) if (!code[name] || m.controllerFiles?.[name] !== digest(code[name])) throw new Error(`controller identity mismatch: ${name}`)
  if (!/^[\w.-]+\/[\w.-]+$/.test(p.repository ?? '') || !p.files || !Number.isSafeInteger(p.workflowId)) throw new Error('invalid approved policy')
  return { policy:p, manifest:m, policyDigest:m.policySha256 }
}
export function readRootFile(root, name) {
  if (!/^[\w.-]+$/.test(name) || name === '.' || name === '..') throw new Error('invalid trust-root file name')
  const file=resolve(root,name)
  if (lstatSync(file).isSymbolicLink() || realpathSync(file) !== file) throw new Error('trust file link/alias refused')
  return readFileSync(file)
}
export function loadTrust(root) {
  if (!root || !isAbsolute(root) || realpathSync(root) !== resolve(root)) throw new Error('fixed external trust root required')
  const bytes=readRootFile(root,'approval.json'); const m=JSON.parse(bytes)
  const dir=dirname(fileURLToPath(import.meta.url));const code={}
  for(const name of ['bootstrap.mjs','controller.mjs','evaluate.mjs','binding.mjs','trust.mjs','runtime.mjs']) code[name]=readFileSync(resolve(dir,name))
  return verifyApproval({manifestBytes:bytes,signature:readRootFile(root,'approval.sig'),publicKey:readRootFile(root,'signer.pem'),policyBytes:readRootFile(root,m.policyFile),minimum:JSON.parse(readRootFile(root,'minimum-version.json')),code})
}

