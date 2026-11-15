/** Trusted-host local policy journal. Never accepts policy roots from a plugin or HTTP client. */
import { constants, mkdirSync, openSync, closeSync, fstatSync, lstatSync, realpathSync, readSync, writeSync, fsyncSync, unlinkSync } from 'node:fs'
import { resolve, join } from 'node:path'
import { createHash, createPublicKey, verify } from 'node:crypto'
import { canonicalConfig } from '../integrations/configOverlay.js'
import { createIndependentPluginReviewer } from './pluginLifecycle.js'

const LIMIT=1048576, ZERO='0'.repeat(64), TOKEN=Symbol('persistent trust')
const hash=value=>createHash('sha256').update(canonicalConfig(value)).digest('hex')
const fingerprint=pem=>createHash('sha256').update((pem?.type==='public'?pem:createPublicKey(pem)).export({type:'spki',format:'der'})).digest('hex')
const identity=s=>`${s.dev}:${s.ino}`
function key(pem){const k=createPublicKey(pem);if(k.asymmetricKeyType!=='ed25519')throw new Error('PLUGIN_POLICY_KEY_TYPE');return k}
function signedPolicy(envelope,publicKey){
 if(!envelope||Object.keys(envelope).sort().join(',')!=='payload,signature')throw new Error('PLUGIN_POLICY_ENVELOPE')
 const p=envelope.payload
 if(!p||Object.keys(p).sort().join(',')!=='expiresAt,notBefore,policyId,roots,schema,version'||p.schema!=='armorbreak.plugin-trust-policy/v1'||typeof p.policyId!=='string'||!/^[a-zA-Z0-9._:-]{1,128}$/.test(p.policyId)||!Number.isSafeInteger(p.version)||p.version<1||!Number.isSafeInteger(p.notBefore)||!Number.isSafeInteger(p.expiresAt)||p.expiresAt<=p.notBefore)throw new Error('PLUGIN_POLICY_INVALID')
 if(!/^[A-Za-z0-9+/]{86}==$/.test(envelope.signature??'')||!verify(null,Buffer.from(canonicalConfig(p)),publicKey,Buffer.from(envelope.signature,'base64')))throw new Error('PLUGIN_POLICY_SIGNATURE')
 createIndependentPluginReviewer({roots:p.roots})
 if(p.roots.some(r=>fingerprint(r.publicKey)===fingerprint(publicKey)))throw new Error('PLUGIN_POLICY_ISSUER_ROLE_MIX')
 return structuredClone(p)
}
function validNow(p){const now=Date.now();if(now<p.notBefore||now>=p.expiresAt)throw new Error('PLUGIN_POLICY_NOT_CURRENT')}
function writeAll(fd,bytes){let offset=0;while(offset<bytes.length){const n=writeSync(fd,bytes,offset,bytes.length-offset);if(!n)throw new Error('PLUGIN_POLICY_PARTIAL_WRITE');offset+=n}fsyncSync(fd)}

class PersistentReviewer{
 #directory;#directoryId;#journal;#journalId;#key;#floor;#seen=0;#tip=ZERO
 constructor(token,{directory,policyPublicKey,minimumSequence=0}){
  if(token!==TOKEN)throw new Error('PLUGIN_POLICY_CONSTRUCTOR')
  if(!Number.isSafeInteger(minimumSequence)||minimumSequence<0)throw new Error('PLUGIN_POLICY_MINIMUM_SEQUENCE')
  this.#directory=resolve(directory);this.#directoryId=identity(lstatSync(this.#directory));this.#journal=join(this.#directory,'policy.ndjson');this.#journalId=identity(lstatSync(this.#journal));this.#key=key(policyPublicKey);this.#floor=minimumSequence
  this.#load();Object.freeze(this)
 }
 get kind(){return 'INDEPENDENT_SCOPED_PLUGIN_REVIEWER_V1'}
 #boundary(){const s=lstatSync(this.#directory);if(!s.isDirectory()||s.isSymbolicLink()||identity(s)!==this.#directoryId||realpathSync(this.#directory)!==this.#directory)throw new Error('PLUGIN_POLICY_DIRECTORY_DRIFT')}
 #read(){
  this.#boundary();const pathStat=lstatSync(this.#journal)
  if(!pathStat.isFile()||pathStat.isSymbolicLink()||pathStat.nlink!==1||identity(pathStat)!==this.#journalId)throw new Error('PLUGIN_POLICY_JOURNAL_DRIFT')
  const fd=openSync(this.#journal,constants.O_RDONLY|(constants.O_NOFOLLOW??0))
  try{const s=fstatSync(fd);if(identity(s)!==this.#journalId||s.nlink!==1||s.size>LIMIT)throw new Error('PLUGIN_POLICY_JOURNAL_LIMIT_OR_DRIFT');const bytes=Buffer.alloc(s.size+1),n=readSync(fd,bytes,0,bytes.length,0);if(n!==s.size||identity(lstatSync(this.#journal))!==this.#journalId)throw new Error('PLUGIN_POLICY_JOURNAL_DRIFT');return bytes.subarray(0,n).toString('utf8')}finally{closeSync(fd)}
 }
 #load(){
  const text=this.#read();if(!text.endsWith('\n'))throw new Error('PLUGIN_POLICY_JOURNAL_INCOMPLETE')
  let sequence=0,tip=ZERO,policy,seenTip=this.#seen===0?ZERO:null;const keys=new Set(),authorities=new Set(),fingerprints=new Set()
  for(const line of text.trimEnd().split('\n')){
   let record;try{record=JSON.parse(line)}catch{throw new Error('PLUGIN_POLICY_JOURNAL_CORRUPT')}
   const {digest,...body}=record
   if(Object.keys(body).sort().join(',')!=='operation,payload,previous,schema,sequence'||body.schema!=='armorbreak.plugin-policy-event/v1'||body.sequence!==++sequence||body.previous!==tip||digest!==hash(body))throw new Error('PLUGIN_POLICY_JOURNAL_CORRUPT')
   if(body.operation==='policy'){
    const next=signedPolicy(body.payload,this.#key)
    if(policy&&(next.policyId!==policy.policyId||next.version<=policy.version))throw new Error('PLUGIN_POLICY_VERSION_ROLLBACK')
    policy=next
   }else if(body.operation==='revokeKey'){
    if(!policy||Object.keys(body.payload).sort().join(',')!=='fingerprint,keyId'||!policy.roots.some(r=>r.keyId===body.payload.keyId&&fingerprint(r.publicKey)===body.payload.fingerprint))throw new Error('PLUGIN_POLICY_REVOCATION_BINDING')
    keys.add(body.payload.keyId);fingerprints.add(body.payload.fingerprint)
   }else if(body.operation==='revokeAuthority'){
    if(!policy||Object.keys(body.payload).join(',')!=='authorityId'||!policy.roots.some(r=>r.authorityId===body.payload.authorityId))throw new Error('PLUGIN_POLICY_REVOCATION_BINDING')
    authorities.add(body.payload.authorityId)
   }else throw new Error('PLUGIN_POLICY_EVENT_INVALID')
   tip=digest;if(sequence===this.#seen)seenTip=tip
  }
  if(!policy||sequence<this.#floor||sequence<this.#seen||seenTip!==this.#tip)throw new Error('PLUGIN_POLICY_HISTORY_ROLLBACK')
  this.#seen=sequence;this.#tip=tip
  return {sequence,tip,policy,keys,authorities,fingerprints}
 }
 #lease(){
  this.#boundary();const path=join(this.#directory,'operation.lock');let fd
  try{fd=openSync(path,'wx',0o600)}catch(e){if(e.code==='EEXIST')throw new Error('PLUGIN_POLICY_BUSY');throw e}
  const lockId=identity(fstatSync(fd));writeAll(fd,Buffer.from(JSON.stringify({pid:process.pid})))
  return ()=>{try{if(identity(lstatSync(path))!==lockId)throw new Error('PLUGIN_POLICY_LOCK_DRIFT');unlinkSync(path)}finally{closeSync(fd)}}
 }
 #append(operation,payload){
  const state=this.#load(),body={schema:'armorbreak.plugin-policy-event/v1',sequence:state.sequence+1,previous:state.tip,operation,payload},bytes=Buffer.from(canonicalConfig({...body,digest:hash(body)})+'\n')
  const fd=openSync(this.#journal,constants.O_WRONLY|constants.O_APPEND|(constants.O_NOFOLLOW??0))
  try{const stat=fstatSync(fd);if(identity(stat)!==this.#journalId||stat.nlink!==1||stat.size+bytes.length>LIMIT)throw new Error('PLUGIN_POLICY_JOURNAL_LIMIT_OR_DRIFT');writeAll(fd,bytes)}finally{closeSync(fd)}
  return this.#load()
 }
 revokeKey(keyId){const release=this.#lease();try{const state=this.#load(),root=state.policy.roots.find(r=>r.keyId===keyId);if(!root)throw new Error('PLUGIN_POLICY_UNKNOWN_KEY');if(!state.keys.has(keyId))this.#append('revokeKey',{keyId,fingerprint:fingerprint(root.publicKey)})}finally{release()}}
 revokeAuthority(authorityId){const release=this.#lease();try{const state=this.#load();if(!state.policy.roots.some(r=>r.authorityId===authorityId))throw new Error('PLUGIN_POLICY_UNKNOWN_AUTHORITY');if(!state.authorities.has(authorityId))this.#append('revokeAuthority',{authorityId})}finally{release()}}
 rotatePolicy(envelope){const release=this.#lease();try{const state=this.#load(),p=signedPolicy(envelope,this.#key);validNow(p);if(p.policyId!==state.policy.policyId||p.version<=state.policy.version)throw new Error('PLUGIN_POLICY_VERSION_ROLLBACK');this.#append('policy',structuredClone(envelope))}finally{release()}}
 checkpoint(){const s=this.#load();return {sequence:s.sequence,tip:s.tip,policyId:s.policy.policyId,policyVersion:s.policy.version,rollbackBoundary:'LOCAL_HISTORY_AND_CALLER_MINIMUM_SEQUENCE_ONLY',authorityIdentity:'PINNED_ISSUER_ASSERTION_NOT_EXTERNAL_IDENTITY_PROOF',powerLossRecovery:'NOT_TESTED'}}
 exportRevocations(){const s=this.#load();return {schema:'armorbreak.plugin-revocations/v1',keys:[...s.keys].sort(),authorities:[...s.authorities].sort()}}
 review(snapshot,receipts){
  const s=this.#load();validNow(s.policy)
  const roots=s.policy.roots.filter(r=>!s.fingerprints.has(fingerprint(r.publicKey)))
  const reviewer=createIndependentPluginReviewer({roots,revocations:{schema:'armorbreak.plugin-revocations/v1',keys:[...s.keys],authorities:[...s.authorities]}})
  return {...reviewer.review(snapshot,receipts),policyCheckpoint:this.checkpoint()}
 }
 async withCommitLease(operation){if(typeof operation!=='function')throw new Error('PLUGIN_POLICY_OPERATION_REQUIRED');const release=this.#lease();try{this.#load();return await operation()}finally{release()}}
}

/** Fresh local state only; preexisting directories are never initialized or overwritten. */
export function createPersistentPluginReviewer({directory,policy,policyPublicKey}){
 const publicKey=key(policyPublicKey),p=signedPolicy(policy,publicKey);validNow(p)
 directory=resolve(directory);mkdirSync(directory,{mode:0o700})
 if(realpathSync(directory)!==directory)throw new Error('PLUGIN_POLICY_DIRECTORY_DRIFT')
 const body={schema:'armorbreak.plugin-policy-event/v1',sequence:1,previous:ZERO,operation:'policy',payload:structuredClone(policy)}
 const fd=openSync(join(directory,'policy.ndjson'),'wx',0o600);try{writeAll(fd,Buffer.from(canonicalConfig({...body,digest:hash(body)})+'\n'))}finally{closeSync(fd)}
 return new PersistentReviewer(TOKEN,{directory,policyPublicKey})
}
export function openPersistentPluginReviewer(options){return new PersistentReviewer(TOKEN,options)}
