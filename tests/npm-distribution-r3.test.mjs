import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { verifyNpmDistribution } from '../scripts/v24/verify-npm-distribution.mjs'

test('frozen actual npm pack installs and runs all declared runtime surfaces in a fresh consumer', {timeout:120000}, async t => {
  const parent=await mkdtemp(join(tmpdir(),'ab-npm-r3-'));t.after(()=>rm(parent,{recursive:true,force:true}))
  const result=await verifyNpmDistribution({repositoryRoot:process.cwd(),outputRoot:join(parent,'acceptance')})
  assert.equal(result.status,'PASS_ACTUAL_PACK_INSTALL_IMPORT_RUNTIME')
  assert.equal(result.checks.yaml,'2.9.1')
  assert.equal(result.checks.configuration,'INSTALLED_APPROVED_SYNTHETIC_APPLY_AND_EXACT_RESTORE')
})
