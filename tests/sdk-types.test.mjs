import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('SDK contract types are generated and compile with tsc', async () => {
  const generated = spawnSync(process.execPath, ['scripts/v2/generate-sdk-types.mjs', '--check'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(generated.status, 0, generated.stderr)
  const contract = await readFile('packages/sdk-ts/generated/contract.d.ts', 'utf8')
  for (const method of ['health', 'capabilities', 'analyze', 'task', 'tasks', 'evidence', 'report']) {
    assert.match(contract, new RegExp(`'${method}'`))
  }
  const tsc = spawnSync(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(tsc.status, 0, `${tsc.stdout}\n${tsc.stderr}`)
})
