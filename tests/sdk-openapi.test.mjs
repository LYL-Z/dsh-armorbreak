import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('SDK OpenAPI is generated from the stable contract', async () => {
  const check = spawnSync(process.execPath, ['scripts/v2/generate-sdk-openapi.mjs', '--check'], { cwd: process.cwd(), encoding: 'utf8' })
  assert.equal(check.status, 0, check.stderr)
  const doc = JSON.parse(await readFile('packages/sdk-ts/openapi.json', 'utf8'))
  assert.equal(doc.openapi, '3.1.0')
  assert.ok(doc.paths['/mcp'].post)
  assert.ok(doc.paths['/health'].get)
  assert.deepEqual(doc['x-armorbreak-methods'], ['analyze', 'capabilities', 'evidence', 'health', 'report', 'task', 'tasks'])
  assert.equal(doc['x-armorbreak-security'].modelIsAuthority, false)
})
