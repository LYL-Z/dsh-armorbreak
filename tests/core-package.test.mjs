import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createCore } from '../packages/core/index.js'
import { redactText } from '../packages/core/src/util.js'
import { validateEvidenceEnvelope, validateInvocation } from '../packages/protocol/index.js'

const ctx = { principal: { id: 'local-user', kind: 'local-user' }, workspaceId: 'ws', requestId: 'req-1', traceId: 'trace-1' }

test('credential redaction uses syntax supported by host Node 22', () => {
  assert.equal(redactText('Bearer abcdefghijklmnop'), 'Bearer [REDACTED]')
  assert.equal(redactText('bearer abcdefghijklmnop'), 'Bearer [REDACTED]')
  assert.equal(redactText('Authorization: Bearer abcdefghijklmnop'), 'Authorization: [REDACTED] [REDACTED]')
})

test('Universal Core imports and lists capabilities without DSH/Cordis', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-core-'))
  const core = await createCore({ stateRoot })
  const capabilities = await core.capabilities(ctx)
  assert.equal(capabilities.length, 46)
  assert.equal(core.protocolVersion, '1.0.0')
  await core.close?.()
})

test('Core can be imported in a fresh Node process with no @deepseek-ai package', () => {
  const script = `
    import { createCore } from './packages/core/index.js'
    import { mkdtemp } from 'node:fs/promises'
    import { tmpdir } from 'node:os'
    import { join } from 'node:path'
    const core = await createCore({ stateRoot: await mkdtemp(join(tmpdir(), 'abm-core-child-')) })
    console.log(core.version, (await core.capabilities({ principal: { id: 'u', kind: 'local-user' }, workspaceId: 'w', requestId: 'r', traceId: 't' })).length)
  `
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], { cwd: process.cwd(), encoding: 'utf8' })
  assert.match(out, /0\.1\.0-p1 46/)
})

test('Core package source has no DSH/Cordis/DOM/Electron imports', async () => {
  const text = await readFile(join('packages/core', 'index.js'), 'utf8')
  const imports = text.match(/^import .*$/gm) ?? []
  assert.ok(imports.length > 0)
  for (const line of imports) assert.doesNotMatch(line, /@deepseek-ai|cordis|electron|document\.|window\./i)
  const pkg = JSON.parse(await readFile(join('packages/core', 'package.json'), 'utf8'))
  assert.deepEqual(pkg.dependencies ?? {}, {})
  assert.deepEqual(pkg.peerDependencies ?? {}, {})
})

test('protocol validates invocation and evidence envelopes', () => {
  assert.equal(validateInvocation(ctx).ok, true)
  assert.equal(validateInvocation({ principal: { id: 'x' } }).ok, false)
  assert.equal(validateEvidenceEnvelope({ traceId: 't', runId: 'r', taskId: 'k', principalId: 'p', origin: 'cli', targetHash: 'a'.repeat(64) }).ok, true)
  assert.equal(validateEvidenceEnvelope({ traceId: 't', runId: 'r', taskId: 'k', principalId: 'p', origin: 'cli', targetHash: 'bad' }).ok, false)
})

test('versioned JSON Schema files are present and parseable', async () => {
  for (const name of ['invocation', 'evidence-envelope', 'error']) {
    const schema = JSON.parse(await readFile(join('packages/protocol/schemas', `${name}.schema.json`), 'utf8'))
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
    assert.ok(schema.$id.startsWith('https://armorbreak.dev/schemas/v1/'))
    assert.ok(Array.isArray(schema.required))
  }
})
