import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import adapter, { legacy } from '../packages/adapter-dsh/index.js'

test('adapter-dsh still registers the legacy ArmorBreak tools and L0 health', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'abm-dsh-adapter-'))
  const defs = new Map()
  const ctx = {
    tools: { register(definition) { defs.set(definition.name, definition); return () => {} } },
    get(key) { return key === 'workingDirectory' ? { ensure: async () => workspace } : undefined },
    logger: { warn() {} },
  }
  legacy.tools.apply(ctx)
  for (const name of ['armorbreak_health', 'armorbreak_capabilities', 'armorbreak_analyze', 'armorbreak_environment']) {
    assert.ok(defs.has(name), `missing legacy tool ${name}`)
  }
  const value = await defs.get('armorbreak_health').execute({ workspace })
  assert.match(value.text, /ArmorBreak 环境健康/)
  assert.equal(value.data.capabilities.length, 50)
})
