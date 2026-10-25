import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ScopePolicy } from '../lib/core/scope.js'
import { searchFiles } from '../lib/core/files.js'

test('file search terminates catastrophic regular expressions in an isolated worker', async () => {
  const base = await mkdtemp(join(tmpdir(), 'abm-search-redos-'))
  const workspace = join(base, 'workspace')
  const stateRoot = join(base, 'state')
  await mkdir(workspace)
  await writeFile(join(workspace, 'sample.txt'), `${'a'.repeat(40)}!\n`)

  const scopeUrl = new URL('../lib/core/scope.js', import.meta.url).href
  const filesUrl = new URL('../lib/core/files.js', import.meta.url).href
  const source = `
    import { ScopePolicy } from ${JSON.stringify(scopeUrl)}
    import { searchFiles } from ${JSON.stringify(filesUrl)}
    const scope = new ScopePolicy({ stateRoot: process.env.STATE_ROOT })
    const result = await searchFiles(scope, {
      workspaceRoot: process.env.WORKSPACE,
      path: process.env.WORKSPACE,
      pattern: '(a+)+$',
    })
    console.log(JSON.stringify({ allowed: result.allowed, code: result.code ?? null, reason: result.reason ?? null }))
  `

  try {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], {
      env: { ...process.env, STATE_ROOT: stateRoot, WORKSPACE: workspace },
      encoding: 'utf8',
      timeout: 5_000,
      windowsHide: true,
    })
    assert.equal(result.error, undefined, `child process did not finish: ${result.error?.message ?? ''}`)
    assert.equal(result.status, 0, result.stderr)
    const output = JSON.parse(result.stdout)
    assert.equal(output.allowed, false)
    assert.equal(output.code, 'REGEX_TIMEOUT', JSON.stringify(output))
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})

test('file search preserves ordinary regex use and rejects invalid or oversized patterns', async () => {
  const base = await mkdtemp(join(tmpdir(), 'abm-search-pattern-'))
  const workspace = join(base, 'workspace')
  await mkdir(workspace)
  await writeFile(join(workspace, 'sample.txt'), 'alpha\nbeta\n')
  const manyWorkspace = join(workspace, 'many')
  await mkdir(manyWorkspace)
  await writeFile(join(manyWorkspace, 'many.txt'), `${Array.from({ length: 75 }, () => 'x').join('\n')}\n`)
  const scope = new ScopePolicy({ stateRoot: join(base, 'state') })
  const input = { workspaceRoot: workspace, path: workspace }

  try {
    const ordinary = await searchFiles(scope, { ...input, pattern: 'alpha|gamma' })
    assert.equal(ordinary.allowed, true)
    assert.deepEqual(ordinary.data.matches.map(({ line, text }) => ({ line, text })), [{ line: 1, text: 'alpha' }])

    const invalid = await searchFiles(scope, { ...input, pattern: '[' })
    assert.equal(invalid.allowed, false)
    assert.equal(invalid.code, 'INVALID_PATTERN')

    const oversized = await searchFiles(scope, { ...input, pattern: 'a'.repeat(201) })
    assert.equal(oversized.allowed, false)
    assert.equal(oversized.code, 'PATTERN_TOO_LONG')

    const bounded = await searchFiles(scope, {
      ...input,
      path: manyWorkspace,
      pattern: '^x$',
      maxResults: 'not-a-number',
    })
    assert.equal(bounded.allowed, true)
    assert.equal(bounded.data.matches.length, 50)
    assert.equal(bounded.data.truncated, true)
  } finally {
    await rm(base, { recursive: true, force: true })
  }
})
