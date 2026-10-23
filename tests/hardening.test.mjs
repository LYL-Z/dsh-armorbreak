/**
 * Hardening tests for issues found during the post-install audit:
 *   - a port-scoped authorization/approval must not cover a portless target
 *   - the YAML subset parser must bound flow nesting and reject prototype keys
 *   - every shipped text file must be valid UTF-8 (source quality gate)
 */
import assert from 'node:assert/strict'
import { mkdtemp, readdir, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { ScopePolicy, networkTargetMatches, parseNetworkTarget } from '../lib/core/scope.js'
import { parseYamlLite, YamlParseError } from '../lib/analyzers/web/yaml-lite.js'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

async function tempDir(prefix = 'abm-hard-') {
  return mkdtemp(join(tmpdir(), prefix))
}

test('port-scoped network targets never match a portless host', () => {
  const pattern443 = { host: 'lab.example.test', ports: [443] }
  assert.equal(networkTargetMatches(pattern443, { host: 'lab.example.test', port: null }), false)
  assert.equal(networkTargetMatches(pattern443, { host: 'lab.example.test', port: 443 }), true)
  assert.equal(networkTargetMatches(pattern443, { host: 'lab.example.test', port: 80 }), false)
  assert.equal(networkTargetMatches({ host: 'lab.example.test' }, { host: 'lab.example.test', port: null }), true)
})

test('checkNetwork applies the port restriction end to end', async () => {
  const scope = new ScopePolicy({ stateRoot: await tempDir(), dnsLookup: async () => ['8.8.8.8'] })
  await scope.authorize({ purpose: 'port-scoped lab', operator: 'tester', networkTargets: ['lab.example.test:443'], riskCeiling: 'L2', ttlMs: 60_000 })
  const portless = await scope.checkNetwork({ taskId: 't1', target: 'lab.example.test' })
  assert.equal(portless.allowed, false)
  assert.equal(portless.code, 'NETWORK_OUT_OF_SCOPE')
  const approval = await scope.recordApproval({ kind: 'L2', taskId: 't1', target: 'lab.example.test:443', outcome: 'allowed-once', source: 'test' })
  const allowed = await scope.checkNetwork({ taskId: 't1', target: 'lab.example.test:443', approvalId: approval.id })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.code, 'NETWORK_AUTHORIZED')
  void parseNetworkTarget
})

test('YAML flow nesting is bounded instead of overflowing the stack', () => {
  // A bare value is not valid JSON, so the lenient flow parser handles it and must bound recursion.
  const deep = `${'['.repeat(500)}x${']'.repeat(500)}`
  assert.throws(() => parseYamlLite(`value: ${deep}\n`), (error) => error instanceof YamlParseError && /嵌套/.test(error.message))
})

test('YAML parser rejects prototype-polluting keys', () => {
  assert.throws(() => parseYamlLite('a:\n  __proto__:\n    polluted: true\n'), (error) => error instanceof YamlParseError && /危险键名/.test(error.message))
  assert.throws(() => parseYamlLite('value: {__proto__: {polluted: true}}\n'), (error) => error instanceof YamlParseError && /危险键名/.test(error.message))
  assert.throws(() => parseYamlLite('constructor:\n  prototype:\n    polluted: true\n'), (error) => error instanceof YamlParseError && /危险键名/.test(error.message))
  assert.equal(/** @type {any} */ ({}).polluted, undefined)
})

test('all shipped text files are valid UTF-8', async () => {
  /** @type {string[]} */
  const files = []
  /** @param {string} dir */
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (['.git', 'node_modules', '.armorbreak'].includes(entry.name)) continue
        await walk(join(dir, entry.name))
      } else if (/\.(js|mjs|json|md|yml|yaml)$/.test(entry.name)) {
        files.push(join(dir, entry.name))
      }
    }
  }
  await walk(ROOT)
  assert.ok(files.length > 50, 'expected the project tree to be scanned')
  const invalid = []
  for (const file of files) {
    const bytes = await readFile(file)
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      invalid.push(relative(ROOT, file))
    }
  }
  assert.deepEqual(invalid, [], `invalid UTF-8 in: ${invalid.join(', ')}`)
})
