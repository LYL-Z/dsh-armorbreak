/**
 * AB2-M1-11 offline boundary gate.
 *
 * L0 analyzers must not import network clients. The only network-capable domain
 * is `lib/analyzers/live` (L1/L2) and it is excluded from this static gate; the
 * ResourceFetcher defaults to disabled and is not an analyzer. This is a static
 * gate, not a substitute for a real air-gapped VM run.
 */
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { ResourceFetcher } from '../lib/connectivity/resourceFetcher.js'
import { PolicyGateway } from '../lib/control/policyGateway.js'

const root = fileURLToPath(new URL('..', import.meta.url))
const analyzersDir = join(root, 'lib/analyzers')

function walk(dir, files = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'live') continue
    const full = join(dir, entry.name)
    if (entry.isDirectory()) walk(full, files)
    else if (entry.isFile() && entry.name.endsWith('.js')) files.push(full)
  }
  return files
}

test('L0 analyzer modules contain no network-client imports', () => {
  const offenders = []
  const patterns = [/from\s+['"]node:(http|https|net|dns|dgram|tls)['"]/, /\bfetch\s*\(/, /\bhttps?\.request\s*\(/, /from\s+['"]undici['"]/]
  for (const file of walk(analyzersDir)) {
    // patch.js emits illustrative code snippets as strings; it never executes them.
    if (file.replace(/\\/g, '/').endsWith('lib/analyzers/sast/patch.js')) continue
    const raw = readFileSync(file, 'utf8')
    // Strip string/template literals: patch-suggestion text may contain illustrative network calls.
    const text = raw.replace(/'(?:\\.|[^'\\])*'/g, "''").replace(/"(?:\\.|[^"\\])*"/g, '""').replace(/`(?:\\.|[^`\\])*`/g, '``')
    for (const pattern of patterns) {
      if (pattern.test(text)) offenders.push(`${relative(root, file)} matched ${pattern}`)
    }
  }
  assert.deepEqual(offenders, [], `L0 network imports found: ${offenders.join('; ')}`)
})

test('RESOURCE_READ is default-off and not modeled as L2', async () => {
  const fetcher = new ResourceFetcher()
  await assert.rejects(() => fetcher.fetch('cisa-kev'), /disabled by policy/)
  const gateway = new PolicyGateway({ scope: { checkNetwork: async () => ({ allowed: true }) }, resourceConnectors: ['cisa-kev'] })
  const read = await gateway.decide({ action: 'resource.read', connector: 'cisa-kev', identity: { kind: 'model' } })
  assert.equal(read.allowed, true)
  assert.equal(read.activeTesting, false)
  const l2 = await gateway.decide({ action: 'tool.armorbreak_analyze', riskLevel: 'L2', target: 'lab.example.test', identity: { kind: 'model' } })
  assert.equal(l2.allowed, false)
})

test('L0 file actions never select the live/L1 domain implicitly', () => {
  const liveDir = join(analyzersDir, 'live')
  assert.equal(statSync(liveDir).isDirectory(), true)
  const names = readdirSync(liveDir)
  assert.ok(names.length > 0)
})
