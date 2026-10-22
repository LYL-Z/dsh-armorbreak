import assert from 'node:assert/strict'
import test from 'node:test'

import { scanSecrets, scanSourceForSecrets } from '../lib/analyzers/sast/secrets.js'

function source(path, line) {
  return { path, buffer: Buffer.from(`${line}\n`, 'utf8') }
}

test('sast.secrets suppresses scanner-rule text and AWS documentation examples, not real keys', () => {
  const ruleSource = source(
    'D:/dsh-ABM/armorbreak/lib/analyzers/sast/secrets.js',
    "return matchText.replace(/-----[A-Z ]*PRIVATE KEY-----/g, '-----BEGIN PRIVATE KEY----- [content omitted]')",
  )
  const rule = scanSourceForSecrets(ruleSource)
  assert.equal(rule.findings.length, 0)
  assert.equal(rule.suppressed[0].reason, 'scanner-own-redaction-rule-text')

  const awsSource = source(
    'D:/dsh-ABM/armorbreak/scripts/v2/core-benchmark.mjs',
    "const fixture = 'AKIAIOSFODNN7EXAMPLE'",
  )
  const awsExample = scanSourceForSecrets(awsSource)
  assert.equal(awsExample.findings.length, 0)
  assert.equal(awsExample.suppressed[0].reason, 'aws-documentation-example')

  const realSource = source(
    'D:/dsh-ABM/armorbreak/src/real.js',
    "const key = 'AKIA1234567890ABCDEF'",
  )
  const real = scanSourceForSecrets(realSource)
  assert.equal(real.findings.length, 1)
  assert.equal(real.secrets[0].type, 'aws-access-key')
  assert.equal(real.suppressed.length, 0)

  const aggregate = scanSecrets([ruleSource, awsSource, realSource])
  assert.equal(aggregate.findings.length, 1)
  assert.ok(aggregate.stats.suppressed >= 2)
  assert.deepEqual(aggregate.stats.suppressedReasons.sort(), ['aws-documentation-example', 'scanner-own-redaction-rule-text'])
})
