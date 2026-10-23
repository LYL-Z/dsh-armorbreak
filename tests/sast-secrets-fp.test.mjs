import assert from 'node:assert/strict'
import test from 'node:test'

import { scanSecrets, scanSourceForSecrets } from '../lib/analyzers/sast/secrets.js'

function source(path, line) {
  return { path, buffer: Buffer.from(`${line}\n`, 'utf8') }
}

test('sast.secrets reports PEM headers even on scanner source lines and preserves exact AWS documentation suppression', () => {
  const scannerPath = 'D:/checkout/lib/analyzers/sast/secrets.js'
  const safeRuleSource = source(
    scannerPath,
    "return matchText.replace(/-----[A-Z ]*PRIVATE KEY-----/g, privateKeyHeader + ' [内容已省略]')",
  )
  const safeRule = scanSourceForSecrets(safeRuleSource)
  assert.equal(safeRule.findings.length, 0)
  assert.equal(safeRule.suppressed.length, 0)

  const pemHeader = ['-----', 'BEGIN PRIVATE KEY', '-----'].join('')
  const attackSource = source(scannerPath, "const note = 'matchText.replace'; const privateKey = '" + pemHeader + "'")
  const attack = scanSourceForSecrets(attackSource)
  assert.equal(attack.findings.length, 1)
  assert.equal(attack.secrets[0].type, 'private-key-block')
  assert.equal(attack.suppressed.length, 0)

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

  const aggregate = scanSecrets([safeRuleSource, attackSource, awsSource, realSource])
  assert.equal(aggregate.findings.length, 2)
  assert.ok(aggregate.stats.suppressed >= 1)
  assert.deepEqual(aggregate.stats.suppressedReasons, ['aws-documentation-example'])
})
