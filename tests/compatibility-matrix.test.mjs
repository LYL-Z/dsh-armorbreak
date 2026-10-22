import assert from 'node:assert/strict'
import { readFile, stat } from 'node:fs/promises'
import test from 'node:test'

test('compatibility matrix has nine hosts and makes no unverified claims', async () => {
  const matrix = JSON.parse(await readFile('docs/v2/acceptance/compatibility-matrix.json', 'utf8'))
  assert.equal(matrix.hosts.length, 9)
  assert.deepEqual(matrix.hosts.map((row) => row.host).sort(), ['Claude Code', 'Codex', 'Cursor', 'DSH', 'Hermes Agent', 'Pi', 'TRAE', 'WorkBuddy', 'ZCode'].sort())
  const required = ['host', 'hostVersion', 'os', 'arch', 'integrationMethod', 'transport', 'installState', 'toolHandshake', 'taskRunState', 'policyDeniedTest', 'evidenceId', 'reportHash', 'testAt', 'commitSha', 'limitation']
  for (const row of matrix.hosts) {
    for (const field of required) assert.ok(field in row, `${row.host} missing ${field}`)
    assert.ok(row.limitation && row.limitation.length > 5)
    assert.ok(['real_verified', 'mock_verified', 'docs_only', 'blocked', 'not_installed'].includes(row.evidenceLevel))
    if (row.evidenceLevel === 'real_verified') assert.equal(row.taskRunState, 'L0_COMPLETED')
    if (row.installState === 'NOT_INSTALLED') {
      assert.equal(row.toolHandshake, 'NOT_RUN')
      assert.equal(row.taskRunState, 'NOT_RUN')
    }
  }
  assert.deepEqual(matrix.hosts.filter((row) => row.taskRunState === 'L0_COMPLETED').map((row) => row.host).sort(), ['Codex', 'DSH', 'Hermes Agent'])
  assert.deepEqual(matrix.hosts.filter((row) => row.toolHandshake === 'PASS').map((row) => row.host).sort(), ['Codex', 'DSH', 'Hermes Agent'])
  assert.equal(matrix.hosts.filter((row) => row.reportHash).length, 3)
  for (const row of matrix.hosts.filter((item) => item.evidenceId?.startsWith('docs/'))) {
    assert.equal((await stat(row.evidenceId)).isFile(), true)
  }
})
