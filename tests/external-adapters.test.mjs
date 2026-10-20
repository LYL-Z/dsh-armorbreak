/**
 * Stage B adapter tests: Semgrep / Trivy JSON normalization and failure paths.
 * No external tool is required: capability runs use the env.execExternal test seam
 * that the runner never sets. The missing-tool test skips if the tool is installed.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import test from 'node:test'

import { parseSemgrepReport, parseTrivyReport, semgrepCapability, trivyCapability } from '../lib/analyzers/external/adapters.js'

function hasCommand(command) {
  try {
    execFileSync(command, ['--version'], { stdio: 'ignore', timeout: 20_000 })
    return true
  } catch {
    return false
  }
}

const SEMGREP_REPORT = {
  version: '1.99.0',
  results: [
    {
      check_id: 'javascript.lang.security.audit.eval',
      path: 'src/app.js',
      start: { line: 12, col: 3 },
      end: { line: 12, col: 25 },
      extra: {
        severity: 'ERROR',
        message: 'Detected eval() usage\nsecond line ignored',
        lines: '  return eval(userInput)',
        metadata: { cwe: ['CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code'] },
      },
    },
    {
      check_id: 'javascript.lang.security.audit.hardcoded-secret',
      path: 'src/config.js',
      start: { line: 3 },
      end: { line: 3 },
      extra: { severity: 'WARNING', message: 'Hardcoded secret', lines: 'const AWS_KEY = "AKIA..."' },
    },
  ],
  errors: [],
  paths: { scanned: ['src/app.js', 'src/config.js'] },
}

const TRIVY_REPORT = {
  SchemaVersion: 2,
  Results: [
    {
      Target: 'package-lock.json',
      Class: 'lang-pkgs',
      Type: 'npm',
      Vulnerabilities: [
        {
          VulnerabilityID: 'CVE-2024-0001',
          PkgName: 'lodash',
          InstalledVersion: '4.17.20',
          FixedVersion: '4.17.21',
          Severity: 'HIGH',
          Title: 'Prototype pollution',
          CweIDs: ['CWE-1321'],
          CVSS: { nvd: { V3Score: 7.4 } },
        },
      ],
    },
    {
      Target: '.env',
      Class: 'secret',
      Secrets: [{ RuleID: 'aws-access-key-id', Severity: 'CRITICAL', Title: 'AWS Access Key', StartLine: 4 }],
    },
    {
      Target: 'Dockerfile',
      Class: 'config',
      Misconfigurations: [{ ID: 'DS002', Severity: 'MEDIUM', Title: 'Root user', Message: 'Container runs as root', CauseMetadata: { StartLine: 9 }, Resolution: 'Add a non-root USER' }],
    },
  ],
}

test('Semgrep JSON normalizes to hypothesis findings with location and source rule', () => {
  const parsed = parseSemgrepReport(JSON.stringify(SEMGREP_REPORT))
  assert.equal(parsed.findings.length, 2)
  const evalFinding = parsed.findings[0]
  assert.equal(evalFinding.severity, 'critical')
  assert.equal(evalFinding.verification, 'hypothesis')
  assert.equal(evalFinding.sourceTool, 'semgrep')
  assert.equal(evalFinding.sourceRule, 'javascript.lang.security.audit.eval')
  assert.deepEqual(evalFinding.location, { file: 'src/app.js', startLine: 12, endLine: 12 })
  assert.match(evalFinding.title, /Detected eval/)
  assert.match(evalFinding.cwe ?? '', /CWE-95/)
  assert.equal(parsed.data.resultCount, 2)
  assert.equal(parsed.data.reportedFindings, 2)
  assert.equal(parsed.data.scannedPaths, 2)
  assert.match(parsed.evidence[0].excerpt, /src\/app\.js:12/)
})

test('Semgrep malformed or wrong-shape JSON is rejected instead of silently normalized', () => {
  assert.throws(() => parseSemgrepReport('{not json'), /not valid JSON/)
  assert.throws(() => parseSemgrepReport('{}'), /not a Semgrep report/)
  assert.throws(() => parseTrivyReport('[]'), /not a Trivy report/)
  assert.throws(() => parseTrivyReport('{}'), /not a Trivy report/)
})

test('Trivy JSON normalizes vulnerabilities, secrets and misconfigurations separately', () => {
  const parsed = parseTrivyReport(JSON.stringify(TRIVY_REPORT))
  assert.equal(parsed.findings.length, 3)
  const vulnerability = parsed.findings[0]
  assert.equal(vulnerability.sourceRule, 'CVE-2024-0001')
  assert.equal(vulnerability.severity, 'high')
  assert.equal(vulnerability.cvss, 7.4)
  assert.equal(vulnerability.location.package, 'lodash')
  assert.equal(vulnerability.location.fixedVersion, '4.17.21')
  assert.match(vulnerability.remediation, /Upgrade lodash/)
  const secret = parsed.findings[1]
  assert.equal(secret.severity, 'critical')
  assert.equal(secret.confidence, 'low')
  assert.equal(secret.location.kind, 'secret')
  assert.equal(parsed.findings[2].location.kind, 'configuration')
  assert.equal(parsed.findings[2].severity, 'medium')
  assert.equal(parsed.data.resultCount, 3)
  assert.deepEqual([...parsed.data.kinds].sort(), ['config', 'lang-pkgs', 'secret'])
})

test('normalization is bounded and deterministic', () => {
  const parsed = parseSemgrepReport(JSON.stringify(SEMGREP_REPORT), { maxFindings: 1 })
  assert.equal(parsed.findings.length, 1)
  assert.equal(parsed.data.truncated, true)
  const again = parseSemgrepReport(JSON.stringify(SEMGREP_REPORT), { maxFindings: 1 })
  assert.deepEqual(again.findings, parsed.findings)
  assert.doesNotThrow(() => JSON.stringify(parsed))
})

test('semgrep capability runs through the injected executor and reports normalized data', async () => {
  const result = await semgrepCapability.run({
    targetPath: 'D:\\repo',
    options: { config: 'D:\\rules\\semgrep.yml' },
    env: { execExternal: async () => ({ stdout: JSON.stringify(SEMGREP_REPORT), stderr: '', exitCode: 0 }) },
  })
  assert.equal(result.findings.length, 2)
  assert.match(result.summary, /Semgrep/)
  assert.equal(result.meta.verificationDefault, 'hypothesis')
  assert.equal(result.data.ruleConfig, 'D:\\rules\\semgrep.yml')
  assert.doesNotThrow(() => JSON.stringify(result))
})

test('trivy capability builds offline-db args and reports normalized data', async () => {
  let seen = null
  const result = await trivyCapability.run({
    targetPath: 'D:\\repo',
    options: { severity: 'CRITICAL' },
    env: {
      execExternal: async (command, args) => {
        seen = { command, args }
        return { stdout: JSON.stringify(TRIVY_REPORT), stderr: '', exitCode: 0 }
      },
    },
  })
  assert.equal(seen.command, 'trivy')
  assert.deepEqual(seen.args.slice(0, 2), ['fs', '--format'])
  assert.ok(seen.args.includes('--skip-db-update'))
  assert.ok(seen.args.includes('--severity'))
  assert.ok(seen.args.includes('CRITICAL'))
  assert.equal(result.findings.length, 3)
  assert.equal(result.data.dbDownloadAllowed, false)
  assert.equal(result.meta.offlineDb, true)
})

test('missing external tool produces actionable guidance, not a silent downgrade', { skip: hasCommand('semgrep') }, async () => {
  await assert.rejects(
    () => semgrepCapability.run({ targetPath: 'D:\\repo', options: { config: 'rules.yml' }, env: {} }),
    /not installed|not on PATH|Semgrep/,
  )
})
