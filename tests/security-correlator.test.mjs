import assert from 'node:assert/strict'
import { readFile, readdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { sha256 } from '../packages/core/src/util.js'
import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { generateTaskReport } from '../lib/core/reports.js'
import { getWorkflow } from '../packages/core/src/workflows.js'
import { correlateEvidenceBundle, EVIDENCE_BUNDLE_SCHEMA } from '../lib/analyzers/security/correlator.js'
import { scanSource } from '../lib/analyzers/sast/scanner.js'
import { vulnerabilityContrastCorpus } from './fixtures/m4/vulnerability-contrast-corpus.mjs'
import { evaluateVulnerabilityContrastCorpus } from './fixtures/m4/evaluate-corpus.mjs'
import { makeTestTempDirectory } from './helpers/temporary.js'

function bundle(sources, extras = {}) {
  return {
    schema: EVIDENCE_BUNDLE_SCHEMA,
    artifact: { sha256: 'a'.repeat(64), path: 'src/example.js' },
    ...extras,
    sources,
  }
}

function correlate(value, options = {}) {
  return correlateEvidenceBundle(Buffer.from(JSON.stringify(value)), options)
}

test('owned contrast corpus has 20 vulnerable/safe/lookalike groups and exact local scanner metrics', () => {
  assert.equal(vulnerabilityContrastCorpus.length, 20)
  assert.equal(new Set(vulnerabilityContrastCorpus.map((item) => item.cwe)).size, 5)
  for (const group of vulnerabilityContrastCorpus) assert.deepEqual(Object.keys(group.variants).sort(), ['lookalike', 'secure', 'vulnerable'])
  const metrics = evaluateVulnerabilityContrastCorpus(vulnerabilityContrastCorpus)
  assert.deepEqual(metrics.totals, { tp: 20, fp: 20, fn: 0, tn: 20, samples: 60, precision: 0.5, recall: 1, falsePositiveRate: 0.5 })
  for (const category of Object.values(metrics.byCategory)) assert.deepEqual(category, { tp: 4, fp: 4, fn: 0, tn: 4, samples: 12, precision: 0.5, recall: 1, falsePositiveRate: 0.5 })
})

test('correlation preserves original sources while keeping evidence maturity separate from vulnerability status', () => {
  const code = "const rows = db.query('SELECT * FROM users WHERE id=' + req.query.id)"
  const hash = sha256(code)
  const first = {
    id: 'armorbreak-sast-01', kind: 'armorbreak', sourceFamily: 'armorbreak-sast',
    findings: [{ title: 'SQL string concatenation', severity: 'high', cwe: 'CWE-89', target: 'src/example.js:7', verification: 'hypothesis', vulnerabilityStatus: 'confirmed', reachability: 'reachable', impactScope: 'high', evidence: [{ excerpt: code }] }],
  }
  const second = {
    id: 'semgrep-01', kind: 'semgrep-json', sourceFamily: 'semgrep',
    document: { results: [{ check_id: 'javascript.lang.security.audit.query-string', path: 'src/example.js', start: { line: 7, col: 1 }, extra: { severity: 'ERROR', message: 'Possible SQL injection', lines: code, metadata: { cwe: ['CWE-89'], impactScope: 'high', reachability: 'reachable' } } }] },
  }
  const input = Buffer.from(JSON.stringify(bundle([first, second], { artifact: { sha256: hash, path: 'src/example.js' } })))
  const result = correlateEvidenceBundle(input)
  assert.equal(result.data.counts.sourceFindings, 2)
  assert.equal(result.data.counts.correlationGroups, 1)
  const finding = result.data.correlations[0]
  assert.equal(finding.evidenceStatus, 'corroborated')
  assert.equal(finding.verification, 'corroborated')
  assert.equal(finding.vulnerabilityStatus, 'not_tested')
  assert.equal(finding.triagePriority, 'P1')
  assert.equal(finding.cvss, null)
  assert.deepEqual(finding.sourceFindingIds, ['armorbreak-sast-01:1', 'semgrep-01:1'])
  assert.equal(finding.sources[0].originalFinding.vulnerabilityStatus, 'confirmed', 'the untrusted source claim remains visible as source data')
  assert.equal(result.findings[0].vulnerabilityStatus, 'not_tested', 'an imported claim cannot promote itself to confirmed')
  const report = JSON.parse(result.artifacts.find((item) => item.name.endsWith('.sarif.json')).content)
  assert.equal(report.version, '2.1.0')
  assert.equal(report.runs[0].results[0].relatedLocations.length, 2)
  assert.equal(report.runs[0].results[0].properties.vulnerabilityStatus, 'not_tested')
  assert.equal(report.runs[0].results[0].locations[0].physicalLocation.region.startLine, 7)
  const repeated = correlateEvidenceBundle(input)
  assert.deepEqual(repeated.data.correlations, result.data.correlations)
  assert.equal(repeated.artifacts[0].content, result.artifacts[0].content)
})

test('same-family duplicates are observed, not independent corroboration; incomplete keys are kept separate', () => {
  const common = { title: 'fact', severity: 'medium', cwe: 'CWE-79', target: 'src/view.js:3', verification: 'observed', evidence: [{ excerpt: 'element.innerHTML = value' }] }
  const sameFamily = correlate(bundle([
    { id: 'source-one', kind: 'armorbreak', sourceFamily: 'armorbreak-sast', findings: [common] },
    { id: 'source-two', kind: 'armorbreak', sourceFamily: 'armorbreak-sast', findings: [common] },
  ]))
  assert.equal(sameFamily.data.correlations.length, 1)
  assert.equal(sameFamily.data.correlations[0].evidenceStatus, 'observed')
  const incomplete = correlate(bundle([
    { id: 'missing-location', kind: 'armorbreak', findings: [{ ...common, target: null }] },
    { id: 'missing-context', kind: 'armorbreak', findings: [{ ...common, evidence: [] }] },
  ]))
  assert.equal(incomplete.data.counts.correlationGroups, 2)
  assert.equal(incomplete.data.counts.incompleteKeys, 2)
  assert.equal(incomplete.data.correlations.every((item) => item.grouping.completeKey === false), true)
})

test('derived report strings redact credentials and absolute path components', () => {
  const secret = 'ghp_012345678901234567890123456789012345'
  const result = correlate(bundle([
    {
      id: 'private-source', kind: 'armorbreak', sourceFamily: 'scanner',
      findings: [{
        title: `Authorization: Bearer ${secret}`,
        severity: 'high', cwe: 'CWE-89',
        target: 'C:\\Users\\刘佑林\\客户资料\\private-source.js:12',
        evidence: [{ excerpt: `token=${secret} observed at C:\\Users\\刘佑林\\客户资料\\private-source.js` }],
        cookie: `session=${secret}`,
      }],
    },
  ]))
  const serialized = JSON.stringify({ report: result.data, artifacts: result.artifacts, findings: result.findings })
  assert.equal(serialized.includes(secret), false)
  assert.equal(serialized.includes('刘佑林'), false)
  assert.equal(serialized.includes('客户资料'), false)
  assert.match(serialized, /REDACTED/)
  assert.match(serialized, /external\/[a-f0-9]{16}:12/)
})

test('Trivy, explicit OSV matches, CycloneDX and snapshot provenance remain offline and unconverted', () => {
  const result = correlate(bundle([
    { id: 'trivy-results', kind: 'trivy-json', sourceFamily: 'trivy', document: { Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2025-0001', PkgName: 'sample-pkg', InstalledVersion: '1.2.3', FixedVersion: '1.2.4', Severity: 'HIGH' }] }] } },
    { id: 'osv-match', kind: 'osv-match', sourceFamily: 'osv', document: { matches: [{ id: 'CVE-2025-0001', package: { ecosystem: 'npm', name: 'sample-pkg' }, version: '1.2.3', location: 'package-lock.json', summary: 'advisory match' }] } },
    { id: 'bom', kind: 'sbom-cyclonedx', sha256: 'b'.repeat(64), document: { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'sample-pkg', version: '1.2.3', purl: 'pkg:npm/sample-pkg@1.2.3' }] } },
  ], {
    assessmentDate: '2026-10-29',
    databaseSnapshots: [{ id: 'OSV', source: 'local snapshot export', retrievedAt: '2026-10-28T00:00:00Z', snapshotDate: '2026-08-15', sha256: 'c'.repeat(64) }],
  }))
  assert.equal(result.data.correlations.length, 1)
  assert.deepEqual(result.data.correlations[0].sourceFamilies, ['osv', 'trivy'])
  assert.equal(result.data.correlations[0].vulnerabilityStatus, 'not_tested')
  assert.equal(result.data.supplyChain.sboms[0].format, 'CycloneDX')
  assert.equal(result.data.supplyChain.sboms[0].componentCount, 1)
  assert.equal(result.data.supplyChain.sboms[0].declaredSha256, 'b'.repeat(64))
  assert.equal(result.data.supplyChain.databaseSnapshots[0].staleStatus, 'current')
  assert.equal(result.data.supplyChain.networkAccess, 'none')
  assert.equal(result.data.limitations.some((item) => item.includes('version-range matched')), true)
  assert.equal(result.data.limitations.some((item) => item.includes('full SBOM documents are not copied')), true)
  assert.throws(() => correlate(bundle([{ id: 'bad-cdx', kind: 'sbom-cyclonedx', document: { specVersion: '1.6' } }])), /bomFormat/)
})

test('invalid hashes, unsupported sources, and over-limit source counts fail closed', () => {
  assert.throws(() => correlate({ ...bundle([{ id: 'empty', kind: 'armorbreak', findings: [] }]), artifact: { sha256: 'xyz' } }), /64-character SHA-256/)
  assert.throws(() => correlate(bundle([{ id: 'unsupported', kind: 'custom-raw' }])), /unsupported evidence source kind/)
  const tooMany = Array.from({ length: 201 }, (_, index) => ({ title: `f${index}`, cwe: 'CWE-89', target: `src/${index}.js:1`, evidence: [{ excerpt: `line ${index}` }] }))
  assert.throws(() => correlate(bundle([{ id: 'too-many', kind: 'armorbreak', findings: tooMany }])), /exceeds 200 findings/)
})

test('Runner executes UniversalSecurityReview on a local bundle and writes valid JSON/SARIF artifacts', async () => {
  const stateRoot = await makeTestTempDirectory('abm-m4-state-')
  const workspace = await makeTestTempDirectory('abm-m4-workspace-')
  const code = "const rows = db.query('SELECT * FROM users WHERE id=' + req.query.id)"
  const scan = scanSource({ path: 'src/example.js', buffer: Buffer.from(code) })
  const armorFinding = { ...scan.findings[0], vulnerabilityStatus: 'confirmed' }
  const evidenceBundle = bundle([
    { id: 'armorbreak-live-sast', kind: 'armorbreak', sourceFamily: 'armorbreak-sast', findings: [armorFinding] },
    { id: 'semgrep-live', kind: 'semgrep-json', sourceFamily: 'semgrep', document: { results: [{ check_id: 'semgrep.sql-injection', path: 'src/example.js', start: { line: 1, col: 1 }, extra: { severity: 'ERROR', message: 'SQL source/sink pattern', lines: code, metadata: { cwe: ['CWE-89'] } } }] } },
  ], { artifact: { sha256: sha256(code), path: 'src/example.js' } })
  const bundlePath = join(workspace, 'security-evidence.json')
  await writeFile(bundlePath, JSON.stringify(evidenceBundle), 'utf8')
  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  const workflow = getWorkflow('UniversalSecurityReview')
  const store = runtime.workspace(workspace).taskStore
  const task = await store.create({
    title: 'M4 offline correlation E2E',
    objective: 'Correlate local findings and preserve source evidence',
    targetPath: bundlePath,
    targetKind: 'file',
    workflowId: workflow.id,
    steps: workflow.steps.map((step) => ({ ...step, options: {} })),
  })
  const completed = await runtime.runner.runWorkflow(task)
  assert.equal(completed.state, 'COMPLETED')
  assert.equal(completed.steps[0].status, 'DONE')
  const evidenceState = await store.evidenceStore(task.id).readFindings()
  assert.equal(evidenceState.findings.length, 1)
  assert.equal(evidenceState.findings[0].verification, 'corroborated')
  assert.equal(evidenceState.findings[0].vulnerabilityStatus, 'not_tested')
  const artifactDir = join(store.taskDir(task.id), 'artifacts')
  const artifactNames = await readdir(artifactDir)
  const sarifName = artifactNames.find((name) => name.endsWith('.sarif.json'))
  const jsonName = artifactNames.find((name) => name.endsWith('.json') && !name.endsWith('.sarif.json'))
  assert.ok(sarifName)
  assert.ok(jsonName)
  const sarif = JSON.parse(await readFile(join(artifactDir, sarifName), 'utf8'))
  const correlation = JSON.parse(await readFile(join(artifactDir, jsonName), 'utf8'))
  assert.equal(sarif.version, '2.1.0')
  assert.equal(sarif.runs[0].results[0].relatedLocations.length, 2)
  assert.equal(correlation.counts.sourceFindings, 2)
  assert.equal(correlation.correlations[0].vulnerabilityStatus, 'not_tested')
  const taskSarif = await generateTaskReport(runtime, completed, { format: 'sarif' })
  const rendered = JSON.parse(await readFile(taskSarif.path, 'utf8'))
  assert.equal(rendered.version, '2.1.0')
  assert.equal(rendered.runs[0].results[0].properties.vulnerabilityStatus, 'not_tested')
})
