import assert from 'node:assert/strict'
import { access, mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { ArmorBreakRuntime } from '../lib/core/runtime.js'
import { getWorkflow, listWorkflows } from '../lib/core/workflows.js'
import { analyzeSourceUnits, sourceLanguageForPath } from '../lib/analyzers/source/symbols.js'
import { fitSourceResult, sourceLayersForPath } from '../lib/analyzers/source/manifest.js'

const validJavaScript = [
  ['function declaration and call', 'function add(a, b) { return a + b }\nconst total = add(2, 3)\n'],
  ['class and method', 'class Counter { value = 0; increment() { this.value += 1 } }\n'],
  ['static import and export', "import { readFile as read } from 'node:fs/promises'\nexport const load = read\n"],
  ['JSX component', 'export function View() { return <main>ready</main> }\n', 'view.jsx'],
  ['object and destructuring', 'const source = { value: 3 }; const { value } = source;\n'],
]

const validTypeScript = [
  ['typed function and interface', 'interface User { id: string }\nexport function getId(user: User): string { return user.id }\n'],
  ['enum and class', 'enum Mode { Read, Write }\nclass Store { mode: Mode = Mode.Read }\n'],
  ['generic method', 'class Box<T> { constructor(public value: T) {} map<U>(f: (x: T) => U): Box<U> { return new Box(f(this.value)) } }\n'],
  ['type alias and export alias', 'type Pair = readonly [number, number]\nconst point: Pair = [1, 2]\nexport { point as origin }\n'],
  ['namespace and optional chaining', 'namespace App { export const label: string = "ok" }\nconst result = App?.label\n'],
]

const invalidJavaScript = [
  ['unfinished function parameters', 'function ( {'],
  ['missing variable initializer name', 'const = 1'],
  ['unterminated block', 'if (ready) { run()'],
  ['invalid object member', 'const item = { value: ; }'],
  ['unterminated export list', 'export { value'],
]

const invalidTypeScript = [
  ['unterminated interface', 'interface Item { name: string'],
  ['missing type annotation', 'const value: = 1'],
  ['invalid return expression', 'function add(a: number): number { return a + }'],
  ['missing type alias value', 'type Item = ;'],
  ['unterminated class', 'class Box { value: string'],
]

function parseOne(path, text, truncated = false) {
  return analyzeSourceUnits([{ path, text, truncated }])
}

test('M2 parses at least five valid JavaScript and TypeScript syntax fixtures with source locations', async (t) => {
  for (const [name, text, overridePath] of validJavaScript) {
    await t.test(`JavaScript: ${name}`, () => {
      const result = parseOne(overridePath ?? 'fixture.js', text)
      assert.equal(result.summary.filesParsed, 1)
      assert.equal(result.files[0].language, 'JavaScript')
      assert.equal(result.files[0].status, 'COMPLETE')
      assert.equal(result.files[0].syntaxErrorCount, 0)
      assert.equal(result.files[0].parserVersion, result.parser.version)
      assert.ok(result.files[0].languageVersion.includes(result.parser.version))
      assert.ok(result.files[0].symbols.length > 0)
      for (const symbol of result.files[0].symbols) {
        assert.ok(symbol.location.startLine >= 1)
        assert.ok(symbol.location.startColumn >= 1)
        assert.ok(symbol.location.endOffset >= symbol.location.startOffset)
      }
    })
  }
  for (const [name, text] of validTypeScript) {
    await t.test(`TypeScript: ${name}`, () => {
      const result = parseOne('fixture.ts', text)
      assert.equal(result.summary.filesParsed, 1)
      assert.equal(result.files[0].language, 'TypeScript')
      assert.equal(result.files[0].status, 'COMPLETE')
      assert.equal(result.files[0].syntaxErrorCount, 0)
      assert.equal(result.files[0].parserVersion, result.parser.version)
      assert.ok(result.files[0].languageVersion.includes(result.parser.version))
      assert.ok(result.files[0].symbols.length > 0)
    })
  }
})

test('M2 resolves same-file identifier references to emitted symbol IDs for JavaScript and TypeScript', async (t) => {
  const fixtures = [
    ['JavaScript', 'fixture.js', 'function add(a, b) { return a + b }\nconst total = add(2, 3)\n'],
    ['TypeScript', 'fixture.ts', 'interface User { id: string }\nexport function getId(user: User): string { return user.id }\n'],
  ]
  for (const [language, path, text] of fixtures) {
    await t.test(language, () => {
      const file = parseOne(path, text).files[0]
      const symbolIds = new Set(file.symbols.map((symbol) => symbol.id))
      const resolved = file.references.filter((reference) => reference.resolution === 'LOCAL_DECLARATION')
      assert.ok(resolved.length > 0)
      assert.ok(resolved.every((reference) => reference.targetSymbolIds.length > 0))
      assert.ok(resolved.every((reference) => reference.targetSymbolIds.every((id) => symbolIds.has(id))))
      assert.equal(file.coverage.crossFileResolution, false)
      assert.equal(file.coverage.typeChecking, false)
    })
  }
})

test('M2 reports syntax errors for five invalid fixtures in each supported language', async (t) => {
  for (const [name, text] of invalidJavaScript) {
    await t.test(`JavaScript: ${name}`, () => {
      const file = parseOne('broken.js', text).files[0]
      assert.equal(file.language, 'JavaScript')
      assert.ok(file.syntaxErrorCount > 0)
      assert.ok(file.syntaxErrors.length > 0)
      assert.equal(file.status, 'PARTIAL')
      assert.ok(file.syntaxErrors.every((error) => error.location.startLine >= 1))
    })
  }
  for (const [name, text] of invalidTypeScript) {
    await t.test(`TypeScript: ${name}`, () => {
      const file = parseOne('broken.ts', text).files[0]
      assert.equal(file.language, 'TypeScript')
      assert.ok(file.syntaxErrorCount > 0)
      assert.ok(file.syntaxErrors.length > 0)
      assert.equal(file.status, 'PARTIAL')
    })
  }
})

test('M2 marks macros and unsupported languages unsupported instead of inferring symbols', () => {
  for (const path of ['main.c', 'header.h', 'main.cpp', 'App.java', 'main.rs', 'module.py']) {
    assert.equal(sourceLanguageForPath(path), null, `${path} must not be advertised as an implemented parser`)
    assert.equal(analyzeSourceUnits([{ path, text: '#define VALUE 1\nint main() { return VALUE; }' }]).analysis.status, 'UNSUPPORTED')
  }
})

test('M2 separates product, test, generated, vendor, and build-output source layers', () => {
  assert.deepEqual(sourceLayersForPath('src/main.ts'), ['product'])
  assert.deepEqual(sourceLayersForPath('tests/unit.test.js'), ['test'])
  assert.deepEqual(sourceLayersForPath('src/generated/api.ts'), ['generated'])
  assert.deepEqual(sourceLayersForPath('vendor/library.js'), ['vendor'])
  assert.deepEqual(sourceLayersForPath('dist/app.js'), ['build-output'])
  assert.deepEqual(sourceLayersForPath('vendor/generated/example.test.js'), ['vendor', 'generated', 'test'])
})

test('M2 preserves deferred imports and marks reflection, eval, truncation, and record limits', () => {
  const text = [
    "import { remote } from './remote.js'",
    'const dynamic = import(moduleName)',
    'const loaded = require(name)',
    'const value = Reflect.get(target, key)',
    'eval(input)',
    'export { remote }',
  ].join('\n')
  const complete = parseOne('src/main.js', text).files[0]
  assert.ok(complete.imports.some((entry) => entry.module === './remote.js' && entry.resolution === 'DEFERRED_CROSS_FILE'))
  assert.ok(complete.unknownEdges.some((edge) => edge.kind === 'dynamic-import'))
  assert.ok(complete.unknownEdges.some((edge) => edge.kind === 'dynamic-require'))
  assert.ok(complete.unknownEdges.some((edge) => edge.kind === 'reflection'))
  assert.ok(complete.unknownEdges.some((edge) => edge.kind === 'dynamic-execution'))
  assert.equal(complete.coverage.crossFileResolution, false)
  assert.equal(complete.coverage.dataFlow, false)

  const truncated = parseOne('src/partial.ts', 'export function f(a: number) { return a }', true).files[0]
  assert.equal(truncated.truncated, true)
  assert.equal(truncated.status, 'PARTIAL')

  const limited = analyzeSourceUnits([{ path: 'src/large.ts', text: Array.from({ length: 80 }, (_, i) => `export const value${i} = ${i};`).join('\n') }], { maxRecords: 12 })
  assert.equal(limited.analysis.status, 'PARTIAL')
  assert.ok(limited.summary.omittedRecords > 0)
  assert.equal(limited.summary.recordsEmitted, 12)
  assert.ok(limited.analysis.limitsApplied.includes('maxRecords'))

  const omittedFiles = analyzeSourceUnits([
    { path: 'src/first.ts', text: 'export const first = 1' },
    { path: 'src/second.ts', text: 'export const second = 2' },
  ], { maxRecords: 1 })
  assert.equal(omittedFiles.summary.filesOmitted, 1)
  assert.equal(omittedFiles.summary.omittedRecords > 0, true)
  assert.equal(omittedFiles.analysis.status, 'PARTIAL')
})

test('M2 keeps serialized source IR within a one-kilobyte result budget', () => {
  const parsed = analyzeSourceUnits([{
    path: 'src/large.ts',
    text: Array.from({ length: 100 }, (_, i) => `export function veryLongFunctionName${i}(input: string) { const output${i} = input.trim(); return output${i} }`).join('\n'),
  }], { maxRecords: 300 })
  const data = {
    ...parsed,
    summary: { ...parsed.summary, filesListed: 1, sourceCandidates: 1, unsupportedLanguageFiles: 0, filesExcludedByLayer: 0, excludedFileDetailsOmitted: 0, unreadableFiles: 0, invalidEncodingFiles: 0, bytesRead: 20_000, truncatedFiles: 0 },
    unsupportedFiles: [],
    excludedFiles: [],
    analysis: { ...parsed.analysis, extraction: 'IN_MEMORY_ONLY_NO_CODE_EXECUTED' },
  }
  const bounded = fitSourceResult(data, 1024)
  assert.ok(Buffer.byteLength(JSON.stringify(bounded), 'utf8') <= 1024)
  assert.equal(bounded.summary.resultTruncated, true)
  assert.equal(bounded.analysis.status, 'PARTIAL')
  assert.ok(bounded.analysis.limitsApplied.includes('maxResultBytes'))
  assert.equal(bounded.summary.recordsEmitted, bounded.files.reduce((n, file) => n + file.symbols.length + file.imports.length + file.exports.length + file.references.length + file.unknownEdges.length + file.syntaxErrors.length, 0))
})

test('M2 integrates source.symbols and CrossLanguageSourceReview through the real Runner and PolicyGateway', async () => {
  const stateRoot = await mkdtemp(join(tmpdir(), 'abm-source-state-'))
  const workspace = await mkdtemp(join(tmpdir(), 'abm-source-workspace-'))
  await mkdir(join(workspace, 'src'), { recursive: true })
  await mkdir(join(workspace, 'tests'), { recursive: true })
  await mkdir(join(workspace, 'vendor'), { recursive: true })
  await mkdir(join(workspace, 'generated'), { recursive: true })
  const sentinel = join(workspace, 'source-must-not-execute.txt')
  await writeFile(join(workspace, 'src', 'main.ts'), [
    "import { helper } from './helper.js'",
    'export function run(input: string) { return helper(input) }',
  ].join('\n'))
  await writeFile(join(workspace, 'src', 'helper.js'), 'export function helper(value) { return value.trim() }\n')
  await writeFile(join(workspace, 'src', 'sample.py'), '#define NOT_JAVASCRIPT 1\n')
  await writeFile(join(workspace, 'src', 'payload.js'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(sentinel)}, 'executed')`)
  await writeFile(join(workspace, 'tests', 'fixture.test.js'), 'export const testFixture = true\n')
  await writeFile(join(workspace, 'vendor', 'library.js'), 'export function vendorCode() { return 1 }\n')
  await writeFile(join(workspace, 'generated', 'api.ts'), 'export interface GeneratedApi { id: string }\n')

  const runtime = new ArmorBreakRuntime({ stateRoot })
  await runtime.init()
  assert.equal(runtime.registry.diagnostics.length, 0)
  assert.equal(runtime.registry.get('source.symbols')?.riskLevel, 'L0')
  assert.ok(listWorkflows().some((workflow) => workflow.id === 'CrossLanguageSourceReview'))

  const workflow = getWorkflow('CrossLanguageSourceReview')
  const workflowTask = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized JS and TS syntax fixture',
    targetPath: workspace,
    targetKind: 'directory',
    workflowId: workflow.id,
    steps: workflow.steps,
  })
  await runtime.runner.prepareTask(workflowTask)
  const workflowResult = await runtime.runner.runWorkflow(workflowTask, { generateReport: false })
  assert.equal(workflowResult.state, 'COMPLETED')
  assert.equal(workflowResult.steps[0].status, 'DONE')

  const task = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized JS and TS source indexing fixture',
    targetPath: workspace,
    targetKind: 'directory',
    steps: [{ id: 'symbols', capabilityId: 'source.symbols' }],
  })
  const result = await runtime.runner.runCapability({ task, capabilityId: 'source.symbols' })
  assert.equal(result.capability, 'source.symbols')
  assert.equal(result.data.schemaVersion, 'armorbreak.source-symbol-ir/v1')
  assert.ok(result.data.files.some((file) => file.path === 'src/main.ts' && file.parserVersion === result.data.parser.version))
  assert.ok(result.data.files.some((file) => file.path === 'src/helper.js'))
  assert.equal(result.data.summary.unsupportedLanguageFiles, 1)
  assert.equal(result.data.summary.filesExcludedByLayer, 3)
  assert.equal(result.data.analysis.status, 'PARTIAL')
  assert.equal(result.data.analysis.extraction, 'IN_MEMORY_ONLY_NO_CODE_EXECUTED')
  assert.deepEqual(new Set(result.data.excludedFiles.map((file) => file.path)), new Set(['tests/fixture.test.js', 'vendor/library.js', 'generated/api.ts']))
  assert.ok(result.evidenceIds.length > 0)
  await assert.rejects(() => access(sentinel), /ENOENT/, 'source files are parsed as text and never executed')

  const includedTask = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized explicit inclusion of test vendor and generated layers',
    targetPath: workspace,
    targetKind: 'directory',
    steps: [{ id: 'symbols-included-layers', capabilityId: 'source.symbols' }],
  })
  const included = await runtime.runner.runCapability({
    task: includedTask,
    capabilityId: 'source.symbols',
    options: { includeTests: true, includeVendor: true, includeGenerated: true },
  })
  assert.equal(included.data.summary.filesExcludedByLayer, 0)
  for (const path of ['tests/fixture.test.js', 'vendor/library.js', 'generated/api.ts']) assert.ok(included.data.files.some((file) => file.path === path))

  const boundedTask = await runtime.workspace(workspace).taskStore.create({
    title: 'authorized source read-bound fixture',
    targetPath: workspace,
    targetKind: 'directory',
    steps: [{ id: 'symbols-bounded', capabilityId: 'source.symbols' }],
  })
  const bounded = await runtime.runner.runCapability({ task: boundedTask, capabilityId: 'source.symbols', options: { maxFileBytes: 8, maxScanBytes: 1024 } })
  assert.equal(bounded.data.analysis.status, 'PARTIAL')
  assert.ok(bounded.data.summary.truncatedFiles > 0)
  assert.ok(bounded.data.analysis.limitsApplied.includes('maxFileBytes'))
  assert.ok(bounded.data.summary.bytesRead <= 1024)
})
