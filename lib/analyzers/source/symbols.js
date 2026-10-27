/** Bounded JavaScript/TypeScript syntax and symbol extraction using TypeScript's parser. */
import ts from 'typescript'

export const SOURCE_PARSER_ID = 'typescript-compiler-api'
export const SOURCE_PARSER_VERSION = ts.version
const SOURCE_LANGUAGE_VERSION = `ScriptTarget.${ts.ScriptTarget[ts.ScriptTarget.Latest] ?? 'Latest'}; TypeScript ${ts.version}`

const EXTENSIONS = new Map([
  ['.js', { language: 'JavaScript', kind: ts.ScriptKind.JS }],
  ['.jsx', { language: 'JavaScript', kind: ts.ScriptKind.JSX }],
  ['.mjs', { language: 'JavaScript', kind: ts.ScriptKind.JS }],
  ['.cjs', { language: 'JavaScript', kind: ts.ScriptKind.JS }],
  ['.ts', { language: 'TypeScript', kind: ts.ScriptKind.TS }],
  ['.tsx', { language: 'TypeScript', kind: ts.ScriptKind.TSX }],
  ['.mts', { language: 'TypeScript', kind: ts.ScriptKind.TS }],
  ['.cts', { language: 'TypeScript', kind: ts.ScriptKind.TS }],
])

const CAPABILITIES_NOT_IMPLEMENTED = ['cross_file_resolution', 'data_flow', 'compiler_semantics', 'generated_source_mapping']

export function sourceLanguageForPath(filePath) {
  const extension = String(filePath).toLowerCase().match(/\.[^.\\/]+$/)?.[0]
  return EXTENSIONS.get(extension) ?? null
}

function locationOf(sourceFile, start, end) {
  const safeStart = Math.max(0, Math.min(sourceFile.text.length, Number.isFinite(start) ? start : 0))
  const safeEnd = Math.max(safeStart, Math.min(sourceFile.text.length, Number.isFinite(end) ? end : safeStart))
  const first = sourceFile.getLineAndCharacterOfPosition(safeStart)
  const last = sourceFile.getLineAndCharacterOfPosition(safeEnd)
  return {
    startOffset: safeStart,
    endOffset: safeEnd,
    startLine: first.line + 1,
    startColumn: first.character + 1,
    endLine: last.line + 1,
    endColumn: last.character + 1,
  }
}

function nodeLocation(node, sourceFile) {
  return locationOf(sourceFile, node.getStart(sourceFile, false), node.getEnd())
}

function literalName(name) {
  if (!name) return null
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name) || ts.isStringLiteralLike(name) || ts.isNumericLiteral(name)) return String(name.text).slice(0, 160)
  if (ts.isComputedPropertyName(name)) return '[computed]'
  if (ts.isObjectBindingPattern(name)) return '[object-pattern]'
  if (ts.isArrayBindingPattern(name)) return '[array-pattern]'
  return null
}

function declarationKind(node) {
  if (ts.isFunctionDeclaration(node)) return 'function'
  if (ts.isClassDeclaration(node)) return 'class'
  if (ts.isInterfaceDeclaration(node)) return 'interface'
  if (ts.isTypeAliasDeclaration(node)) return 'type'
  if (ts.isEnumDeclaration(node)) return 'enum'
  if (ts.isEnumMember(node)) return 'enum-member'
  if (ts.isMethodDeclaration(node) || ts.isMethodSignature(node)) return 'method'
  if (ts.isConstructorDeclaration(node)) return 'constructor'
  if (ts.isGetAccessorDeclaration(node)) return 'getter'
  if (ts.isSetAccessorDeclaration(node)) return 'setter'
  if (ts.isPropertyDeclaration(node) || ts.isPropertySignature(node)) return 'property'
  if (ts.isParameter(node)) return 'parameter'
  if (ts.isVariableDeclaration(node)) return 'variable'
  if (ts.isBindingElement(node)) return 'binding'
  if (ts.isTypeParameterDeclaration(node)) return 'type-parameter'
  if (ts.isImportClause(node)) return 'default-import'
  if (ts.isImportSpecifier(node)) return 'named-import'
  if (ts.isNamespaceImport(node)) return 'namespace-import'
  if (ts.isImportEqualsDeclaration(node)) return 'import-alias'
  return null
}

function declarationOwner(node) {
  if (ts.isVariableDeclaration(node)) return ts.isVariableDeclarationList(node.parent) ? node.parent.parent : node.parent
  if (ts.isBindingElement(node)) return node
  if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node) || ts.isImportClause(node)) return node
  return node
}

function hasModifier(node, modifierKind) {
  if (!node || !ts.canHaveModifiers(node)) return false
  return (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === modifierKind)
}

function relativeModuleName(node) {
  const value = node?.moduleSpecifier
  return value && ts.isStringLiteralLike(value) ? value.text.slice(0, 500) : null
}

function importBindings(clause) {
  if (!clause) return []
  const bindings = []
  if (clause.name) bindings.push({ imported: 'default', local: clause.name.text })
  if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
    bindings.push({ imported: '*', local: clause.namedBindings.name.text })
  } else if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
    for (const element of clause.namedBindings.elements) {
      bindings.push({ imported: element.propertyName?.text ?? element.name.text, local: element.name.text })
    }
  }
  return bindings.map((binding) => ({ imported: String(binding.imported).slice(0, 160), local: String(binding.local).slice(0, 160) }))
}

function normalizeFileName(value) {
  return ts.normalizePath(String(value).replace(/\\/g, '/'))
}

function canonicalFileName(value) {
  const normalized = normalizeFileName(value)
  return ts.sys.useCaseSensitiveFileNames ? normalized : normalized.toLowerCase()
}

/**
 * Parse a set of already Core-read JS/TS files. The compiler host is memory-only:
 * TypeScript cannot read other project files, load project configs, or emit code.
 */
export function analyzeSourceUnits(units, { maxRecords = 300 } = {}) {
  const usable = units.filter((unit) => unit && typeof unit.path === 'string' && typeof unit.text === 'string' && sourceLanguageForPath(unit.path))
  const sourceFiles = new Map()
  const unitByCanonicalPath = new Map()
  for (const unit of usable) {
    const language = sourceLanguageForPath(unit.path)
    const path = normalizeFileName(unit.path)
    const sourceFile = ts.createSourceFile(path, unit.text, ts.ScriptTarget.Latest, true, language.kind)
    sourceFiles.set(canonicalFileName(path), sourceFile)
    unitByCanonicalPath.set(canonicalFileName(path), { ...unit, path, language, sourceFile })
  }

  const options = {
    allowJs: true,
    checkJs: false,
    noResolve: true,
    noLib: true,
    noEmit: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.Latest,
    module: ts.ModuleKind.ESNext,
    jsx: ts.JsxEmit.Preserve,
  }
  const host = {
    getSourceFile(fileName) { return sourceFiles.get(canonicalFileName(fileName)) },
    getSourceFileByPath(fileName) { return sourceFiles.get(canonicalFileName(fileName)) },
    getDefaultLibFileName() { return '' },
    writeFile() {},
    getCurrentDirectory() { return '/' },
    getDirectories() { return [] },
    fileExists(fileName) { return sourceFiles.has(canonicalFileName(fileName)) },
    readFile(fileName) { return sourceFiles.get(canonicalFileName(fileName))?.text },
    directoryExists() { return false },
    realpath(fileName) { return normalizeFileName(fileName) },
    useCaseSensitiveFileNames() { return ts.sys.useCaseSensitiveFileNames },
    getCanonicalFileName(fileName) { return canonicalFileName(fileName) },
    getNewLine() { return '\n' },
  }
  const program = ts.createProgram([...sourceFiles.keys()], options, host)
  const checker = program.getTypeChecker()
  const resultFiles = []
  const remaining = Math.max(0, Math.min(5000, Math.floor(Number(maxRecords) || 0)))
  let recordsLeft = remaining
  let totalSymbols = 0
  let totalReferences = 0
  let totalImports = 0
  let totalExports = 0
  let totalUnknownEdges = 0
  let recordsOmitted = 0
  let filesOmitted = 0

  for (let unitIndex = 0; unitIndex < usable.length; unitIndex += 1) {
    const original = usable[unitIndex]
    const canonical = canonicalFileName(original.path)
    const unit = unitByCanonicalPath.get(canonical)
    if (!unit) continue
    const sourceFile = unit.sourceFile
    const symbols = []
    const imports = []
    const exports = []
    const references = []
    const unknownEdges = []
    const diagnostics = program.getSyntacticDiagnostics(sourceFile)
    const emittedDeclarationIds = new WeakMap()
    const declarationNameNodes = new WeakSet()
    let localIndex = 0
    let localOmitted = 0
    const perFileBudget = Math.min(80, Math.max(0, recordsLeft))
    let localRecordsLeft = perFileBudget
    const addRecord = (collection, value) => {
      if (localRecordsLeft <= 0) {
        localOmitted += 1
        return false
      }
      collection.push(value)
      localRecordsLeft -= 1
      recordsLeft -= 1
      return true
    }

    const walkDeclarations = (node, parentSymbolId = null) => {
      let currentParentId = parentSymbolId
      const kind = declarationKind(node)
      const name = kind ? literalName(node.name) : null
      if (kind && name) {
        const id = `sym-${String(++localIndex).padStart(5, '0')}`
        const owner = declarationOwner(node)
        const exported = hasModifier(owner, ts.SyntaxKind.ExportKeyword) || hasModifier(owner, ts.SyntaxKind.DefaultKeyword)
        const entry = {
          id,
          kind,
          name,
          syntaxKind: ts.SyntaxKind[node.kind] ?? 'Unknown',
          exported,
          parentSymbolId,
          location: nodeLocation(node, sourceFile),
        }
        if (addRecord(symbols, entry)) {
          emittedDeclarationIds.set(node, id)
          currentParentId = id
        }
        if (node.name && ts.isIdentifier(node.name)) declarationNameNodes.add(node.name)
      }
      if (ts.isImportDeclaration(node)) {
        const module = relativeModuleName(node)
        addRecord(imports, { kind: 'static', module, bindings: importBindings(node.importClause), typeOnly: Boolean(node.importClause?.isTypeOnly), location: nodeLocation(node, sourceFile), resolution: 'DEFERRED_CROSS_FILE' })
        addRecord(unknownEdges, { kind: 'module-import', module, location: nodeLocation(node, sourceFile), reason: 'Cross-file module resolution is not implemented in this M2 slice.' })
      } else if (ts.isImportEqualsDeclaration(node)) {
        const module = ts.isExternalModuleReference(node.moduleReference) && node.moduleReference.expression && ts.isStringLiteralLike(node.moduleReference.expression)
          ? node.moduleReference.expression.text.slice(0, 500)
          : null
        addRecord(imports, { kind: 'import-equals', module, bindings: [{ imported: '*', local: node.name.text }], typeOnly: false, location: nodeLocation(node, sourceFile), resolution: 'DEFERRED_CROSS_FILE' })
        addRecord(unknownEdges, { kind: 'module-import', module, location: nodeLocation(node, sourceFile), reason: 'Cross-file module resolution is not implemented in this M2 slice.' })
      } else if (ts.isExportDeclaration(node)) {
        const module = relativeModuleName(node)
        const clause = node.exportClause
        const bindings = clause && ts.isNamedExports(clause)
          ? clause.elements.map((item) => ({ local: item.propertyName?.text ?? item.name.text, exported: item.name.text }))
          : [{ local: '*', exported: '*' }]
        addRecord(exports, { kind: module ? 're-export' : 'named', module, bindings, typeOnly: Boolean(node.isTypeOnly), location: nodeLocation(node, sourceFile), resolution: module ? 'DEFERRED_CROSS_FILE' : 'LOCAL_NAME_ONLY' })
        if (module) addRecord(unknownEdges, { kind: 'module-re-export', module, location: nodeLocation(node, sourceFile), reason: 'Cross-file module resolution is not implemented in this M2 slice.' })
      } else if (ts.isExportAssignment(node)) {
        addRecord(exports, { kind: node.isExportEquals ? 'export-equals' : 'default', module: null, bindings: [{ local: null, exported: node.isExportEquals ? '=' : 'default' }], typeOnly: false, location: nodeLocation(node, sourceFile), resolution: 'EXPRESSION_ONLY' })
      }

      return ts.forEachChild(node, (child) => walkDeclarations(child, currentParentId))
    }
    walkDeclarations(sourceFile)

    for (const statement of sourceFile.statements) {
      const owner = ts.isVariableStatement(statement) ? statement : statement
      if (!hasModifier(owner, ts.SyntaxKind.ExportKeyword) && !hasModifier(owner, ts.SyntaxKind.DefaultKeyword)) continue
      const declarationNodes = []
      if (ts.isVariableStatement(statement)) declarationNodes.push(...statement.declarationList.declarations)
      else declarationNodes.push(statement)
      for (const declaration of declarationNodes) {
        const id = emittedDeclarationIds.get(declaration)
        const name = literalName(declaration.name)
        if (id || name) addRecord(exports, { kind: hasModifier(owner, ts.SyntaxKind.DefaultKeyword) ? 'default-declaration' : 'declaration', module: null, bindings: [{ local: name, exported: hasModifier(owner, ts.SyntaxKind.DefaultKeyword) ? 'default' : name }], symbolId: id ?? null, typeOnly: false, location: nodeLocation(declaration, sourceFile), resolution: id ? 'LOCAL_DECLARATION' : 'LOCAL_NAME_ONLY' })
      }
    }

    const skippedIdentifier = (node) => {
      const parent = node.parent
      if (declarationNameNodes.has(node)) return true
      if (ts.isPropertyAccessExpression(parent) && parent.name === node) return true
      if ((ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent) || ts.isPropertyDeclaration(parent) || ts.isPropertySignature(parent)) && parent.name === node) return true
      if ((ts.isLabeledStatement(parent) || ts.isBreakStatement(parent) || ts.isContinueStatement(parent)) && parent.label === node) return true
      if (ts.isImportSpecifier(parent) || ts.isExportSpecifier(parent)) return true
      return false
    }
    const walkReferences = (node) => {
      if (ts.isCallExpression(node)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          const module = node.arguments[0] && ts.isStringLiteralLike(node.arguments[0]) ? node.arguments[0].text.slice(0, 500) : null
          addRecord(unknownEdges, { kind: 'dynamic-import', module, location: nodeLocation(node, sourceFile), reason: 'The runtime-selected module target is not resolved.' })
        } else if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
          const module = node.arguments[0] && ts.isStringLiteralLike(node.arguments[0]) ? node.arguments[0].text.slice(0, 500) : null
          addRecord(unknownEdges, { kind: module ? 'commonjs-require' : 'dynamic-require', module, location: nodeLocation(node, sourceFile), reason: 'CommonJS module resolution is not implemented in this M2 slice.' })
        } else if (ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
          addRecord(unknownEdges, { kind: 'dynamic-execution', module: null, location: nodeLocation(node, sourceFile), reason: 'eval input is dynamic and is not interpreted or executed.' })
        }
      }
      if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Reflect') {
        addRecord(unknownEdges, { kind: 'reflection', module: node.name.text, location: nodeLocation(node, sourceFile), reason: 'Reflection may create dynamic edges; no target is inferred.' })
      }
      if (ts.isIdentifier(node) && !skippedIdentifier(node)) {
        const symbol = checker.getSymbolAtLocation(node)
        if (symbol) {
          const targets = (symbol.declarations ?? []).map((declaration) => emittedDeclarationIds.get(declaration)).filter(Boolean)
          addRecord(references, { name: node.text.slice(0, 160), resolution: targets.length ? 'LOCAL_DECLARATION' : 'UNRESOLVED_IN_LOCAL_PROGRAM', targetSymbolIds: targets, location: nodeLocation(node, sourceFile) })
        } else {
          addRecord(references, { name: node.text.slice(0, 160), resolution: 'UNRESOLVED_IN_LOCAL_PROGRAM', targetSymbolIds: [], location: nodeLocation(node, sourceFile) })
        }
      }
      return ts.forEachChild(node, walkReferences)
    }
    walkReferences(sourceFile)

    const syntaxErrors = []
    for (const diagnostic of diagnostics) {
      const start = diagnostic.start ?? sourceFile.text.length
      const end = diagnostic.start === undefined ? start : start + (diagnostic.length ?? 0)
      if (!addRecord(syntaxErrors, {
        code: diagnostic.code,
        message: ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ').slice(0, 500),
        location: locationOf(sourceFile, start, end),
      })) break
    }
    const truncated = original.truncated === true
    const unsupportedFeatures = [...CAPABILITIES_NOT_IMPLEMENTED]
    if (unknownEdges.some((edge) => edge.kind === 'reflection')) unsupportedFeatures.push('reflection_target_resolution')
    if (unknownEdges.some((edge) => edge.kind === 'dynamic-execution')) unsupportedFeatures.push('dynamic_code_interpretation')
    const fileStatus = syntaxErrors.length || truncated || localOmitted ? 'PARTIAL' : 'COMPLETE'
    recordsOmitted += localOmitted
    totalSymbols += symbols.length
    totalReferences += references.length
    totalImports += imports.length
    totalExports += exports.length
    totalUnknownEdges += unknownEdges.length
    resultFiles.push({
      path: String(original.path).replace(/\\/g, '/').slice(0, 500),
      sourceLayers: Array.isArray(original.sourceLayers) ? original.sourceLayers : ['product'],
      language: unit.language.language,
      supportLevel: 'S2',
      parserId: SOURCE_PARSER_ID,
      parserVersion: SOURCE_PARSER_VERSION,
      languageVersion: SOURCE_LANGUAGE_VERSION,
      truncated,
      status: fileStatus,
      syntaxErrorCount: diagnostics.length,
      syntaxErrors,
      symbols,
      imports,
      exports,
      references,
      unknownEdges,
      unsupportedFeatures: [...new Set(unsupportedFeatures)],
      coverage: { crossFileResolution: false, dataFlow: false, typeChecking: false, sourceMaps: false, omittedRecords: localOmitted },
    })
    if (recordsLeft <= 0 && unitIndex < usable.length - 1) {
      filesOmitted += usable.length - unitIndex - 1
      break
    }
  }

  return {
    schemaVersion: 'armorbreak.source-symbol-ir/v1',
    parser: { id: SOURCE_PARSER_ID, version: SOURCE_PARSER_VERSION },
    summary: {
      filesProvided: units.length,
      filesParsed: resultFiles.length,
      filesWithSyntaxErrors: resultFiles.filter((file) => file.syntaxErrorCount > 0).length,
      filesTruncated: resultFiles.filter((file) => file.truncated).length,
      symbols: totalSymbols,
      imports: totalImports,
      exports: totalExports,
      references: totalReferences,
      unknownEdges: totalUnknownEdges,
      recordsEmitted: remaining - recordsLeft,
      omittedRecords: recordsOmitted,
      filesOmitted,
    },
    files: resultFiles,
    analysis: {
      level: 'S2',
      status: resultFiles.length === 0 ? 'UNSUPPORTED' : resultFiles.some((file) => file.status === 'PARTIAL') || recordsOmitted || filesOmitted ? 'PARTIAL' : 'COMPLETE',
      warnings: [],
      limitsApplied: recordsOmitted || filesOmitted ? ['maxRecords'] : [],
      coverageNotes: [
        'Only JavaScript and TypeScript syntax is parsed by the pinned TypeScript compiler API.',
        'Import targets are recorded but cross-file module resolution is disabled; no data-flow or compiler-semantic claims are made.',
        'The compiler host reads only source texts supplied in memory by the Core boundary; it performs no emit, configuration loading, or target execution.',
      ],
    },
  }
}
