# M2 — JavaScript/TypeScript Source Symbol IR

## Status

**Partial; locally tested.** This implementation declares S2 only for JavaScript and TypeScript syntax accepted by the pinned TypeScript Compiler API 5.9.3. It does not satisfy the taskbook's broader M2 goal of stable S1–S2 for the seven core source languages or S3 semantics for four languages. The compatibility matrix must retain those gaps as blockers.

## Implemented scope

- `source.symbols` is an L0 directory capability registered through the existing analyzer registry and executed through the real Core `listFiles`/`readFile` boundary.
- `CrossLanguageSourceReview` runs that capability over an authorized local project directory.
- `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, and `.cts` are parsed by TypeScript 5.9.3 in memory, with `ScriptTarget.Latest`, no emit, no project configuration load, and no filesystem resolution by the compiler host.
- The IR records modules, functions, classes, interfaces, type aliases, enums, methods, properties, parameters, variables, imports, exports, identifier references, syntax diagnostics, source positions, parser identity/version, language version, truncation, partial status, and unsupported features.
- Same-file identifier references can point to emitted symbol IDs. Import/re-export targets remain `DEFERRED_CROSS_FILE`; cross-file links, type checking, data flow, call graphs, and source-map mapping are explicitly false/not implemented.
- `import()`, `require()`, `eval()`, and `Reflect` create unresolved/unknown-edge records where applicable. The parser does not evaluate dynamic targets or execute source code.
- Test, generated, vendored/external, and build-output path layers are excluded from the default product-source index and listed in `excludedFiles`. `includeTests`, `includeGenerated`, `includeVendor`, and `includeBuildOutputs` opt those layers in. The current Core path policy continues to omit its existing excluded directories such as `node_modules` and `dist` before this capability sees them.
- Output has deterministic record and byte budgets. Parser results are capped at 192 KiB to leave room below Core's 256 KiB result limit. A file read exactly at its cap is conservatively marked truncated because Core does not supply an independent complete-size fact.
- If the TypeScript runtime dependency is absent, registry loading remains functional and `source.symbols` returns `UNSUPPORTED` before reading files. The current portable source archive does not bundle `node_modules/typescript`; use the npm-installed environment for JS/TS parsing. This boundary is covered by the portable-artifact test.

## Supported and unsupported language statements

| Language / input | Current statement | Evidence boundary |
|---|---|---|
| JavaScript | S2 syntax/symbol extraction | Five positive and five syntax-negative local fixtures; same-file reference fixture; real Runner integration |
| TypeScript | S2 syntax/symbol extraction | Five positive and five syntax-negative local fixtures; same-file reference fixture; real Runner integration |
| Python, Java, C/C++, Go, Rust, C#, and other listed source languages | No S2 backend in this M2 slice; reported by extension and not parsed here | C/C++ macro text is explicitly checked as unsupported; no parser or semantic claims |
| Four-language S3 semantics | Not implemented | No call/data-flow backend or linked multi-file ground-truth set |

The M1 artifact detector may provide extension-level S1 candidates for other languages. That is not parser support and is not promoted to S2 here.

## Resource and trust boundary

Defaults are 100 files, 4 MiB total input, 256 KiB per file, 300 IR records, five directory levels, and the 192 KiB serialized IR ceiling. Hard limits are 300 files, 8 MiB total bytes, 1 MiB per file (also bounded by Core's 4 MiB file-read limit), 300 records, and depth eight. Source bytes are decoded as strict UTF-8. Invalid encoding, inaccessible files, unsupported source extensions, parser diagnostics, truncation, excluded layers, and budget omissions are reported as partial/unsupported conditions rather than silently treated as complete.

The implementation uses no shell, subprocess, network access, target execution, or sample writes. A local integration fixture includes source text that would write a sentinel if executed; the sentinel remains absent after capability and workflow runs. This is a test of the local parser path, not hostile-plugin isolation.

## Local evaluation

`tests/program-intelligence-source.test.mjs` uses deterministic source fixtures, not third-party repositories. It currently checks 5/5 positive and 5/5 syntax-negative JS fixtures, 5/5 positive and 5/5 syntax-negative TS fixtures, two same-file reference-link cases, unknown dynamic/reflection edges, macro-language refusal, layered-source inclusion/exclusion, truncation, file/record/result budgets, a real Core Runner/PolicyGateway capability call, a real workflow call, and no-execution sentinel behavior. The fixture ratios describe only these cases; they do not estimate real-world parser accuracy, false-positive/negative rates, or codebase coverage.

Exact focused/full-suite results, tested source commit, runtime registry snapshot, and raw ignored logs are recorded under `docs/v2.3/evidence/m2/` after the M2 implementation commit and exact-SHA full-suite run.

## Not implemented or not verified

- S1–S2 parsers for Python, Java, C/C++, Go, Rust, C#, or the extension-language groups.
- Real semantic S3 for four selected languages, inter-file resolution, type-aware navigation, call graphs, taint/data-flow, source/sink/sanitizer/path segments, and compiler database construction.
- Comprehensive link-precision/recall, false-positive/negative measurement, ambiguous resolution, macro/conditional compilation, Python dynamic import, framework semantics, or generated-code source-map tests.
- Tests against real third-party applications, large repositories, multi-platform file systems, Windows/Ubuntu CI, CI provenance, or an independent security review.
- The portable source archive does not carry TypeScript; in that artifact, parser invocation returns `UNSUPPORTED` until the dependency is installed. The npm-managed runtime dependency is locked to 5.9.3.
