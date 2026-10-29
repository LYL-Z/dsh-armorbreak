# M5 — Authorized behavior contract and finite comparison

Status: `PARTIAL_LOCAL_TESTED` on source commit `7e42b1a5b5f1cf9c8833dd355b6c266cc62b15d3`. Windows/Node/Python local evidence is recorded in `docs/v2.3/evidence/m5/m5-validation.json`; CI and cross-platform verification remain outstanding. The implementation is deliberately offline: it normalizes caller-supplied observations and compares already-produced JSON results. It never compiles or starts a reference or candidate program.

## Contract source bundle

`rebuild.contract` accepts `armorbreak.behavior-contract-source/v1` with an artifact SHA-256 and bounded `observations[]`. Each observation has an ID, kind (`signature`, `api`, `cli`, `test`, `state-transition`, `error`, or `constraint`), statement, certainty (`observed`, `inferred`, or `unknown`), and at least one evidence reference. Optional preconditions, inputs, outputs, errors and side effects are retained as bounded text. The output distinguishes certainty counts and marks the result `not_independently_validated`.

This capability organizes explicit evidence; it does not parse arbitrary source, infer a complete specification, authenticate caller evidence references, or generate a replacement implementation. Unknown observations stay unknown.

## Comparison bundle

`rebuild.compare` and `AuthorizedBehaviorReconstruction` accept `armorbreak.behavior-comparison-bundle/v1`. Each finite case supplies an input SHA-256, reference and candidate result status, JSON values for complete results, evidence references for both sides, and an environment comparability flag. `complete` results are compared canonically. Mismatches include only bounded JSON-pointer paths and hashes/byte sizes, not output values. Missing, timeout, nondeterministic, unavailable, or environment-incomparable results become `INCONCLUSIVE`.

The output includes `casesTotal`, `casesExecuted`, `casesCompared`, `casesPassed`, `casesFailed`, `casesInconclusive`, `coverageScope`, and a bounded `equivalenceClaim`. Here `casesExecuted` counts complete result pairs supplied by the caller; `executionByArmorBreak` is always false and result provenance remains `caller_supplied_unverified_observations`. A finite match is never a claim of global equivalence.

Limits: 4 MiB input, 300 observations/cases, 32 JSON nesting levels, 3,000 collection members, and 220 KiB output. Values are hashed and compared in memory but are not copied to reports.

## Self-authored cross-language fixture

`tests/fixtures/m5` contains a JavaScript reference and a separate Python candidate for an account formatter, arithmetic evaluator, and gated state transition. The test harness actually invokes the self-authored Python file through a fixed executable plus argv, compares produced values, includes deliberately broken candidates, and records real timeout/nondeterministic outcomes as inconclusive. It exercises local fixture code only; the ArmorBreak capability receives only the generated JSON result bundle and does not execute either fixture.

The exact-SHA M5 report lists per-case counts, fixture hashes, Python/Node versions, and test logs. The test harness runs the authored reference/candidate fixtures locally before handing only their result bundle to ArmorBreak. Current CI and cross-platform runs remain separate gates.
