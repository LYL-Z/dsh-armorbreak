# ArmorBreak V2.3 interruption checkpoint

Pause recorded on 2026-10-27; explicitly resumed on 2026-10-29.
Status: the original pause was explicitly lifted; implementation resumed at M3. This file preserves the pause point and records the verified continuation below. No release, push, PR, or merge has been performed.

## Exact repository state at pause

- Worktree: `D:\dsh-ABM\armorbreak-v2.3-worktree`
- Branch: `feature/v2.3-universal-program-intelligence`
- HEAD: `ca88b0b12a974f1f763acd39433afab247144e0b` (`feat: add native program IR`)
- The branch was 7 commits ahead of `origin/main` when checked.
- Source changes for M3 are committed. Five untracked M3 result snapshots were present:
  - `docs/v2.3/evidence/m3/ghidra-bounded-scope-i386.json`
  - `docs/v2.3/evidence/m3/runner-native-i386.json`
  - `docs/v2.3/evidence/m3/runner-native-pe.json`
  - `docs/v2.3/evidence/m3/runner-native-stripped-i386-elf.json`
  - `docs/v2.3/evidence/m3/runner-native-stripped-pe.json`
- Those snapshots contain temporary machine-local paths. Sanitize paths while preserving sample hashes and result data before committing or sharing them.
- This checkpoint file is also untracked and was added only to preserve the interruption state.

## Evidence already present at the exact M3 source SHA

- `npm test`: 634 passed, 0 failed; log `docs/v2.3/evidence/m3/full-test.log`.
- Focused binary/adapter/fixture tests: 27 passed, 0 failed; log `docs/v2.3/evidence/m3/focused-tests.log`.
- `npm run typecheck`: exit 0; log `docs/v2.3/evidence/m3/typecheck.log`.
- Real Ghidra 12.1.4 / Runner evidence exists for self-authored compiled x64 PE and i386 ELF, including stripped variants and a bounded-output run. The analyzed inputs were not executed.
- M3 test fixtures include malformed PE/ELF/Mach-O inputs. The Mach-O input is structurally constructed; no valid self-compiled Mach-O fixture or Mach-O Ghidra E2E was available at pause.

## Gate status and limits

- M0–M2 have earlier local evidence and exact commits; revalidate current state on resume before relying on it.
- M3 is `PARTIAL`, not passed. Taskbook §7.1/§13 requires PE/ELF/Mach-O symbol-bearing and stripped fixtures, damaged cases, and real Ghidra evidence. Mach-O coverage is the outstanding M3 fixture gap; additional bytecode E2Es listed in §7.2 are also not newly verified here.
- Docker client 29.8.1 was present, but the daemon was unreachable (`dockerDesktopLinuxEngine` named pipe missing). Do not claim L1 isolation or run hostile samples.
- WSL Ubuntu probe found GCC but no `clang`, `ld64.lld`, `llvm-strip`, or `zig`; Windows Rust only had the `x86_64-pc-windows-msvc` target. No new toolchain was installed.
- No M4–M6 implementation began. No PR was created. Formal release remains unauthorized.

## Resume order

1. Recheck local rules, branch/HEAD/status/diff, processes, Docker daemon and available compiler/tool versions.
2. Sanitize and hash-review the five untracked result snapshots; retain exact fixture SHA-256 values.
3. Complete the M3 Mach-O valid/symbol-bearing/stripped/damaged fixture matrix and real static-analysis evidence, or document the exact blocker and keep M3 partial.
4. Re-run exact-SHA tests and refresh M3 registry/compatibility/evidence records.
5. Advance to M4 only after M3's P0-D gate is satisfied; continue the taskbook gates sequentially.
6. Create a PR only after implementation and evidence are reviewable. Do not publish a formal release without explicit authorization.

## Resume verification on 2026-10-29

- The fetched GitHub `main` reference still resolves to `66ec0017af4b9d636f09e45f7cf55eed060512ac`; the work branch remains based on that frozen baseline.
- The branch HEAD at resume was `ca88b0b12a974f1f763acd39433afab247144e0b`; no earlier implementation commits were rewritten.
- Added and parser-tested valid symbol-bearing, stripped, and truncated x86-64 Mach-O fixtures. The symbol-bearing fixture was cross-compiled from the self-authored C fixture with Zig 0.17.0. The stripped derivative is produced by a checked-in deterministic load-command transformation.
- M3 implementation/evidence commits are `ba3c5ea4134f138bca22d1a6aa597f1e7f2b0cc4` and `e57287f5abc9fb9ba86cb686736f67f3ab030357`. On the latter exact SHA, focused tests passed 28/28, the default full suite passed 635/635, typecheck exited 0, and six real Runner/PolicyGateway/Ghidra 12.1.4 cases passed across PE/ELF/Mach-O with symbols and stripped symbols; every case recorded `inputExecuted:false`. Evidence is indexed in `docs/v2.3/evidence/m3/m3-validation.json`.
- Fresh Docker CLI check on Oct 29 finds client 29.8.1 but no server at `dockerDesktopLinuxEngine`; the Oct 26 harmless isolation self-test remains historical evidence only.
- Native M3 P0 local gate is satisfied; M3 overall remains partial because P1 bytecode E2Es and isolation/macOS/CI coverage are missing. M4–M6 and P0-H have not started. No push, PR, merge, tag, or release has been performed.

## Resume verification on 2026-10-29 — M4 in progress, paused again

- The user explicitly resumed work, so M4 implementation began after the M3 P0 local gate. This pause was explicitly requested after the latest targeted M4 test run.
- Worktree: `D:\dsh-ABM\armorbreak-v2.3-worktree`
- Branch: `feature/v2.3-universal-program-intelligence` (10 commits ahead of `origin/main` at pause)
- HEAD at pause: `4906162a6c3b23ed8cbca94ccbb41920f5e0cd63` (`docs: record exact-SHA M3 verification evidence`)
- No M4 implementation commit exists. All changes below are uncommitted and must be preserved on resume:
  - Modified: `packages/core/src/evidence.js`, `packages/core/src/reports.js`, `packages/core/src/workflows.js`
  - New: `lib/analyzers/security/correlator.js`, `lib/analyzers/security/manifest.js`
  - New: `tests/security-correlator.test.mjs`, `tests/fixtures/m4/vulnerability-contrast-corpus.mjs`, `tests/fixtures/m4/evaluate-corpus.mjs`
  - New: `scripts/v2/verify-m4-vulnerability-corpus.mjs`
- The existing `git diff --stat` at pause covers only the three modified tracked files; it excludes all new files. No unrelated edits were observed.

### M4 implementation present in the dirty worktree

- Added an L0 `security.correlate` capability and a `UniversalSecurityReview` workflow. The input contract is a local `armorbreak.security-evidence-bundle/v1` JSON file. It currently accepts ArmorBreak findings, SARIF 2.1.0, Semgrep JSON, Trivy JSON, explicit OSV match records, and declared CycloneDX/SPDX documents.
- The correlator groups only records with artifact SHA-256, normalized file/line, CWE/rule, and evidence-context hash. Incomplete keys remain separate. It retains a sanitized source record per finding and source references, marks cross-family matching as evidence corroboration, and always emits vulnerability status `not_tested`; imported `confirmed` claims remain visible only as source claims.
- Added JSON and SARIF artifacts, SARIF `relatedLocations` for imported evidence, separate vulnerability status in persisted finding/report output, and a 20-group/60-snippet authored contrast corpus across CWE-78/89/22/918/95.
- The targeted test command `node --test --test-concurrency=1 tests/security-correlator.test.mjs` passed 6/6 on the dirty worktree after fixing two implementation bugs (location normalization and severity normalization) plus the snapshot parser call. The suite exercised actual `scanSource`, a local Runner `UniversalSecurityReview` execution, generated JSON/SARIF artifacts, provenance metadata, and the rule that source claims cannot set `confirmed`.
- The same focused test measured this authored corpus at TP=20, FP=20, FN=0, TN=20; precision=0.50, recall=1.00, false-positive rate=0.50. This is corpus-only line-regex evidence, not a real-world detection estimate. The separate metrics evidence script has **not** been run, and no M4 test log/evidence artifact has been saved yet.

### M4 gate state at pause

- M4: `IN_PROGRESS_UNCOMMITTED`; P0 gate is not yet accepted. No full `npm test`, `npm run typecheck`, M4 evidence script, or compatibility matrix refresh has been run on the current changes.
- No M4 documentation/schema guide or compatibility-matrix entry update has been added yet. Existing tests with hard-coded live capability counts still expect 50 and will need review/update if the new capability remains registered.
- Known boundary: correlation imports already-produced JSON evidence; the DAG does not pass previous step output into a later step. The new workflow therefore consumes a prepared offline evidence bundle rather than automatically invoking every analyzer. Native Trivy/Semgrep adapters cover the implemented report fields only; OSV records are not fetched or version-range matched. No network, exploit, or sample execution occurred.
- No push, PR, merge, tag, or formal release has been performed.

### Resume order

1. Inspect this checkpoint and `git status` before editing; preserve the uncommitted M4 changes.
2. Review the correlator for redaction of derived title/message/context strings, path privacy, evidence limits, output truncation, and precise claims about SBOM/source retention. Add/adjust tests before describing M4 as accepted.
3. Run the corpus evidence script and save its output with fixture hash and the exact M4 source commit; record the applicability limits and FP/FN counts.
4. Update M4 implementation documentation, compatibility matrix, live capability/workflow count expectations, and any product description that still says 50 capabilities. Keep historical M2/M3 evidence unchanged.
5. Run focused M4 tests, `npm run typecheck`, and full `npm test`; commit the M4 source/test stage, rerun and save evidence against that exact SHA, then update the M4 matrix to the observed status.
6. Only after M4's P0 evidence gate, proceed sequentially to M5, M6, and P0-H. Create a PR only after the complete authorized work is reviewable. Formal release remains unauthorized.

## Resume progress on 2026-10-29 — M4 hardening and Docker refresh

- The worktree and HEAD were rechecked on resume; HEAD was unchanged at `4906162a6c3b23ed8cbca94ccbb41920f5e0cd63`, and the initial dirty M4 file set matched the prior checkpoint. The Docker refresh below added one tracked host-verification report update.
- Hardened M4 report redaction after adding a regression test: derived messages now redact credential-shaped values and absolute path fragments; source finding path/URI fields are replaced with stable opaque identifiers; source and SBOM digests cover bounded redacted representations. Corrected the report language to state SBOM documents are summarized and hashed, not copied or converted. Targeted suite now passes 7/7.
- `npm run typecheck` exited 0 on the working tree. A full `npm test` run before commit completed 642 tests: 639 passed and 3 failed. One failure was the stale 50-capability Core assertion and has been updated to 51; two release-build tests correctly rejected dirty source inputs. The full suite must be rerun after the M4 sources are committed and the tree is clean.
- The user reported Docker Desktop open. Fresh CLI verification now connects to Docker Desktop 4.93.0 / Engine 29.8.1 (linux/amd64); the pinned BusyBox digest was already present. `node scripts/verify-l1.mjs` then passed against a benign temporary fixture: task `task_mvtp9hb3_fa92f1dc`, `COMPLETED`, exit 0, uid 65534, sample mount read-only. The refreshed report is `docs/acceptance/l1-docker-verification.json`; no analyzed program was executed. This is a current host L1 gate observation, not cross-platform isolation proof.
- M4 remains uncommitted and unaccepted. Next: finalize compatibility/runtime counts and M4 evidence docs, commit the implementation and tests, run the focused suite/typecheck/full suite on the committed tree, then save corpus/test logs with the exact source SHA. M5 has not started. No push, PR, merge, tag, or formal release has occurred.

## M4 local verification completed on 2026-10-29

- M4 implementation commit: `f52f9f87ba8f9b308b86c58b74c60160843391b6` (`feat: add offline security evidence correlation`). Follow-up release count gate fix: `23af85c900e54a2ac0f6bdf93ce2aad34b65d263` (`fix: update clean-room capability gate`). Evidence/compatibility metadata is being recorded in evidence-only commits after these source commits.
- On exact clean source commit `23af85c900e54a2ac0f6bdf93ce2aad34b65d263`: focused M4 suite 7/7, `npm run typecheck` exit 0, `npm test` 642/642 with zero failures/skips. The full suite initially exposed a hard-coded clean-room expectation of 50; the build gate now expects 51 and its isolated release-build test passed 1/1 before the full rerun.
- Corpus evidence is bound to source SHA `23af85c900e54a2ac0f6bdf93ce2aad34b65d263` and fixture SHA-256 `0e07d0d5758a15bee8004b7801d74df38fbe5f70cfb5ce12534e9e9ff5f512ca`. Results: 20 groups / 60 authored snippets; TP=20, FP=20, FN=0, TN=20, precision=0.50, recall=1.00, FPR=0.50. This is not a real-world estimate.
- Compatibility runtime registry was freshly queried: 51 capabilities, 11 domains, 49 L0 / 1 L1 / 1 L2, 13 workflows, no registry diagnostics. The M4 capability/workflow are `PARTIAL_LOCAL_TESTED`; CI, Ubuntu/macOS, advisory fetching/version-range matching, automated scanner invocation, and independent vulnerability confirmation remain unverified or unsupported.
- Docker Desktop 4.93.0 / Engine 29.8.1 was reachable. `docs/acceptance/l1-docker-verification.json` records a successful harmless local-container check (non-root UID 65534, read-only fixture mount); no analyzed program ran.
- Current next step: proceed to M5 only after M4 evidence commits leave a clean tree. Preserve M4 source/test commits and exact evidence. No push, PR, merge, tag, or formal release has occurred.

## M5 local verification completed on 2026-10-29

- M5 implementation source commit: `7e42b1a5b5f1cf9c8833dd355b6c266cc62b15d3` (`feat: add bounded behavior contract comparison`). Branch was 16 commits ahead of `origin/main` immediately after this commit.
- Implemented `rebuild.contract`, `rebuild.compare`, and `AuthorizedBehaviorReconstruction`. The capabilities accept bounded local JSON and never execute either candidate/reference program. Contract certainty and evidence references are caller supplied and not authenticated; comparison checks complete JSON values and labels timeout, nondeterminism, missing evidence/results, and environment mismatch `INCONCLUSIVE`.
- Self-authored JavaScript/Python fixtures exercise an account formatter, arithmetic evaluator, and gated state transition. Positive and intentionally broken cases run as actual local processes. Timeout is a real Python process killed at 150 ms (`ETIMEDOUT`); nondeterminism comes from two independent Python runs with distinct random outputs. The ArmorBreak workflow only receives the precomputed results bundle.
- On exact source SHA `7e42b1a...`, M5 focused tests passed 2/2; full `npm test` passed 644/644, 0 failed, 0 skipped (132704.6294 ms); `npm run typecheck` exited 0. Windows x64, Node v24.16.0, Python 3.13.13. Evidence and SHA-256 hashes are in `docs/v2.3/evidence/m5/m5-validation.json`; log hash verification passed locally.
- Finite comparison result: 11 cases total, 8 complete result pairs compared, 5 pass, 3 fail, 3 inconclusive. This is a test fixture outcome, not a reconstruction-rate or global-equivalence claim.
- Runtime count after M5: 53 capabilities / 12 domains (51 L0, 1 L1, 1 L2), 14 workflows, registry diagnostics empty. Docker Engine 29.8.1 linux/amd64 is currently connected; the harmless L1 probe evidence remains at `docs/acceptance/l1-docker-verification.json` and did not execute a target program.
- M5 status: `PARTIAL_LOCAL_TESTED`; CI and Ubuntu/macOS coverage, general source-to-contract inference, authenticated evidence references, and arbitrary project execution remain unverified/unsupported. M6/P0-G and P0-H have not been completed. No push, PR, merge, tag, or formal release has occurred.
- Current continuation point: commit the M5 evidence/compatibility/checkpoint-only changes, then test the actual new CLI/MCP/workflow discovery and execution paths for M6. Preserve all exact-SHA evidence; continue to P0-H only after M6.
