# ArmorBreak V2.3.0 implementation and acceptance report

This report follows taskbook §15. It reports the latest evidence available for the engineering branch and explicitly separates implementation from release readiness. It does **not** claim a complete V2.3.0 Stable release.

## 1. BASELINE

- Repository: `LYL-Z/dsh-armorbreak`; frozen `origin/main` baseline: `66ec0017af4b9d636f09e45f7cf55eed060512ac`.
- Baseline tag: `v2.2.0` exists; no V2.3 tag is created.
- Branch: `feature/v2.3-universal-program-intelligence`; implementation branch was created from the exact main SHA above.
- M6 source: `965fbe4fa9abd2af73644865a56d8db64c8a6089`; last previously pushed PR head tested by GitHub: `0795c4dd270f59cb60a006c756035da111e1d970`. New P0-H source commits are recorded below; historical CI is not proof for them.
- Windows 11 build 26300, x64; baseline and M6 recorded Node `v24.16.0`, npm `11.13.0`; TypeScript lock `5.9.3`.
- Frozen M0 full test: 530/530 on the baseline after setting TEMP/TMP to a same-volume worktree directory; default cross-volume run had 6 environment-dependent failures and was retained in evidence. Candidate M6 evidence reports 647/647 on the exact M6 source SHA.

## 2. IMPLEMENTED

The complete changed-file list and reviewable patch are available in the [PR file view](https://github.com/LYL-Z/dsh-armorbreak/pull/25/files).

The following capability groups are present in committed source; stage evidence is bound in the V2.3 manifest, and the later exact-head CI is recorded in §8:

- M1: bounded artifact identification and archive inventory; source commit `3135688b3a5cbea89798bc0c61a2a45abfa38312`.
- M2: JS/TS source symbols and local references; source commit `47b5869a7d18e32c057aa6d2083693f920a21340`.
- M3: bounded PE/ELF/Mach-O Program IR and optional real Ghidra integration; source/evidence commits `ba3c5ea4134f138bca22d1a6aa597f1e7f2b0cc4`, `e57287f5abc9fb9ba86cb686736f67f3ab030357`.
- M4: offline security evidence correlation, redaction, JSON/SARIF results; source commit `23af85c900e54a2ac0f6bdf93ce2aad34b65d263`.
- M5: caller-supplied behavior contracts and finite comparison of precomputed JSON outputs; source commit `7e42b1a5b5f1cf9c8833dd355b6c266cc62b15d3`.
- M6: capability status metadata and fixed L0-only MCP workflow discovery/start; source commit `965fbe4fa9abd2af73644865a56d8db64c8a6089`.

Observed M6 runtime registry: 53 capabilities / 12 domains (51 L0, 1 L1, 1 L2), 14 workflows, 10 DSH model tools, 8 MCP tools, 7 skills, and 0 registry diagnostics. Original Core contract `0.1.0-p1` and protocol v1 remain unchanged. The exact registry snapshot and tests are in `evidence/m6/m6-validation.json`.

## 3. VERIFIED

| Area | Observed local evidence | Status and limit |
|---|---|---|
| M0 | `evidence/m0/test-results.json`; baseline SHA above; 530/530 canonical full suite | Frozen baseline; default cross-volume failures remain documented |
| M1 | `evidence/m1/test-results.json` | Local fixture tests and exact-head full-suite CI |
| M2 JS/TS | `evidence/m2/test-results.json`; 5 positive and 5 syntax-negative per language in authored fixtures | Partial S2 for JS/TS only; not broad language semantics or taint |
| M3 native | `evidence/m3/native-ghidra-runner-e2e.json`, `m3-validation.json`; Ghidra 12.1.4, Temurin 21, six PE/ELF/Mach-O cases, x64 and i386 | Real host E2E; each is static (`inputExecuted:false`); outputs can be partial/bounded; no macOS host |
| M4 corpus | `evidence/m4/vulnerability-corpus-metrics.json`; 20 groups / 60 snippets; TP=20 FP=20 FN=0 TN=20; precision .50, recall 1.00, FPR .50 | Authored regex corpus only; not a real-world accuracy estimate or independent confirmation |
| M5 behavior | `evidence/m5/m5-validation.json`; 11 cases, 8 compared, 5 pass, 3 fail, 3 inconclusive | Authored JS/Python local fixtures; ArmorBreak itself receives precomputed results and does not execute programs |
| M6 integration | `evidence/m6/m6-validation.json`; full suite 647/647, focused CLI/MCP/API 24/24, typecheck exit 0 | Windows / Node 24 local exact-source run; exact-head CI additionally passed on all four OS/Node combinations below |
| Node 22 compatibility | `evidence/p0-h/node22-local-validation.json`; exact source `679bbeb6152d9f9c9f151c5bae6f7c01d098b357`, 647/647 and TypeScript check exit 0 | Local Windows Node `v22.23.4`; exact-head Windows and Ubuntu CI passed; invalid temp-root attempt retained separately |
| Exact-head CI | Run `40995701875`, SHA `8364343fc2ef75007009d8074341ee5d7bbc6b0d`; `evidence/p0-h/github-ci-run-40995701875.json` | Ubuntu Node 22/24: 649/649 each; Windows Node 22/24: 647/647 each; all typechecks exit 0. The two-count difference is from two explicitly Linux-only tests not registered on Windows; evidence integrity and benign pinned-image L1 path passed |
| Inherited CI | Run `40995701865`, same exact SHA; `evidence/p0-h/github-ci-run-40995701865.json` | Node 24 Windows/Ubuntu full suite passed; L0 static boundary passed; real Docker daemon integration passed; release evidence job skipped under the V2.3 branch rule |
| Dependency audit | `evidence/p0-h/npm-audit.json`; npm audit via `https://registry.npmjs.org` | Exit 0; 0 info/low/moderate/high/critical advisories in the audited lockfile dependency set; license review not included |
| Latest local full test/typecheck | Source SHA `26a3e8edc81bf950cc7cdde37e027607121e207b`; `npm test`, `npm run typecheck` | 654/654 passed, 0 failed/skipped; typecheck exit 0; local Windows x64 / Node 24.16.0; historical local evidence, superseded by exact-head GitHub CI for `c1c1094…` |
| P0-1 evidence provenance | `tests/v23-provenance.test.mjs`; `evidence/p0-h/acceptance-manifest.json` | Negative tests 4/4 passed locally; allowlist admits only named docs and P0-H evidence; the committed 74-file manifest was checked by run `41026010595`; the current local report/evidence tree has 76 files and passes locally, with its new exact-head run pending |
| P0-4 isolated upgrade/rollback | `evidence/p0-h/upgrade-rollback-drill.json` | Synthetic V2.2-compatible task/report/config were read by current Core; actual local installer state transitions, failure injection, rollback pointer, and pre/post SHA checks passed. This was not a real package install or user-profile exercise; OS ACL/service principal was not measured |
| P0-5 V2.3-specific gate | `scripts/v2/v23-release-gate.mjs`, `.github/workflows/v2.3-main-gate.yml`, `tests/v23-release-gate.test.mjs` | Fail-closed modes passed local tests; current PR's inherited and V2.3 validation checks passed, but the dedicated main-gate workflow has no successful PR-event run: run `41026002895` for `c1c1094…` concluded failure with zero jobs; prior PR run `41025798504` failed before its test setup fix. Branch protection is unreadable to the connected GitHub integration (403) |
| Security/license pre-review | `evidence/p0-h/security-license-review-preliminary.json` | Explicitly same-agent AI pre-review, not independent or human; it documents coverage and blockers but does not satisfy P0-3 |
| Latest dependency audit | `evidence/p0-h/npm-audit-latest.json`, source SHA `26a3e8e…` | Official npm registry audit exit 0; zero advisories; package-lock SHA recorded. This is not a license review |
| Performance | [`performance-report.md`](performance-report.md) and sanitized raw benchmark | Same benchmark script/Node/OS family; baseline CPU identity not recorded, no peak-memory comparison |

The stage JSON records include exact source SHAs, commands, counts and evidence hashes. Fixture SHA-256 values are catalogued in `fixture-catalog.json` and stage evidence. M3 tool versions are in its exact evidence record. Full raw M6 test output is ignored locally; the committed JSON records its log digest.

## 4. SECURITY

- L0 new analyses use existing Core/Engine/PolicyGateway routes and bounded local inputs. MCP `armorbreak_workflow` accepts only shipped L0 workflows; caller-provided steps, principal, approvals and commands are not accepted.
- M1–M4 do not execute target files. M5 fixture tests run self-authored JS/Python test programs as part of tests and pass only precomputed JSON outcomes into the product capability. Those fixtures are not arbitrary user targets.
- M3 Ghidra 12.1.4 processed six self-authored PE/ELF/Mach-O fixtures; records show `inputExecuted:false`.
- M4 aggregate vulnerability status stays `not_tested`; imported “confirmed” claims cannot confirm findings. Its authored contrast corpus has FPR 0.50.
- L1: local Docker CLI 29.8.1 still cannot reach `dockerDesktopLinuxEngine`; exact-head GitHub Ubuntu jobs passed both the pinned BusyBox benign container path and the inherited real-daemon integration. These validate the hosted CI runner path only and do not establish local daemon or hostile-sample isolation readiness.
- L2: no new remote workflow was added. L3 remains refused.
- `npm audit` against the official npm registry at source SHA `26a3e8e…` found zero known advisories in the lockfile set; this is historical dependency evidence and does not replace current CI. The separate review record is explicitly a same-agent AI pre-review, not an independent security audit or human certification. Redistribution/license review for the final package, optional external tools and binary fixtures remains open. The Ghidra host run is not hostile-sample isolation; exhaustive Windows reparse/TOCTOU, hostile archive/fuzzing, and full approval/session adversarial matrices are not complete.

## 5. PERFORMANCE

See [`performance-report.md`](performance-report.md). In the recorded seven-step workflow benchmark, candidate p50/p95 was 1,267.052/1,322.097 ms versus baseline 1,276.771/1,331.449 ms. M0 did not record CPU identity or peak memory; the comparison is descriptive only, and a second diagnostic run showed substantial SAST timing variation. Candidate end-of-process RSS is not a peak measurement. The 100-run timeout/cancel soak, large-file streaming throughput, peak memory, concurrency and cancellation latency are not verified.

## 6. COMPATIBILITY

- Runtime counts at baseline: 46 capabilities, 9 workflows, 10 DSH tools, 7 MCP tools, 7 skills.
- M6: 53 capabilities, 14 workflows, 10 DSH tools, 8 MCP tools, 7 skills.
- A fresh runtime enumeration against the M6 worktree found all 46 baseline capability IDs and all 9 baseline workflow IDs still present (missing IDs: none); capability risk counts remain 51 L0 / 1 L1 / 1 L2.
- Existing Core version `0.1.0-p1`, protocol v1, CLI command families and policy path are retained. M6 adds one fixed MCP tool and support-status fields.
- The live registry has no diagnostics. The compatibility matrix was corrected to report M5/M6 as locally implemented instead of stale `NOT_IMPLEMENTED`.
- No real user data were accessed or migrated. A current local drill used a synthetic V2.2-compatible task/report/config copy, read historical content using the candidate Core, injected a staged-artifact hash failure, activated and rolled back through the actual installer state machine, and verified exact task/evidence/report/config hashes. It does not establish a full external user-data corpus, owner package install, OS ACL, or service-principal boundary.

## 7. BLOCKED / PARTIAL / UNSUPPORTED

- **P0-H `IN_PROGRESS`, release `NOT_READY`:** Historical checks on `0795c4dd270f59cb60a006c756035da111e1d970` remain in the record and do not stand in for current CI. The current exact PR head at report capture is `c1c109453b12493b3ae9b8a76be4f271a820f835`: V2.3 validation runs `41026010595` (PR event) and `41026004259` (push event), and inherited CI runs `41026010642` (PR event) and `41026004165` (push event) completed successfully. The dedicated main-gate run `41026002895` failed with zero jobs and is not a passing gate. P0-1 and current exact-head checks pass; P0-4 is only a synthetic filesystem drill. Independent human security/license review, real package/profile drill and OS permission verification, a successful dedicated main-gate PR run, exact-main, package/SBOM/attestation, branch-protection verification, package version bump from 2.2.0, and owner authorization remain open.
- **M2 PARTIAL:** JS/TS only; no four-language S3, inter-file taint or broad language matrix.
- **M3 PARTIAL:** native P0 local static E2E is present; P1 bytecode families/APK/DEX refresh and hostile-input isolated E2E are deferred/unverified.
- **M4 PARTIAL:** correlation only; advisory fetching/version evaluation and independent finding validation are unsupported; corpus FPR is 0.50.
- **M5 PARTIAL:** finite caller-supplied outcomes; no arbitrary source-to-spec inference and no global equivalence guarantee.
- **M6 PARTIAL:** the integration is tested on Windows/Ubuntu with Node 22/24, but capability depth and broad language support remain partial as scoped above.
- **Performance PARTIAL:** descriptive microbenchmark only; no peak-memory baseline or soak.
- **Docker/L1 BLOCKED on this host check:** Docker CLI present, Engine named pipe unavailable.
- **P0-3 BLOCKED:** The saved AI pre-review is transparently non-independent and cannot close the human security/license gate.
- **P0-4 PARTIAL:** Real local installer transitions and synthetic-data rollback were exercised; real candidate-package deployment, real user-profile backup/restore, and OS permission identity checks were not.
- **P0-5 PARTIAL:** Version-specific PR/main/tag workflow and a failing-closed release script exist locally; exact workflow runs and repository required-check configuration are not verified. The existing `v2.2.0` guard remains unchanged.
- **Formal release is not authorized:** no tag, merge or publication is performed in this task.

## 8. RELEASE READINESS

- Historical exact PR head tested by runs `40996527035`, `40996532452`, `40996526943`, and `40996532448`: `0795c4dd270f59cb60a006c756035da111e1d970`; M6 source SHA: `965fbe4fa9abd2af73644865a56d8db64c8a6089`. These CI records predate the P0-H code changes below.
- Latest P0-H source commit: `bf7d3d4d590d7ba2cc7d53edf548b1afc78687fd`. Latest PR head at report capture: `c1c109453b12493b3ae9b8a76be4f271a820f835`, with only evidence/report descendants after the source commit. Local full suite/typecheck remain recorded historically at `26a3e8e…`; current exact PR-head hosted CI is recorded below.
- `npm test` at M6 SHA: 647/647; focused CLI/MCP/API: 24/24; `npm run typecheck`: exit 0.
- Node 22.23.4 local validation at `679bbeb6152d9f9c9f151c5bae6f7c01d098b357`: full suite 647/647 and TypeScript check exit 0; the exact log hashes and invalid first attempt are recorded in `evidence/p0-h/node22-local-validation.json`.
- The V2.3-specific integrity validator passed on the current local tree based on PR head `c1c1094…` and checked 76 bound files using source commit `bf7d3d4…`. The committed tree checked remotely by run `41026010595` contained 74 bound files; the two new CI observation records and report updates await exact-head CI on their new commit. The post-source allowlist excludes validators, workflows and security gates; 4 negative provenance tests passed locally. This integrity check is not the release gate; its machine result says `NOT_READY`.
- V2.3 exact-head CI: [40995701875](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/40995701875), head `8364343…`, all six jobs successful. Inherited exact-head CI: [40995701865](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/40995701865), same SHA, full suite, L0 gate and real-daemon Docker integration successful; release evidence gate skipped by the V2.3 branch condition. Benign and real Docker artifact digests are respectively `sha256:bad252c760cd0edcaca51e492cc186db2f0794af4b5ac99bea4ae5ac865b77d8` and `sha256:2b4524eb902045d76ef094a0bed8d9119934e44417ab2cac4541a56d6e45dda9`.
- Official-registry npm audit at current source: exit 0, zero known advisories; package-lock SHA is recorded in its evidence. License review remains incomplete. Package hashes/SBOM/attestation: **NOT_CREATED**. Exact-main CI: **NOT_RUN** because the PR is unmerged.
- Isolated synthetic upgrade/rollback drill: **PASS_ISOLATED_FILESYSTEM_DRILL**; not a real package install or user-data test. Evidence preserves before/after hashes and lists remaining permission limits.
- V2.3 main/tag release gate: local configuration tests pass. Dedicated run `41026002895` on `c1c1094…` failed with zero jobs; earlier PR run `41025798504` exposed missing test scratch initialization (fixed in commit `bf7d3d4…`), but no passing dedicated PR-event run is present. Repository branch protection API returned 403, so required-check settings remain unverified. No merge, tag or release was performed.
- Owner merge/tag/publish decision: pending; this report is not an authorization.

## 9. HANDOFF

Commands used for the implemented local checks:

```powershell
npm test
npm run typecheck
node --test --test-concurrency=1 tests/cli.test.mjs tests/mcp-stdio.test.mjs tests/api.test.mjs
node benchmarks/bench.mjs --sample fixtures/notepad.exe --out .runtime/p0-h-benchmark.json
node scripts/v2/validate-v23-acceptance.mjs
```

Relevant evidence is under `docs/v2.3/evidence/m0/` through `m6/` and `docs/v2.3/evidence/p0-h/`. Draft PR: [#25](https://github.com/LYL-Z/dsh-armorbreak/pull/25). The report capture records exact CI for `c1c1094…`; its report-only descendant will require its own current check IDs in the PR. Remaining blockers are successful execution of the dedicated main-gate PR workflow, independent human security/license review, real package/profile upgrade and rollback plus OS permissions, exact-main/artifact/SBOM/attestation, repository protection verification, package version bump from 2.2.0, and maintainer authorization. No merge, tag or formal release without the owner's explicit decision.
