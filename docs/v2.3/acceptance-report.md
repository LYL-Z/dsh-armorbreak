# ArmorBreak V2.3.0 implementation and acceptance report

This report follows taskbook §15. It reports the latest evidence available for the engineering branch and explicitly separates implementation from release readiness. It does **not** claim a complete V2.3.0 Stable release.

## 1. BASELINE

- Repository: `LYL-Z/dsh-armorbreak`; latest live `origin/main` checked on 2026-10-29: `66ec0017af4b9d636f09e45f7cf55eed060512ac`.
- Baseline tag: `v2.2.0` exists; no V2.3 tag is created.
- Branch: `feature/v2.3-universal-program-intelligence`; implementation branch was created from the exact main SHA above.
- M6 source: `965fbe4fa9abd2af73644865a56d8db64c8a6089`; current P0-H exact-CI source: `d53146706a760b8789b297f7445838c9b0a0a4c6` (draft PR #25).
- Windows 11 build 26300, x64; baseline and M6 recorded Node `v24.16.0`, npm `11.13.0`; TypeScript lock `5.9.3`.
- Frozen M0 full test: 530/530 on the baseline after setting TEMP/TMP to a same-volume worktree directory; default cross-volume run had 6 environment-dependent failures and was retained in evidence. Candidate M6 evidence reports 647/647 on the exact M6 source SHA.

## 2. IMPLEMENTED

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
| Exact-head CI | Run `40994705723`, SHA `d53146706a760b8789b297f7445838c9b0a0a4c6`; `evidence/p0-h/github-ci-run-40994705723.json` | Ubuntu Node 22/24: 649/649 each; Windows Node 22/24: 647/647 each; all typechecks exit 0. The two-count difference is from two explicitly Linux-only tests not registered on Windows; evidence integrity and benign pinned-image L1 path passed. Later CI diagnosed a missing pinned Python runtime in the inherited workflow; see run `40995286248` and its evidence record |
| Dependency audit | `evidence/p0-h/npm-audit.json`; npm audit via `https://registry.npmjs.org` | Exit 0; 0 info/low/moderate/high/critical advisories in the audited lockfile dependency set; license review not included |
| Performance | [`performance-report.md`](performance-report.md) and sanitized raw benchmark | Same benchmark script/Node/OS family; baseline CPU identity not recorded, no peak-memory comparison |

The stage JSON records include exact source SHAs, commands, counts and evidence hashes. Fixture SHA-256 values are catalogued in `fixture-catalog.json` and stage evidence. M3 tool versions are in its exact evidence record. Full raw M6 test output is ignored locally; the committed JSON records its log digest.

## 4. SECURITY

- L0 new analyses use existing Core/Engine/PolicyGateway routes and bounded local inputs. MCP `armorbreak_workflow` accepts only shipped L0 workflows; caller-provided steps, principal, approvals and commands are not accepted.
- M1–M4 do not execute target files. M5 fixture tests run self-authored JS/Python test programs as part of tests and pass only precomputed JSON outcomes into the product capability. Those fixtures are not arbitrary user targets.
- M3 Ghidra 12.1.4 processed six self-authored PE/ELF/Mach-O fixtures; records show `inputExecuted:false`.
- M4 aggregate vulnerability status stays `not_tested`; imported “confirmed” claims cannot confirm findings. Its authored contrast corpus has FPR 0.50.
- L1: local Docker CLI 29.8.1 still cannot reach `dockerDesktopLinuxEngine`; separately, the exact-head GitHub Ubuntu runner passed the pinned BusyBox benign container-path job. This validates that CI path only and does not establish local daemon or hostile-sample isolation readiness.
- L2: no new remote workflow was added. L3 remains refused.
- `npm audit` against the official npm registry found zero known advisories for the lockfile dependency set. A license review and independent security review, exhaustive Windows reparse/TOCTOU matrix, hostile archive/fuzzing campaign and full approval/session adversarial matrix have not been completed.

## 5. PERFORMANCE

See [`performance-report.md`](performance-report.md). In the recorded seven-step workflow benchmark, candidate p50/p95 was 1,267.052/1,322.097 ms versus baseline 1,276.771/1,331.449 ms. M0 did not record CPU identity or peak memory; the comparison is descriptive only, and a second diagnostic run showed substantial SAST timing variation. Candidate end-of-process RSS is not a peak measurement. The 100-run timeout/cancel soak, large-file streaming throughput, peak memory, concurrency and cancellation latency are not verified.

## 6. COMPATIBILITY

- Runtime counts at baseline: 46 capabilities, 9 workflows, 10 DSH tools, 7 MCP tools, 7 skills.
- M6: 53 capabilities, 14 workflows, 10 DSH tools, 8 MCP tools, 7 skills.
- A fresh runtime enumeration against the M6 worktree found all 46 baseline capability IDs and all 9 baseline workflow IDs still present (missing IDs: none); capability risk counts remain 51 L0 / 1 L1 / 1 L2.
- Existing Core version `0.1.0-p1`, protocol v1, CLI command families and policy path are retained. M6 adds one fixed MCP tool and support-status fields.
- The live registry has no diagnostics. The compatibility matrix was corrected to report M5/M6 as locally implemented instead of stale `NOT_IMPLEMENTED`.
- Old user task/report files were not migrated. Read compatibility on the local committed fixtures is covered by the existing suite, but no full external user-data corpus or upgrade migration was exercised.

## 7. BLOCKED / PARTIAL / UNSUPPORTED

- **P0-H `IN_PROGRESS`, release `NOT_READY`:** Exact SHA `d53146706a760b8789b297f7445838c9b0a0a4c6` passed GitHub run `40994705723`. Diagnostic run `40995286248` on SHA `7feaaa3e48459cf43b3f974e1cb2c47e8c050c4d` found the inherited Windows Node 24 test job did not explicitly install Python, which the M5 fixture requires; the CI matrices now pin Python 3.11, and the current follow-up revision is checked by PR #25 exact-head jobs. Independent security and license reviews, an upgrade/rollback drill, exact-main release artifacts, SBOM and attestation remain incomplete.
- **M2 PARTIAL:** JS/TS only; no four-language S3, inter-file taint or broad language matrix.
- **M3 PARTIAL:** native P0 local static E2E is present; P1 bytecode families/APK/DEX refresh and hostile-input isolated E2E are deferred/unverified.
- **M4 PARTIAL:** correlation only; advisory fetching/version evaluation and independent finding validation are unsupported; corpus FPR is 0.50.
- **M5 PARTIAL:** finite caller-supplied outcomes; no arbitrary source-to-spec inference and no global equivalence guarantee.
- **M6 PARTIAL:** the integration is tested on Windows/Ubuntu with Node 22/24, but capability depth and broad language support remain partial as scoped above.
- **Performance PARTIAL:** descriptive microbenchmark only; no peak-memory baseline or soak.
- **Docker/L1 BLOCKED on this host check:** Docker CLI present, Engine named pipe unavailable.
- **Formal release is not authorized:** no tag, merge or publication is performed in this task.

## 8. RELEASE READINESS

- Exact PR head tested by run `40994705723`: `d53146706a760b8789b297f7445838c9b0a0a4c6`; M6 source SHA: `965fbe4fa9abd2af73644865a56d8db64c8a6089`.
- `npm test` at M6 SHA: 647/647; focused CLI/MCP/API: 24/24; `npm run typecheck`: exit 0.
- Node 22.23.4 local validation at `679bbeb6152d9f9c9f151c5bae6f7c01d098b357`: full suite 647/647 and TypeScript check exit 0; the exact log hashes and invalid first attempt are recorded in `evidence/p0-h/node22-local-validation.json`.
- The V2.3-specific integrity validator passed on `d531467…` and checked 57 bound files. A CRLF simulation passed, a reversible content-tamper probe was rejected (exit 1), and the restored bundle passed again. This integrity check is not the Stable release gate; its machine result says `NOT_READY`.
- GitHub exact-head CI run: [40994705723](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/40994705723), head `d531467…`, all six V2.3 jobs successful. Its benign Docker artifact is `v2.3-l1-docker-verification` (artifact digest `sha256:e762a8530203afa7082dd6f700e1594db7cf87fcf87bc8d85c484e96319df472`). A later inherited Windows test failure and the pinned-Python correction are recorded in [diagnostic run 40995286248](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/40995286248); exact-head PR checks for the correction are available on PR #25.
- Official-registry npm audit: exit 0, zero known vulnerabilities; evidence is committed separately. Package hashes/SBOM/attestation: **NOT_CREATED**. Exact-main CI: **NOT_RUN** because the PR is unmerged.
- Migration and rollback drill: **NOT_RUN**.
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

Relevant evidence is under `docs/v2.3/evidence/m0/` through `m6/` and `docs/v2.3/evidence/p0-h/`. Draft PR: [#25](https://github.com/LYL-Z/dsh-armorbreak/pull/25). The exact tested implementation SHA and run are listed in §8; a documentation/evidence-only follow-up needs its own exact-head run. Next priorities are independent security/license review, upgrade/rollback drill, then owner review of the remaining Stable gates. No merge, tag or formal release without the owner's explicit decision.
