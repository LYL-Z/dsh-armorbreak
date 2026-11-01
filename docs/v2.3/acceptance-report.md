# ArmorBreak V2.3.0 implementation and acceptance report

This report follows taskbook §15. It reports the latest evidence available for the engineering branch and explicitly separates implementation from release readiness. It does **not** claim a complete V2.3.0 Stable release.

## 1. BASELINE

- Repository: `LYL-Z/dsh-armorbreak`; frozen `origin/main` baseline: `66ec0017af4b9d636f09e45f7cf55eed060512ac`.
- Baseline tag: `v2.2.0` exists; no V2.3 tag is created.
- Branch: `feature/v2.3-universal-program-intelligence`; implementation branch was created from the exact main SHA above.
- M6 source: `965fbe4fa9abd2af73644865a56d8db64c8a6089`; last previously pushed PR head tested by GitHub: `0795c4dd270f59cb60a006c756035da111e1d970`. New P0-H source commits are recorded below; historical CI is not proof for them.
- P0-H snapshot (2026-11-01): GitHub reports PR #25 OPEN/Draft at `fd0f3fc92c1ef607d324259d13c4634d8846915e`. Source commit `b5b89bdc5dd08159d5ac23c065e5acd9b4a711b2` is local and not yet pushed at this report edit. Exact SHA runs on `fd0f3fc…` are recorded in `evidence/p0-h/github-ci-run-412670.json`; they are historical once a later source commit is pushed. No run on `b5b89bd…` has yet been observed.
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
| Exact-head CI | Run `41267019579`, SHA `fd0f3fc92c1ef607d324259d13c4634d8846915e`; `evidence/p0-h/github-ci-run-412670.json` | All six jobs passed: evidence integrity, benign L1 path, Node 22/24 Ubuntu and Windows. This validates only `fd0f3fc…`; the later Windows path fix `b5b89bd…` awaits fresh CI |
| Dedicated V2.3 PR gate | Run `41267019541`, same `fd0f3fc…`; `evidence/p0-h/github-ci-run-412670.json` | Real PR-event run created six jobs; Ubuntu Node 22/24 passed, Windows Node 22/24 each failed 10 tests, and main/release jobs skipped as designed. This is not a successful gate result |
| Inherited CI | Run `41267019416`, same `fd0f3fc…`; `evidence/p0-h/github-ci-run-412670.json` | L0 and Docker jobs passed; Node 24 Ubuntu had 2 release CLI test failures in shallow checkout, and Node 24 Windows had 10 path-boundary/dependent failures. Release evidence job skipped |
| Dependency audit | `evidence/p0-h/npm-audit.json`; npm audit via `https://registry.npmjs.org` | Exit 0; 0 info/low/moderate/high/critical advisories in the audited lockfile dependency set; license review not included |
| Latest focused local checks | Source SHA `b5b89bdc5dd08159d5ac23c065e5acd9b4a711b2`; path boundary, migration, gate/provenance and dependent CLI/MCP/SDK/workbench tests; `npm run typecheck` | Typecheck exit 0; 21/22 focused tests passed before manifest regeneration. The one failure is the intended source-to-evidence lineage check because the manifest still names `2cb8a3d…`; regenerate only after report/matrix/threat updates, then rerun |
| P0-1 evidence provenance | `tests/v23-provenance.test.mjs`; `evidence/p0-h/acceptance-manifest.json` | Negative tests 4/4 passed locally. Current manifest is stale at source `2cb8a3d…` relative to `b5b89bd…`; regenerate after this report-only update, then verify evidence-only lineage and full inventory |
| P0-4 isolated real-package upgrade/rollback | `evidence/p0-h/real-package-upgrade-rollback.json` | PASS on Windows x64 / Node 24.16.0 using the unchanged published V2.2.0 package and a reproducible, unsigned V2.3 candidate. Old task/report reads, candidate startup, MCP init/session denial, host config, current-user ACL, workspace denial, injected corruption, rollback, and before/after task/config/report hashes passed. All data were isolated test data. Rollback selected the old side-by-side package; no OS updater or real user profile was exercised |
| P0-5 V2.3-specific gate | `scripts/v2/v23-release-gate.mjs`, `.github/workflows/v2.3-main-gate.yml`, `tests/v23-release-gate.test.mjs`, `evidence/p0-h/github-ci-run-412670.json` | Actionlint passes on the corrected workflow. Earlier zero-job run `41027505694` is historical. Dedicated PR run `41267019541` generated jobs but failed both Windows matrices on `fd0f3fc…`; b5 path fix is pending hosted retest. The 2 Ubuntu jobs passed; main/release jobs skipped as designed. Branch-protection API access previously returned 403 |
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
- The isolated candidate archive built from source `34b431931857e786b77ff28c90610857b8c8844c` contains 550 files and has SHA-256 `f23b79948faf2d53164dddddeea37a00c0625c758eb02dee9542678cd0ce779d`; its SBOM SHA-256 is `2b589cdb4ea50ef3f2859f47a0598ccff57ebca9e62b1eecd1e8d6ebd23e7a7a`. Archive inspection found no executable/library/archive binaries, tests or fixtures. TypeScript `5.9.3` is declared in package metadata but not bundled; npm installation and its transitive-license path are separate. The inventory is developer-prepared and requires independent legal/license review.
- Separate `npm pack --dry-run --json` inspection found 664 npm package files / 9,185,551 unpacked bytes and no bundled dependencies. Unlike the portable release archive, this npm package file list includes 11 M3 fixture paths: three `.bin`, two `.elf`, two `.exe`, three `.macho`, and the fixture C source. The exact local file SHA-256 inventory is `evidence/p0-h/npm-package-dry-run.json`; this was not published. Independent license/security review must cover both distribution paths, including fixture provenance and binary redistribution.

## 5. PERFORMANCE

See [`performance-report.md`](performance-report.md). In the recorded seven-step workflow benchmark, candidate p50/p95 was 1,267.052/1,322.097 ms versus baseline 1,276.771/1,331.449 ms. M0 did not record CPU identity or peak memory; the comparison is descriptive only, and a second diagnostic run showed substantial SAST timing variation. Candidate end-of-process RSS is not a peak measurement. The 100-run timeout/cancel soak, large-file streaming throughput, peak memory, concurrency and cancellation latency are not verified.

## 6. COMPATIBILITY

- Runtime counts at baseline: 46 capabilities, 9 workflows, 10 DSH tools, 7 MCP tools, 7 skills.
- M6: 53 capabilities, 14 workflows, 10 DSH tools, 8 MCP tools, 7 skills.
- A fresh runtime enumeration against the M6 worktree found all 46 baseline capability IDs and all 9 baseline workflow IDs still present (missing IDs: none); capability risk counts remain 51 L0 / 1 L1 / 1 L2.
- Existing Core version `0.1.0-p1`, protocol v1, CLI command families and policy path are retained. M6 adds one fixed MCP tool and support-status fields.
- The live registry has no diagnostics. The compatibility matrix was corrected to report M5/M6 as locally implemented instead of stale `NOT_IMPLEMENTED`.
- No real user data were accessed or migrated. The earlier synthetic filesystem state-machine drill is historical and does not establish package deployment. The newer P0-4 drill extracted and started the actual portable V2.3 candidate beside the published V2.2.0 package using isolated test data, read an old task/report, tested MCP/session and current-user ACL boundaries, injected a candidate corruption, and rolled back to the preserved V2.2.0 package with unchanged task/config/report hashes. It does not establish an OS installer/updater, a second Windows identity, or arbitrary external user-profile compatibility.

## 7. BLOCKED / PARTIAL / UNSUPPORTED

- **P0-H `IN_PROGRESS`, release `NOT_READY`:** Live PR #25 is OPEN/Draft at `fd0f3fc…`; local source fix `b5b89bd…` is not yet pushed. At `fd0f3fc…`, exact-head validation run `41267019579` passed all six jobs, but dedicated V2.3 PR run `41267019541` and inherited CI `41267019416` failed Windows tests (10 each); inherited Ubuntu Node 24 also had 2 shallow-checkout release CLI failures. The PR gate did run and created jobs; only its main/release jobs were skipped by event design. Fresh CI on b5 is outstanding. P0-4 real isolated package drill is recorded, but predates the latest source fix. P0-3 independent human security/license review remains blocked, including review of 11 M3 fixture paths in the npm package dry-run inventory. Exact-current-HEAD CI, branch-protection verification, exact-main CI, release artifact/SBOM/attestation at eventual main, external signer trust anchors and maintainer authorization remain open. The `v2.2.0` tag ruleset is unchanged; owner bypass remains enabled.
- **M2 PARTIAL:** JS/TS only; no four-language S3, inter-file taint or broad language matrix.
- **M3 PARTIAL:** native P0 local static E2E is present; P1 bytecode families/APK/DEX refresh and hostile-input isolated E2E are deferred/unverified.
- **M4 PARTIAL:** correlation only; advisory fetching/version evaluation and independent finding validation are unsupported; corpus FPR is 0.50.
- **M5 PARTIAL:** finite caller-supplied outcomes; no arbitrary source-to-spec inference and no global equivalence guarantee.
- **M6 PARTIAL:** the integration is tested on Windows/Ubuntu with Node 22/24, but capability depth and broad language support remain partial as scoped above.
- **Performance PARTIAL:** descriptive microbenchmark only; no peak-memory baseline or soak.
- **Docker/L1 BLOCKED on this host check:** Docker CLI present, Engine named pipe unavailable.
- **P0-3 BLOCKED:** The saved AI pre-review is transparently non-independent and cannot close the human security/license gate.
- **P0-4 PARTIAL:** Real portable candidate package deployment and rollback passed against copied V2.2 test data. OS-integrated updater behavior, a second Windows principal denial, and real user-profile restoration remain unverified.
- **P0-5 PARTIAL:** Version-specific PR/main/tag workflow and a fail-closed release script exist. State/provenance tests and actionlint pass locally, but a successful dedicated PR-event run on the fixed workflow and repository required-check configuration are not verified. The existing `v2.2.0` guard remains unchanged.
- **Formal release is not authorized:** no tag, merge or publication is performed in this task.

## 8. RELEASE READINESS

- Historical exact PR head tested by runs `40996527035`, `40996532452`, `40996526943`, and `40996532448`: `0795c4dd270f59cb60a006c756035da111e1d970`; M6 source SHA: `965fbe4fa9abd2af73644865a56d8db64c8a6089`. These CI records predate the P0-H code changes below.
- Historical M6/P0-H records above remain bound to their recorded source SHAs. Current source candidate commit: `b5b89bdc5dd08159d5ac23c065e5acd9b4a711b2`; live remote PR HEAD at time of report edit: `fd0f3fc92c1ef607d324259d13c4634d8846915e`. The `b5b89bd…` source fix is local-only until pushed. Current remote CI evidence is limited to `fd0f3fc…` and is recorded in `github-ci-run-412670.json`.
- `npm test` at M6 SHA: 647/647; focused CLI/MCP/API: 24/24; `npm run typecheck`: exit 0.
- Node 22.23.4 local validation at `679bbeb6152d9f9c9f151c5bae6f7c01d098b357`: full suite 647/647 and TypeScript check exit 0; the exact log hashes and invalid first attempt are recorded in `evidence/p0-h/node22-local-validation.json`.
- Provenance negative cases pass locally (4/4). After updating this report, compatibility matrix and threat model, regenerate the manifest against `b5b89bd…`, verify its full evidence inventory, and rerun integrity checks. This integrity check is not the release gate; machine release readiness remains `NOT_READY`.
- Exact-head validation [41267019579](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41267019579) succeeded only at `fd0f3fc…`. Dedicated V2.3 PR gate [41267019541](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41267019541) created jobs but failed both Windows matrices; inherited CI [41267019416](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41267019416) also failed Windows and had 2 Ubuntu shallow-checkout CLI test failures. The newest source fix `b5b89bd…` has not yet been pushed or tested by GitHub.
- Official-registry npm audit at historical source `26a3e8e…`: exit 0, zero known advisories; lock SHA is in its evidence. Candidate package/SBOM hashes exist for the isolated Windows drill and are not release artifacts. GitHub attestation and exact-main CI: **NOT_CREATED / NOT_RUN** because the PR is unmerged. Independent license review remains open.
- Isolated actual portable package upgrade/rollback drill: **PASS_ISOLATED_REAL_PACKAGE_DEPLOYMENT**, with copied V2.2 test task/report/config, actual V2.3 archive startup, historical reads, MCP and ACL checks, failure injection and rollback hashes. It was run against candidate source `34b4319…`, not latest source `b5b89bd…`; rerun on the final source candidate remains needed. No user data or formal V2.2 assets were modified.
- Dedicated V2.3 PR workflow: run `41027505694` on `ed3d6f9…` was the historical zero-job failure. The corrected workflow later ran on the actual PR event as `41267019541` at `fd0f3fc…` and created six jobs; Ubuntu passed and Windows failed 10 tests in each Node matrix. Workflow is syntactically valid under actionlint. GitHub run `41267019579` exact-head validation passed on the same old SHA. Fresh CI for `b5b89bd…` is pending. Exact-main verification and authorized branch protection inspection remain unavailable while the Draft PR is unmerged; the active V2.2.0 tag ruleset was not modified. P0-5 remains open.
- Owner merge/tag/publish decision: pending; this report is not an authorization.

## 9. HANDOFF

Commands used for implemented/local checks (each result remains bound to its stated source SHA):

```powershell
npm test
npm run typecheck
node --test --test-concurrency=1 tests/cli.test.mjs tests/mcp-stdio.test.mjs tests/api.test.mjs
node benchmarks/bench.mjs --sample fixtures/notepad.exe --out .runtime/p0-h-benchmark.json
node scripts/v2/validate-v23-acceptance.mjs
node scripts/v2/v23-release-gate.mjs --check-pr
node scripts/v2/build-release.mjs --out dist --evidence dist/release-build.json --no-portable-evidence
node scripts/v2/v23-real-package-drill.mjs
```

Relevant evidence is under `docs/v2.3/evidence/m0/` through `m6/` and `docs/v2.3/evidence/p0-h/`. Draft PR: [#25](https://github.com/LYL-Z/dsh-armorbreak/pull/25). This report edit is based on local source `b5b89bdc5dd08159d5ac23c065e5acd9b4a711b2` and live remote PR HEAD `fd0f3fc92c1ef607d324259d13c4634d8846915e`; regenerate the acceptance manifest after the other evidence edits. New hosted CI must run on the pushed HEAD. Remaining blockers include passing Windows standard and dedicated PR CI, independent human security/license review of the exact source and both distribution paths, a latest-source real-package drill, exact-main artifact/SBOM/GitHub attestation, branch-protection verification, and explicit maintainer authorization. PR remains Draft; no merge, tag or formal release is authorized.
