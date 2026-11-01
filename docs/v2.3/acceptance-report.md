# ArmorBreak V2.3.0 implementation and acceptance report

This report follows taskbook §15. It reports the latest evidence available for the engineering branch and explicitly separates implementation from release readiness. It does **not** claim a complete V2.3.0 Stable release.

## 1. BASELINE

- Repository: `LYL-Z/dsh-armorbreak`; frozen `origin/main` baseline: `66ec0017af4b9d636f09e45f7cf55eed060512ac`.
- Baseline tag: `v2.2.0` exists; no V2.3 tag is created.
- Branch: `feature/v2.3-universal-program-intelligence`; implementation branch was created from the exact main SHA above.
- M6 source: `965fbe4fa9abd2af73644865a56d8db64c8a6089`; last previously pushed PR head tested by GitHub: `0795c4dd270f59cb60a006c756035da111e1d970`. New P0-H source commits are recorded below; historical CI is not proof for them.
- Previous passing snapshot (2026-11-01): PR #25 was OPEN/Draft at evidence HEAD `9b7b473beb996610ac17a745f92a3a28534442e7`; source/workflow commit `b39f2285f3bc05301d2989d6a66fc1e641af7b96` remains unchanged. Its three PR-event workflows passed: exact-head `41270050323`, V2.3 main/release gate `41270050295`, and inherited CI `41270050351`; details are in `evidence/p0-h/github-ci-run-412700.json`.
- Subsequent interim evidence-only commit `39de997c0732953d7462a4b44e4ecd0f549402c0` failed its three PR-event checks because a reviewer-packet edit escaped the post-source evidence allowlist. The failure is preserved in `evidence/p0-h/github-ci-run-412859.json`; the allowed source/workflow code remains unchanged. This report records the `9b7b473…` successful snapshot and must not be read as claiming `39de997…` passed.
- Latest passing PR snapshot (2026-11-01): PR #25 remains OPEN/Draft at exact HEAD `14df1d05c6397a25cfffd4903d00c9df3f697c61`; source/workflow commit `b39f2285f3bc05301d2989d6a66fc1e641af7b96` remains unchanged. The regenerated manifest binds 96 files. Exact-head validation `41286249061`, V2.3 main/release gate `41286249033`, and inherited CI `41286249199` all passed on that exact SHA. Job details are in `evidence/p0-h/github-ci-run-412862.json`; resumed local checks are in `evidence/p0-h/local-resume-validation-14df1d0.json`. The previous `39de997…` allowlist failure was corrected by restoring the packet path and is retained as historical evidence.
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
| Exact-head CI | Run `41286249061`, SHA `14df1d05c6397a25cfffd4903d00c9df3f697c61`; `evidence/p0-h/github-ci-run-412862.json` | All six PR-event jobs passed: evidence integrity, benign L1 path, Node 22/24 Ubuntu and Windows |
| Dedicated V2.3 PR gate | Run `41286249033`, same `14df1d0…`; `evidence/p0-h/github-ci-run-412862.json` | Actual PR-event run passed all four Node 22/24 Windows/Ubuntu candidate jobs. Main-candidate and release-verification jobs skipped by event design; this does not establish exact-main CI or release readiness |
| Inherited CI | Run `41286249199`, same `14df1d0…`; `evidence/p0-h/github-ci-run-412862.json` | Node 24 Ubuntu/Windows, L0 and real-daemon Docker jobs passed; release-only evidence job skipped by event design |
| Dependency audit | `evidence/p0-h/npm-audit.json`; npm audit via `https://registry.npmjs.org` | Exit 0; 0 info/low/moderate/high/critical advisories in the audited lockfile dependency set; license review not included |
| Latest local full suite | Evidence HEAD `e02e7fe356f0141fb635a2db0af2be962dcec50e`, source commit `b39f2285f3bc05301d2989d6a66fc1e641af7b96`; `evidence/p0-h/local-validation-e02e7fe.json` | Windows 11 x64 / Node 24.16.0; `node --test --test-concurrency=1` passed 662/662 using isolated external TEMP/TMP and runtime Git 2.53.0; typecheck exit 0. The system Git 2.54.0 temporary-clone attempt crashed with `0xC0000005` and is retained as an environment-specific failed attempt |
| Historical local full suite | Source/evidence snapshot `7a78aef15e59f16f71b192089dcb82a81e811fb5`; `evidence/p0-h/local-validation-7a78aef.json` | `npm test` passed 662/662 with runtime Git 2.53.0 first on PATH; default system Git attempt had one fixture clone crash (`0xC0000005`, 661 pass). TypeScript exit 0; evidence integrity passed 83 files before later evidence edits; PR gate `VALIDATED` and `NOT_READY`; actionlint exit 0 |
| P0-1 evidence provenance | `tests/v23-provenance.test.mjs`; `evidence/p0-h/acceptance-manifest.json` | Negative cases cover validator/workflow/gate tampering, allowlist expansion, malformed SHA and stale SHA reuse. The regenerated manifest binds source commit `b39f228…`; exact-head evidence integrity passed on `e02e7fe…`, `9b7b473…`, and current PR HEAD `14df1d0…`. The intervening `39de997…` packet-path failure is preserved separately and was corrected by restoring the non-allowlisted path |
| P0-4 isolated real-package upgrade/rollback | `evidence/p0-h/real-package-upgrade-rollback.json` | PASS on current source `7a78aef…`, Windows x64 / Node 24.16.0. Reproducible unsigned portable package SHA-256 `cb9e9edef5fd677adbdee97e521f09a457505bee805db319719c206c579590fc`; unchanged V2.2.0 asset SHA-256 `5e5aca98da18d4f0cb17db71cf57c5577f8f8f64810a30844bd5237b4ed7b630`. Old task/report reads, startup, MCP/principal/session denial, current-user ACL, workspace denial, corruption injection and rollback passed; task-tree/config/report hashes matched before and after. No OS updater, second identity or real user profile was exercised |
| P0-5 V2.3-specific gate | `scripts/v2/v23-release-gate.mjs`, `.github/workflows/v2.3-main-gate.yml`, `tests/v23-release-gate.test.mjs`, `evidence/p0-h/github-ci-run-412862.json` | actionlint passed in the dedicated workflow; actual PR-event run `41286249033` passed all four candidate matrix jobs on `14df1d0…`; main and release jobs were correctly skipped. The V2.2.0 tag guard remains. Repository required-check/branch-protection configuration still cannot be verified (GitHub API returned 403); exact-main and signed release verification have not run |
| Security/license pre-review | `evidence/p0-h/security-license-review-preliminary.json` | Explicitly same-agent AI pre-review, not independent or human; it documents coverage and blockers but does not satisfy P0-3 |
| Latest dependency audit | `evidence/p0-h/npm-audit-latest.json`, source SHA `26a3e8e…` | Official npm registry audit exit 0; zero advisories; package-lock SHA recorded. This is not a license review |
| Performance | [`performance-report.md`](performance-report.md) and sanitized raw benchmark | Same benchmark script/Node/OS family; baseline CPU identity not recorded, no peak-memory comparison |

The stage JSON records include exact source SHAs, commands, counts and evidence hashes. Fixture SHA-256 values are catalogued in `fixture-catalog.json` and stage evidence. M3 tool versions are in its exact evidence record. Full raw M6 test output is ignored locally; the committed JSON records its log digest.

## 4. SECURITY

- L0 new analyses use existing Core/Engine/PolicyGateway routes and bounded local inputs. MCP `armorbreak_workflow` accepts only shipped L0 workflows; caller-provided steps, principal, approvals and commands are not accepted.
- M1–M4 do not execute target files. M5 fixture tests run self-authored JS/Python test programs as part of tests and pass only precomputed JSON outcomes into the product capability. Those fixtures are not arbitrary user targets.
- M3 Ghidra 12.1.4 processed six self-authored PE/ELF/Mach-O fixtures; records show `inputExecuted:false`.
- M4 aggregate vulnerability status stays `not_tested`; imported “confirmed” claims cannot confirm findings. Its authored contrast corpus has FPR 0.50.
- L1: the previously recorded Docker-unavailable diagnostic remains historical (2026-10-29). On 2026-11-01, local Docker Desktop was reachable and a real pinned BusyBox benign probe passed (`local-docker-l1-e02e7fe.json`): the process ran as uid 65534 and the sample mount rejected writes. The run used only a self-authored sample and was executed in the disposable verification worktree. This is a bounded benign-path check, not hostile-sample isolation certification.
- L2: no new remote workflow was added. L3 remains refused.
- `npm audit` against the official npm registry at source SHA `26a3e8e…` found zero known advisories in the lockfile set; this is historical dependency evidence and does not replace current CI. The separate review record is explicitly a same-agent AI pre-review, not an independent security audit or human certification. Redistribution/license review for the final package, optional external tools and binary fixtures remains open. The Ghidra host run is not hostile-sample isolation; exhaustive Windows reparse/TOCTOU, hostile archive/fuzzing, and full approval/session adversarial matrices are not complete.
- The latest isolated candidate built from source snapshot `7a78aef15e59f16f71b192089dcb82a81e811fb5` contains 551 files; archive SHA-256 `cb9e9edef5fd677adbdee97e521f09a457505bee805db319719c206c579590fc`, complete per-member manifest SHA-256 `46b607b92248c4bdab0bcadf25ed5c5b5f58223061eba36a5a34bde21ad7b981`, and CycloneDX 1.5 SBOM SHA-256 `4579399cf0df2608106cad5ace01aad13e68399c9cc7e94e652bb3416966b886`. It has no executable/library/archive binaries, tests or fixtures; reproducibility and clean-room startup passed but production signing is absent. TypeScript `5.9.3` is declared but not bundled; npm installation and transitive licenses are separate. This developer-prepared inventory requires independent legal/license review.
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

- **P0-H `IN_PROGRESS`, release `NOT_READY`:** Current PR #25 is OPEN/Draft at `14df1d05c6397a25cfffd4903d00c9df3f697c61`; source/workflow commit is `b39f228…`. Exact-head validation `41286249061`, V2.3 main/release gate `41286249033`, and inherited CI `41286249199` all passed on this exact HEAD. The interim `39de997…` allowlist failure is fixed and retained in `github-ci-run-412859.json`. P0-3 independent human security/license review remains a blocker, including the 11 M3 fixture paths found in the npm package dry run. Also open: repository required-check/branch-protection verification (API returned 403), OS-integrated updater and second-principal validation, exact-main CI, final artifact/SBOM/attestation on main, trusted external signer keys, and explicit maintainer authorization. The `v2.2.0` tag protection is unchanged; owner bypass remains enabled.
- **M2 PARTIAL:** JS/TS only; no four-language S3, inter-file taint or broad language matrix.
- **M3 PARTIAL:** native P0 local static E2E is present; P1 bytecode families/APK/DEX refresh and hostile-input isolated E2E are deferred/unverified.
- **M4 PARTIAL:** correlation only; advisory fetching/version evaluation and independent finding validation are unsupported; corpus FPR is 0.50.
- **M5 PARTIAL:** finite caller-supplied outcomes; no arbitrary source-to-spec inference and no global equivalence guarantee.
- **M6 PARTIAL:** the integration is tested on Windows/Ubuntu with Node 22/24, but capability depth and broad language support remain partial as scoped above.
- **Performance PARTIAL:** descriptive microbenchmark only; no peak-memory baseline or soak.
- **Docker/L1 benign path PASS:** local pinned BusyBox probe and hosted Docker CI passed; hostile-sample isolation certification remains unverified.
- **P0-3 BLOCKED:** The saved AI pre-review is transparently non-independent and cannot close the human security/license gate.
- **P0-4 PARTIAL:** Real portable candidate package deployment and rollback passed against copied V2.2 test data. OS-integrated updater behavior, a second Windows principal denial, and real user-profile restoration remain unverified.
- **P0-5 PARTIAL:** Version-specific PR/main/tag workflow and fail-closed release script exist. The dedicated PR-event matrix passed on `14df1d0…`; the failed `39de997…` evidence-only snapshot is corrected and preserved as a historical failure. The V2.2.0 guard is unchanged. Main-branch candidate build/attestation and tag release verification correctly did not run on a Draft PR; repository required-check settings remain unverified.
- **Formal release is not authorized:** no tag, merge or publication is performed in this task.

## 8. RELEASE READINESS

- Historical exact PR head tested by runs `40996527035`, `40996532452`, `40996526943`, and `40996532448`: `0795c4dd270f59cb60a006c756035da111e1d970`; M6 source SHA: `965fbe4fa9abd2af73644865a56d8db64c8a6089`. These CI records predate the P0-H code changes below.
- Historical M6/P0-H records remain bound to their recorded source SHAs. Current source/workflow commit is `b39f2285f3bc05301d2989d6a66fc1e641af7b96`; current passing PR evidence HEAD is `14df1d05c6397a25cfffd4903d00c9df3f697c61`, and exact-head runs are listed in §3 and `github-ci-run-412862.json`. Local full-suite evidence is from `e02e7fe…` on the same source commit `b39f228…`, with only subsequent evidence/docs commits between them; hosted full-suite matrix checks passed on current HEAD. The isolated portable package was built and deployed from test candidate source `7a78aef15e59f16f71b192089dcb82a81e811fb5`; no app runtime code changed after that package source, but later documentation/workflow changes mean it is not the final main/tag artifact.
- `npm test` at M6 SHA: 647/647; focused CLI/MCP/API: 24/24; `npm run typecheck`: exit 0.
- Node 22.23.4 local validation at `679bbeb6152d9f9c9f151c5bae6f7c01d098b357`: full suite 647/647 and TypeScript check exit 0; the exact log hashes and invalid first attempt are recorded in `evidence/p0-h/node22-local-validation.json`.
- Provenance negative cases pass locally. The acceptance manifest binds source `b39f228…` and 96 files; integrity validation is not the release gate and readiness remains `NOT_READY`.
- Exact-head validation [41286249061](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41286249061), dedicated V2.3 PR gate [41286249033](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41286249033), and inherited CI [41286249199](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41286249199) all passed as real PR-event runs on exact HEAD `14df1d0…`. The matrix covered Node 22/24 on Windows/Ubuntu; L0 and Docker checks passed. Main-only candidate/attestation and tag release jobs were skipped by event contract. Earlier failed runs at `fd0f3fc…` and interim allowlist failure at `39de997…` remain recorded as historical failures.
- Official-registry npm audit at historical source `26a3e8e…`: exit 0, zero known advisories; lock SHA is in its evidence. Candidate package/SBOM hashes exist for the isolated Windows drill and are not release artifacts. GitHub attestation and exact-main CI: **NOT_CREATED / NOT_RUN** because the PR is unmerged. Independent license review remains open.
- Isolated actual portable package upgrade/rollback drill: **PASS_ISOLATED_REAL_PACKAGE_DEPLOYMENT**, candidate source `7a78aef…`, archive SHA-256 `cb9e9edef5fd677adbdee97e521f09a457505bee805db319719c206c579590fc`. It exercised copied V2.2 task/report/config, actual V2.3 archive startup and historical reads, MCP/principal/session denial, current-user ACL, workspace boundary, injected package corruption and rollback; task/config/report hashes matched before/after. No user data or formal V2.2 assets were modified. OS updater and second Windows principal remain untested.
- Dedicated V2.3 PR workflow: zero-job run `41027505694` on `ed3d6f9…` and failed Windows run `41267719541` on `fd0f3fc…` are historical. After the TEMP/TMP setup, checkout-lineage fix, and restoring the post-source allowlist, the current PR event `41286249033` passed all four candidate jobs on exact HEAD `14df1d0…`; full run evidence is in `github-ci-run-412862.json`. Main exact-SHA CI and attestation, repository required-check verification, owner authorization, and release-mode verification remain open. The active V2.2.0 tag ruleset was not changed. P0-5 remains partial, not release-approved.
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

Relevant evidence is under `docs/v2.3/evidence/m0/` through `m6/` and `docs/v2.3/evidence/p0-h/`. The acceptance manifest binds 96 files to source commit `b39f2285f3bc05301d2989d6a66fc1e641af7b96`. The isolated package and rollback record remain explicitly tied to build source `7a78aef…`, with full archive/member/SBOM hashes in P0-H evidence. Current passing PR HEAD is `14df1d05c6397a25cfffd4903d00c9df3f697c61`; exact PR-event runs `41286249061`, `41286249033`, and `41286249199` passed on that SHA. Earlier passing snapshot `9b7b473…` and interim failed snapshot `39de997…` remain separately recorded. The Windows full suite is 662/662 on Node 24.16.0 with runtime Git 2.53.0; on current HEAD, provenance/release-state/doc tests passed 14/14 and acceptance integrity checked 94 files before the two latest snapshots were appended; PR gate returned VALIDATED/NOT_READY, and Release gate correctly rejected with NOT_READY. Details are in `local-resume-validation-14df1d0.json`. The latest hosted matrix covered Node 22/24 on Windows/Ubuntu; Docker and L0 checks passed. The local pinned BusyBox L1 probe also passed as uid 65534 with a read-only sample mount. Remaining blockers are independent human security/license review, OS updater plus second-principal validation, required-check/branch-protection confirmation, exact-main candidate CI and attestation, and explicit maintainer authorization. PR remains Draft; formal release remains NOT_READY; no merge, tag or release is authorized.


## 9. P0-H resume snapshot after source S `66b28af`

The latest remotely verified PR state at the start of this work was OPEN/Draft at HEAD `6b5de2e952b25e5a14877d4179a276be24c9c530`; the three successful PR-event runs recorded earlier apply only to that older SHA. New source commit S is `66b28afdbfb988745662b165460a366074ee9120`. S separates PR, exact-main candidate, and final Release gate modes; the current state is read from the structured P0-H `releaseState` field. Historical NOT_READY wording remains intact. The release gate unit tests passed 10/10, pinned actionlint passed, and typecheck exited 0. The first full suite attempt stopped at the expected stale acceptance manifest because the new S→E evidence manifest had not yet been regenerated; no test failure independent of that stale manifest was observed. Hosted checks for S/E are pending and must be obtained after push.

A reproducible exact-S candidate was built and preserved locally at `dist/armorbreak-portable-2.3.0-66b28af.tar.gz`; 5,851,092 bytes, SHA-256 `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7`. In a clean extraction without development dependencies, an isolated production install supplied TypeScript 5.9.3; capabilities returned 53, JavaScript and TypeScript `source.symbols` completed with 2/2 files, and task/report reads succeeded. The L0 `CrossLanguageSourceReview` workflow completed with its source.symbols step marked DONE; its aggregate `stepsDone=0` inconsistency is explicitly recorded. The exact same archive passed the real isolated Windows V2.2-to-V2.3 package upgrade/rollback drill with preserved task/config/report hashes. The formal V2.2.0 asset was downloaded read-only and hash-verified.

The updated npm dry run contains 677 files and zero `tests/`, M3 fixture or binary executable paths. The original 11 fixture files and their existing hashes remain unchanged in repository evidence. See the exact file inventory and package manifest/SBOM in `evidence/p0-h/`.

P0-H remains `IN_PROGRESS`; release readiness remains `NOT_READY`. Open blockers: independent human security/license review; a real second Windows principal test; maintainer confirmation whether OS-integrated updater support is part of V2.3; exact hosted PR checks for S/E; authorized branch-protection/required-check verification; exact-main CI and provenance; production artifact/SBOM/attestation and trust keys; explicit maintainer release authorization. PR #25 remains Draft. No merge, v2.3.0 tag, or release was performed. Historical CI failures and V2.2.0 assets remain unchanged.


## 10. P0-H source-S2 packaging and evidence refresh

Source S1 `66b28af…` was not pushed. Review and hosted-CI claims now use amended source S2 `5fdedae913da44f9ca6a2988e99583fef2127641`; S2 includes a scoped npm exclusion for the inventory JSON (avoids a self-referential size/hash) and test candidate archive. S2 candidate content remains reproducible at SHA-256 `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7`; exact S2 package build, clean-room runtime, and real isolated rollback evidence are in `evidence/p0-h/*5fdedae*`. The prior S1 records remain historical.

The exact S2 candidate was clean-room extracted with no `node_modules`; the pinned production install produced TypeScript 5.9.3. `capabilities` returned 53 entries, JS/TS `source.symbols` completed 2/2 files with 6 symbols and 3 same-file references, and an L0 `CrossLanguageSourceReview` ran to COMPLETED with its source.symbols step DONE. MCP task and report reads succeeded in the same session. The workflow aggregate reported `stepsDone=0` despite the persisted step/report being DONE; this inconsistency remains disclosed. The real Windows package drill passed using this SHA and isolated test data; task/config/report hashes matched after rollback.

The S2 npm dry run will be bound in the regenerated evidence manifest and lists 675 files, excluding tests, all 11 M3 fixtures, binaries, npm inventory JSON self-reference and candidate archive. The source fixtures and original historical dry-run hashes remain intact.

The S2 acceptance manifest and local test rerun are in progress; hosted PR-event CI has not yet run on S2. PR #25 remains Draft and NOT_READY. Independent human security/license review, second Windows principal, maintainer updater-scope decision, branch protection/required-check confirmation, exact-main CI/provenance, production SBOM/attestation/trust, and explicit maintainer authorization remain open.


## 11. Current P0-H source S3 candidate

Source S1 `66b28af…` and S2 `5fdedae…` were not pushed; their local records are retained as historical. Current exact source S3 is `8140c62f50565a319ba43bfd2a44621777d281ed`. It contains the final gate contract changes and the npm exclusions needed to keep fixtures, inventory/acceptance-manifest self-reference and candidate tar out of npm. The exact S3 candidate archive at `dist/armorbreak-portable-2.3.0-8140c62.tar.gz` is 5,851,092 bytes, SHA-256 `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7`. It was rebuilt, reproducible, clean-room extracted without development dependencies, and installed only its declared TypeScript 5.9.3 production dependency. Capabilities=53; `source.symbols` completed JS/TS 2/2; the L0 CrossLanguageSourceReview completed with its source.symbols step DONE; MCP task/report reads succeeded in the same session. The workflow aggregate `stepsDone=0` mismatch is explicitly recorded. The same exact-S3 archive completed the isolated real Windows V2.2-to-V2.3 package upgrade and rollback drill; task/config/report hashes matched. The official V2.2.0 asset was downloaded read-only and hash-verified.

The exact-S3 `npm pack --dry-run --json` inventory lists 636 files (8,312,971 unpacked bytes; dry-run output SHA-256 `0e4d1b2d3405000be6c877740195ee5eb2caf07eb4fb6bb50025c49f23955f3c`). It contains zero test paths, M3 fixture paths, binary files, npm inventory self-reference, acceptance-manifest self-reference or candidate archives. Full member/path/size/mode rows are in `evidence/p0-h/npm-package-8140c62.json`; the 11 original repository fixture hashes remain in the historical `npm-package-dry-run.json`.

A clean S3 source-only full-suite run produced 664/665: the release-build test passed; the only failure was the PR gate rejecting the pre-S3 S→E manifest and source/evidence mismatch, which is expected before an evidence commit. This is not final validation and will be rerun on a clean evidence commit after regenerating the manifest. The first dirty checkout run (also 664/665) is retained as an environment/working-tree diagnostic and is not counted as a passing suite. Hosted exact-S3 PR checks have not run. Release remains `NOT_READY`; Draft status is preserved. Open blockers: independent human security/license review, second Windows principal, maintainer decision on OS updater scope, exact S3 PR-event CI, branch protection verification, exact-main CI and provenance, production SBOM/attestation/trusted keys, and maintainer authorization. No merge, v2.3.0 tag or release was performed.

## 12. Evidence commit E1 — exact-head CI results

Source S remains `8140c62f50565a319ba43bfd2a44621777d281ed`; evidence commit E1 and current PR #25 HEAD is `3f61c939c816473515e3ad457d50ab0e1136e230`. PR #25 is OPEN / Draft. GitHub reports three successful pull_request workflows on this exact E1 SHA:

- Inherited CI run [41290136931](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41290136931): Windows Node 24, Ubuntu Node 24, L0 offline boundary, real Docker L1 integration succeeded; release-evidence job was skipped by its event condition.
- V2.3 exact-head validation run [41290136914](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41290136914): evidence integrity, Node 22/24 on Windows and Ubuntu, and benign L1 container-path verification succeeded.
- V2.3 main/release gate workflow run [41290136915](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41290136915): PR-candidate matrix jobs succeeded. Main-candidate build/provenance and Release verification jobs were skipped because this was a pull_request event; they have not been validated on main or a tag.

The full test suite and typecheck ran successfully in these exact-head hosted jobs. A separate local clean-worktree `npm test` was interrupted during the user-requested pause; its partial log is not treated as a local pass. The earlier S-only local run is a historical 664/665 diagnostic caused by validating the source snapshot before its S→E manifest existed; it is not evidence against the exact E1 CI result.

P0-H remains `IN_PROGRESS`; structured release readiness remains `NOT_READY`. Remaining blockers: independent human security and license review; real second Windows principal isolation and ACL recovery; maintainer decision on OS-integrated updater support; branch-protection/required-check owner confirmation; exact-main candidate build/provenance; production artifact/SBOM/attestation and trusted key custody; explicit maintainer release authorization. No merge, V2.3 tag, or release was performed.

## 13. Evidence commit E2 — current verified PR-event workflows

Evidence commit E2 and PR #25 HEAD at this CI capture: `97498e3334dea770c39e6fc6cfd7e4d1ee3d1662` (OPEN / Draft). All three PR-event workflows completed successfully on this exact SHA:

- [Inherited CI `41321124390`](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41321124390): Windows Node 24, Ubuntu Node 24, L0 static boundary and Docker L1 jobs passed; release-evidence job skipped by event condition.
- [V2.3 exact-head validation `41321124400`](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41321124400): evidence integrity, Node 22 and Node 24 on Windows and Ubuntu, and benign L1 container verification passed.
- [V2.3 main and release gate `41321124442`](https://github.com/LYL-Z/dsh-armorbreak/actions/runs/41321124442): all four PR-candidate Node/OS matrix jobs passed; main candidate build/provenance and tag Release verification were skipped as designed on pull_request.

These hosted jobs ran the complete test suite and typecheck on their respective matrices. The local Windows test process was interrupted during the pause; no local full-suite pass is claimed. E2's evidence manifest validated 121 files against source S. This next evidence-only commit records E2's runs; it does not change the release source or candidate package.

Release remains `NOT_READY`. Unclosed blockers remain independent human security/license review, second Windows principal/ACL recovery verification, maintainer decision on OS-updater support, branch-protection/required-check confirmation, exact-main build/provenance and production artifact/SBOM/attestation trust, and explicit maintainer release authorization. PR stays Draft; no merge/tag/release occurred.
