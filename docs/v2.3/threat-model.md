This model covers historical M1–M6 and the current P0-H source S3 `8140c62f50565a319ba43bfd2a44621777d281ed`. The last remotely verified PR HEAD before S3 was `6b5de2e952b25e5a14877d4179a276be24c9c530`; earlier successful PR checks do not prove S3. S3 separates PR, main-candidate and final-release contracts and records release state structurally. The exact-S3 portable package, npm inventory, real isolated rollback and clean-room parser/workflow evidence are recorded under `evidence/p0-h/`. This is developer-prepared evidence, not an independent human audit, legal opinion, or release authorization. P0-H is `IN_PROGRESS`, release state `NOT_READY`, and no formal tag or publication is authorized.

## Scope

This model covers M1–M6 (historical M6 source `965fbe4fa9abd2af73644865a56d8db64c8a6089`), P0-H gate/workflow/provenance updates through source commit `b39f2285f3bc05301d2989d6a66fc1e641af7b96`, and the existing V2.2 execution policy. At evidence capture, PR #25 is OPEN/Draft at exact HEAD `14df1d05c6397a25cfffd4903d00c9df3f697c61`. All three actual PR-event workflows passed on that SHA (runs `41286249061`, `41286249033`, `41286249199`); job-level details are in `evidence/p0-h/github-ci-run-412862.json`. The interim evidence commit `39de997…` failed because a reviewer-packet change escaped the post-source allowlist; that failed result and its correction are recorded separately in `github-ci-run-412859.json`. Earlier successful snapshot `9b7b473…` and failures at `fd0f3fc…` remain historical. The workflow changes isolate runner TEMP/TMP and fetch full history for lineage checks. This model supplements but does not replace `SECURITY.md` or an independent audit. The pre-review and reviewer materials are developer-prepared, not independent or human certification. P0-3 remains open until an independent reviewer accepts the exact final source and artifacts.

## Assets and trust boundaries

- User workspace files, task state, raw evidence, reports, credentials and personal data.
- Authorization scope, principal identity, approvals, risk level and the policy decision that gates execution.
- Analyzer outputs and external-tool binaries, versions, stdout/stderr and temporary files.
- MCP/CLI request fields and workflow definitions.
- Evidence lineage, fixture hashes and commit-bound test records.

Target files, archives, parser text, source comments, documentation, SARIF/SBOM records, imported findings, and model-generated plans are untrusted. They cannot provide instructions, principal identity, approval, or new execution authority.

## Threat decisions

| Threat | Existing/added control | Current evidence | Residual status |
|---|---|---|---|
| Path traversal and hostile archive members | M1 bounded archive inventory; no disk extraction | Current local full suite includes malformed/path/link/resource cases; see current exact-source test record | Targeted local coverage only; broad 30 normal/10 hostile matrix and cross-platform hostile-input proof remain incomplete |
| Malformed, oversized or deeply nested input | Explicit byte/item/depth/output budgets and structured partial/failure results | M1–M5 boundary tests and schemas | Hostile parser fuzzing and resource exhaustion campaigns not run |
| Prompt injection in source/comments/evidence | Inputs are parsed as data; M5/M6 do not accept caller commands, approval, principal, or custom workflow steps | M2 no-execution sentinel, M6 MCP rejection tests | Independent adversarial review not run |
| Unauthorized local sample execution | New M1–M4 capabilities are L0 static; M5 only compares precomputed results; M6 MCP start ceiling is L0 | Exact-head run `41286249061` passed on `14df1d0…`; pinned BusyBox probe ran locally as uid 65534 with a read-only mount; no target sample was executed | Benign probe does not certify hostile-sample isolation |
| Unauthorized remote request or approval spoofing | No new L2 route; existing PolicyGateway remains in path; fixed MCP route does not accept model-supplied approvals | Existing policy tests and M6 negative tests | Full adversarial cross-host approval/session matrix not rerun for V2.3 |
| Tool output or supply-chain substitution | Tool adapter bounds and existing release pin/provenance controls | M3 real Ghidra 12.1.4 local runs; V2.2 supply-chain gates are separate | Independent binary/toolchain audit and V2.3 artifact attestation not done |
| Sensitive values or host paths in reports | M4 redacts credential-shaped strings and replaces absolute paths with opaque identifiers; the isolated deployment record now redacts local profile/scratch names while retaining normalized ACL records and output hashes | M4 regression tests; `real-package-upgrade-rollback.json` redaction note and SHA-256 values | Broader secret corpus, Unicode/path edge cases, and independent review remain outstanding |
| Unsupported features presented as complete | Capability status contract includes support, engine, backend, status, reason and limitations; catalog state is `REGISTERED_NOT_EXECUTED` | M6 API/CLI/MCP tests | User-facing claims still require release-document review and exact-SHA CI |
| Evidence tampering or stale evidence | V2.3 validator/workflows/security gates cannot change in an evidence-only append; code changes require a newer source commit and regenerated manifest | Negative cases cover validator/workflow/gate tampering, allowlist widening, stale source SHA, and malformed SHA; current manifest binds source `b39f228…`; exact evidence HEAD `14df1d0…` passed GitHub integrity validation | This does not prove a real GitHub build attestation or independent review |
| V2.2 release assumptions applied to V2.3 | Separate V2.3 PR, main and tag jobs; Release mode requires exact `v2.3.0`, external independent-human signatures, exact-main CI, artifact/SBOM/attestation and explicit maintainer authorization | Pinned actionlint step and corrected PR workflow passed run `41286249033`; `v2.2.0` protection was read as active and unchanged | No exact-main run. Branch-protection API returned 403. Owner bypass on the V2.2 ruleset remains enabled |

## Risk-level behavior

- **L0:** bounded read-only analysis. New V2.3 analyzer routes are registered as L0 and must continue through Engine/Core policy.
- **L1:** code that may execute in a container requires a reachable, freshly verified isolation provider and explicit per-target approval. Current local benign Docker probe passed, but hostile-sample isolation is not certified.
- **L2:** network access needs scoped target authorization, per-run approval, DNS/IP/redirect validation, and request bounds. V2.3 does not add a remote workflow.
- **L3:** automatically executing destructive or unauthorized actions remains refused.

## Required follow-up before any Stable publication

1. **PR-head CI:** at evidence capture, exact PR HEAD `14df1d05c6397a25cfffd4903d00c9df3f697c61` passed exact-head validation `41286249061`, dedicated V2.3 gate `41286249033`, and inherited CI `41286249199`. These successful PR-event runs close the interim evidence-path CI failure at `39de997…`. Re-run after any later source change; exact-main CI remains pending because the PR is unmerged.
2. Fresh authorization, rejection, cancellation, timeout, redaction, archive-boundary and old-report compatibility checks on the exact candidate.
3. The local Docker daemon is reachable again: `evidence/p0-h/local-docker-l1-e02e7fe.json` records a real pinned BusyBox benign run as uid 65534 with a read-only sample mount. This does not establish hostile-sample isolation; do not analyze hostile samples without separately authorized safe fixtures and per-task approval.
4. Independent human security and license review; the developer packet and candidate inventory are not substitutes. Review final package/SBOM and npm dependency distribution separately.
5. The isolated real V2.2-to-V2.3 portable-package drill passed on candidate source `7a78aef…` (archive SHA-256 `cb9e9edef5fd677adbdee97e521f09a457505bee805db319719c206c579590fc`) for copied test data, including rollback hashes, ACL and MCP/session boundaries. It does not verify a shipped OS updater, a second Windows identity, or arbitrary user profiles.
6. **Branch protection and main/release provenance remain open:** the standard and dedicated V2.3 PR-event checks passed on exact HEAD `14df1d0…`. Verify repository required-check settings through an authorized path; the prior API query returned 403. Exact-main CI, external authorization signatures, package/SBOM/attestation bound to the actual main commit, and explicit maintainer authorization remain required. The `v2.2.0` ruleset was not modified and still allows owner bypass. No formal tag/publication is authorized.


## Current candidate security evidence and residual gaps

- Source S changed the V2.3 PR/main/release state contracts and npm packaging rules; validator and workflow were included in S rather than treated as post-source evidence. PR and main candidate modes are separate; main binds exact SHA and does not demand future release evidence; Release mode requires structured READY and the external signed authorization and evidence checks.
- Exact-S artifact SHA-256 `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7` was clean-room extracted and tested after separately installing TypeScript 5.9.3. JavaScript/TypeScript symbol analysis completed on 2/2 sample files. The L0 `CrossLanguageSourceReview` workflow completed and its `source.symbols` step is DONE, although aggregate `stepsDone` reported 0; this mismatch is not counted as a successful aggregate metric.
- A real isolated Windows package deployment/rollback used the exact S archive and synthetic V2.2-format data from the unchanged published package. It passed task/report reads, configuration and ACL checks, failure injection, and rollback hash comparison. It does not test a second Windows logon or an OS-integrated updater.
- The current npm dry run is 677 files and excludes test paths, all 11 M3 fixtures and binary executables; historical fixture hashes and repository test provenance remain preserved. The separate npm package inventory and installed TypeScript dependency graph still require independent license review.
- Remaining security boundaries: independent human review, second-principal isolation, maintainer decision on OS updater support scope, current exact-S hosted PR checks, repository branch-protection/required-check verification, exact-main build/provenance, production attestation/trust keys and maintainer release authorization.


## S2 candidate security observations

- The new exact-source archive SHA-256 is `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7`. Clean-room extraction plus separate TypeScript 5.9.3 install executed 53 capabilities and parsed both JS and TS inputs. CrossLanguageSourceReview completed with its one L0 source.symbols step marked DONE; the returned aggregate `stepsDone=0` mismatch is recorded and not treated as a successful metric.
- The real isolated Windows V2.2-to-V2.3 upgrade/rollback was repeated with this exact archive. It used synthetic V2.2-format task/report/config produced by the published V2.2.0 package; rollback hashes matched. It did not touch a formal installation or user profile.
- npm dry-run file rules exclude the 11 M3 fixtures, test tree, binary test formats, npm inventory self-reference and candidate tar archive. The repo fixtures remain preserved. The clean npm inventory and installed TypeScript dependency graph need independent license review.
- Still unverified: independent human security/license review; a true second Windows logon and private-task denial; whether OS-integrated update is an advertised V2.3 requirement; exact S2 hosted PR checks; repository branch protection/required-check settings; exact-main provenance, production attestation/trust and maintainer release authorization.


## S3 candidate security observations

- The exact-S3 candidate archive is SHA-256 `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7`; clean-room extraction plus separate TypeScript 5.9.3 installation executed 53 registered capabilities and parsed JS and TS inputs. CrossLanguageSourceReview completed and its source.symbols step is DONE; aggregate `stepsDone=0` is inconsistent and remains disclosed.
- The real isolated Windows V2.2-to-V2.3 deployment and rollback used this exact candidate and isolated V2.2-format data; hashes matched. It does not establish second-account ACL isolation or OS updater functionality.
- npm dry run excludes 11 M3 fixtures, tests, binary files, generated inventory/manifest self-reference and the candidate tar. The test fixtures remain in source evidence.
- Independent human review, second Windows principal, maintainer support-scope decision for an OS updater, exact hosted PR checks, branch protection, exact-main provenance/attestation/trust and maintainer authorization remain open.
