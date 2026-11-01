# V2.3 threat model and verification boundary

## Scope

This model covers M1–M6 (historical M6 source `965fbe4fa9abd2af73644865a56d8db64c8a6089`), the P0-H gate/workflow/provenance updates through local source `2cb8a3de102870fc54056ace75688cdfd5594bd0`, and the existing V2.2 execution policy. At this snapshot the local source/evidence update was not yet pushed; the last live PR read showed PR #25 open/Draft at `ed3d6f9c0b3c171f74482cf78ed1bcfbc9ec0d07`. Passing runs `41027514948` (V2.3 exact-head validation) and `41027514842` (inherited CI) cover only that older remote SHA. Dedicated run `41027505694` at that SHA is a push/failure with zero jobs. Actionlint 1.7.12 reproduces a YAML syntax error at line 52 in that workflow snapshot; the corrected local workflow passes actionlint, but no successful dedicated PR-event run has yet exercised the fix. GitHub returned no logs for the zero-job run. This model supplements but does not replace `SECURITY.md` or an independent audit. The pre-review and reviewer packet are developer-prepared, not independent or human certification. The portable release candidate excluded binary fixtures, while the separate npm dry run contained the M3 fixture source and native binaries; both distribution paths require independent review. P0-3 remains open until an independent reviewer accepts the exact final source and artifacts.

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
| Unauthorized local sample execution | New M1–M4 capabilities are L0 static; M5 only compares precomputed results; M6 MCP start ceiling is L0 | Current exact PR CI passed at `c1c1094…` in runs `41026010595` and `41026010642`; no target sample was executed | CI fixtures do not certify hostile-sample isolation; local Docker daemon availability remains separate from hosted CI |
| Unauthorized remote request or approval spoofing | No new L2 route; existing PolicyGateway remains in path; fixed MCP route does not accept model-supplied approvals | Existing policy tests and M6 negative tests | Full adversarial cross-host approval/session matrix not rerun for V2.3 |
| Tool output or supply-chain substitution | Tool adapter bounds and existing release pin/provenance controls | M3 real Ghidra 12.1.4 local runs; V2.2 supply-chain gates are separate | Independent binary/toolchain audit and V2.3 artifact attestation not done |
| Sensitive values or host paths in reports | M4 redacts credential-shaped strings and replaces absolute paths with opaque identifiers; the isolated deployment record now redacts local profile/scratch names while retaining normalized ACL records and output hashes | M4 regression tests; `real-package-upgrade-rollback.json` redaction note and SHA-256 values | Broader secret corpus, Unicode/path edge cases, and independent review remain outstanding |
| Unsupported features presented as complete | Capability status contract includes support, engine, backend, status, reason and limitations; catalog state is `REGISTERED_NOT_EXECUTED` | M6 API/CLI/MCP tests | User-facing claims still require release-document review and exact-SHA CI |
| Evidence tampering or stale evidence | V2.3 validator/workflows/security gates cannot change in an evidence-only append; code changes require a newer source commit and regenerated manifest | Negative cases cover validator/workflow/gate tampering, allowlist widening, stale source SHA, and malformed SHA; local S/E/M exercise uses temporary commits and a test-only local tag | Re-run on the final source/evidence pair; this does not prove a real GitHub attestation or independent review |
| V2.2 release assumptions applied to V2.3 | Separate V2.3 PR, main and tag jobs; Release mode requires exact `v2.3.0`, external independent-human signatures, exact-main CI, artifact/SBOM/attestation and explicit maintainer authorization | Current workflow actionlint passes; `v2.2.0` protection was read as active and unchanged | `41027505694` failed with zero jobs; invalid YAML at line 52 is reproducible with actionlint; no successful fixed-workflow PR run or exact-main run yet. Branch-protection API returned 403. Owner bypass on the V2.2 ruleset remains enabled |

## Risk-level behavior

- **L0:** bounded read-only analysis. New V2.3 analyzer routes are registered as L0 and must continue through Engine/Core policy.
- **L1:** code that may execute in a container requires a reachable, freshly verified isolation provider and explicit per-target approval. A past harmless container probe is not current readiness. Current CLI check reports the daemon missing.
- **L2:** network access needs scoped target authorization, per-run approval, DNS/IP/redirect validation, and request bounds. V2.3 does not add a remote workflow.
- **L3:** automatically executing destructive or unauthorized actions remains refused.

## Required follow-up before any Stable publication

1. **PR-head CI:** at this snapshot the remote PR head is still `ed3d6f9c0b3c171f74482cf78ed1bcfbc9ec0d07`; local source `2cb8a3d…` is not yet pushed. Passing exact-head runs at `ed3d6f9…` do not validate local commits. After the push, require standard Windows/Ubuntu Node 22/24 CI and the dedicated V2.3 `pull_request` workflow on the exact pushed head. Exact-main CI remains pending because the PR is unmerged.
2. Fresh authorization, rejection, cancellation, timeout, redaction, archive-boundary and old-report compatibility checks on the exact candidate.
3. The local Docker daemon is still unreachable. Hosted CI passed benign L1 fixtures; analyze no hostile sample without a separately authorized safe fixture and per-task approval.
4. Independent human security and license review; the developer packet and candidate inventory are not substitutes. Review final package/SBOM and npm dependency distribution separately.
5. The isolated real V2.2-to-V2.3 package drill passed for copied test data, including rollback hashes, ACL and MCP/session boundaries. It does not verify a shipped OS updater, a second Windows identity, or arbitrary user profiles.
6. Obtain a successful fixed-workflow dedicated V2.3 PR-event run on exact PR HEAD, then verify branch protection through an authorized path. Exact-main CI, external authorization signatures, package/SBOM/attestation bound to the actual main commit, and explicit maintainer authorization remain required. The `v2.2.0` ruleset was not modified and still allows owner bypass. No formal tag/publication is authorized.
