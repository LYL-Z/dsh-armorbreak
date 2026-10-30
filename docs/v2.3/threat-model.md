# V2.3 threat model and verification boundary

## Scope

This model covers the M1–M6 implementation (historical M6 source SHA `965fbe4fa9abd2af73644865a56d8db64c8a6089`), P0-H evidence/provenance changes through source SHA `bf7d3d4d590d7ba2cc7d53edf548b1afc78687fd`, and the surrounding existing V2.2 execution policy. Exact PR checks `41026010595` and `41026010642` tested PR SHA `c1c109453b12493b3ae9b8a76be4f271a820f835` and passed their reported jobs. They validated the then-committed 74-file evidence bundle; the current local report/evidence tree has 76 files and awaits fresh exact-head CI. The source evidence commit remains `bf7d3d4…`. Earlier checks on `0795c4dd270f59cb60a006c756035da111e1d970` are historical. The dedicated main-gate run `41026002895` at the current SHA failed with zero jobs, so that gate has not passed. This model supplements, and does not replace, repository `SECURITY.md` or an independent security review. The accompanying pre-review at `evidence/p0-h/security-license-review-preliminary.json` is by the implementation agent, explicitly non-independent and non-human. CI and local tests do not constitute a penetration test, hostile-sample sandbox certification, or human audit.

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
| Sensitive values or host paths in reports | M4 redacts credential-shaped strings and replaces absolute paths with opaque identifiers; source documents are summarized/hashed rather than copied | M4 redaction regression tests and exact-SHA evidence | Broader secret corpus, Unicode/path edge cases, and independent review remain outstanding |
| Unsupported features presented as complete | Capability status contract includes support, engine, backend, status, reason and limitations; catalog state is `REGISTERED_NOT_EXECUTED` | M6 API/CLI/MCP tests | User-facing claims still require release-document review and exact-SHA CI |
| Evidence tampering or stale evidence | V2.3 validator/workflows/security gates cannot change in an evidence-only append; a code change needs a newer source commit and manifest regeneration | 4/4 provenance tests passed locally; run `41026010595` checked 74 files at PR head `c1c1094…`; the updated 76-file tree passes locally and awaits fresh CI | Local tests and CI are not an independent audit or Stable gate; preserve source-to-evidence lineage when the report-only head advances |
| V2.2 release assumptions applied to V2.3 | Separate V2.3 main/tag workflow; release mode requires exact `v2.3.0`, explicit independent-human evidence, exact-main CI, artifact/SBOM/attestation and owner authorization | Main-gate code and local fail-closed tests exist; the V2.2 `v2.2.0` protection ruleset is active and unchanged | Dedicated run `41026002895` failed with zero jobs on `c1c1094…`; no successful main-gate PR run or exact-main CI; branch protection API returned 403 |

## Risk-level behavior

- **L0:** bounded read-only analysis. New V2.3 analyzer routes are registered as L0 and must continue through Engine/Core policy.
- **L1:** code that may execute in a container requires a reachable, freshly verified isolation provider and explicit per-target approval. A past harmless container probe is not current readiness. Current CLI check reports the daemon missing.
- **L2:** network access needs scoped target authorization, per-run approval, DNS/IP/redirect validation, and request bounds. V2.3 does not add a remote workflow.
- **L3:** automatically executing destructive or unauthorized actions remains refused.

## Required follow-up before any Stable publication

1. **PR-head CI:** current exact PR head at report capture is `c1c109453b12493b3ae9b8a76be4f271a820f835`. V2.3 run `41026010595` and inherited CI run `41026010642` passed; duplicate push runs `41026004259` and `41026004165` also passed. Historical runs on `0795c4dd…` remain historical. Exact-main CI remains pending because the PR is unmerged.
2. Fresh authorization, rejection, cancellation, timeout, redaction, archive-boundary and old-report compatibility checks on the exact candidate.
3. The local Docker daemon is still unreachable. Hosted CI passed benign L1 fixtures; analyze no hostile sample without a separately authorized safe fixture and per-task approval.
4. Independent human security and license review; the current AI pre-review is not a substitute. Resolve exact tool/fixture redistribution inventory before packaging.
5. Complete a real owner package/profile upgrade and rollback exercise. The recorded local installer drill used synthetic data and an inert synthetic artifact only.
6. Obtain a successful dedicated V2.3 main-gate PR run (current run `41026002895` failed with zero jobs), verify branch protection with an authorized read path, and then require exact-main CI, package/SBOM/attestation before any release decision. No formal tag or publication is authorized by this task.
