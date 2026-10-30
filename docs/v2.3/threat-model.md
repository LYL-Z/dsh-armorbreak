# V2.3 threat model and verification boundary

## Scope

This model covers the M1–M6 implementation at source SHA `965fbe4fa9abd2af73644865a56d8db64c8a6089` and the surrounding existing V2.2 execution policy. It supplements, and does not replace, the repository `SECURITY.md` or an independent security review. Local tests and the benign Docker probe do not constitute a penetration test, hostile-sample sandbox certification, or human audit.

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
| Path traversal and hostile archive members | M1 bounded archive inventory; no disk extraction | M1 exact-source tests and fixture catalog | Targeted local coverage only; broad 30 normal/10 hostile matrix and cross-platform proof remain incomplete |
| Malformed, oversized or deeply nested input | Explicit byte/item/depth/output budgets and structured partial/failure results | M1–M5 boundary tests and schemas | Hostile parser fuzzing and resource exhaustion campaigns not run |
| Prompt injection in source/comments/evidence | Inputs are parsed as data; M5/M6 do not accept caller commands, approval, principal, or custom workflow steps | M2 no-execution sentinel, M6 MCP rejection tests | Independent adversarial review not run |
| Unauthorized local sample execution | New M1–M4 capabilities are L0 static; M5 only compares precomputed results; M6 MCP start ceiling is L0 | Exact-SHA tests and MCP route tests | Docker daemon is currently unavailable; no current L1 isolation claim |
| Unauthorized remote request or approval spoofing | No new L2 route; existing PolicyGateway remains in path; fixed MCP route does not accept model-supplied approvals | Existing policy tests and M6 negative tests | Full adversarial cross-host approval/session matrix not rerun for V2.3 |
| Tool output or supply-chain substitution | Tool adapter bounds and existing release pin/provenance controls | M3 real Ghidra 12.1.4 local runs; V2.2 supply-chain gates are separate | Independent binary/toolchain audit and V2.3 artifact attestation not done |
| Sensitive values or host paths in reports | M4 redacts credential-shaped strings and replaces absolute paths with opaque identifiers; source documents are summarized/hashed rather than copied | M4 redaction regression tests and exact-SHA evidence | Broader secret corpus, Unicode/path edge cases, and independent review remain outstanding |
| Unsupported features presented as complete | Capability status contract includes support, engine, backend, status, reason and limitations; catalog state is `REGISTERED_NOT_EXECUTED` | M6 API/CLI/MCP tests | User-facing claims still require release-document review and exact-SHA CI |
| Evidence tampering or stale evidence | Existing V2.2 evidence validator binds hashes and commit lineage; V2.3 records retain source SHA and fixture hashes | M0–M6 per-stage JSON and logs | V2.2 acceptance manifest cannot validate the new source lineage; separate V2.3 evidence integrity check and exact-head CI are still required |

## Risk-level behavior

- **L0:** bounded read-only analysis. New V2.3 analyzer routes are registered as L0 and must continue through Engine/Core policy.
- **L1:** code that may execute in a container requires a reachable, freshly verified isolation provider and explicit per-target approval. A past harmless container probe is not current readiness. Current CLI check reports the daemon missing.
- **L2:** network access needs scoped target authorization, per-run approval, DNS/IP/redirect validation, and request bounds. V2.3 does not add a remote workflow.
- **L3:** automatically executing destructive or unauthorized actions remains refused.

## Required follow-up before any Stable publication

1. Exact-commit CI on Windows and Ubuntu/Linux with Node 22 and 24; collect the actual run URLs and statuses.
2. Fresh authorization, rejection, cancellation, timeout, redaction, archive-boundary and old-report compatibility checks on the exact candidate.
3. Current L1 Docker evidence only if the daemon is reachable; analyze no hostile sample without a separately authorized safe fixture and per-task approval.
4. Independent security review, dependency/license review, exact-SHA release artifacts, SBOM and attestation.
5. Reproducible upgrade/rollback exercise and owner review. No formal tag or publication is authorized by this task.
