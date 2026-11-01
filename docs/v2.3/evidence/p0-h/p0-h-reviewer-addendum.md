# P0-H reviewer addendum: evidence-bound review instructions

Status: developer-prepared material for an independent reviewer. This is not an audit, certification, or release approval; no AI-authored review is represented as independent or human work.

## Commit selection

Resolve `sourceCommit` and `baselineSha` from `acceptance-manifest.json` at the time of review. The source snapshot is the code under review; compare it with the frozen V2.2 baseline. Separately inspect the source-to-evidence commit range at the current PR head. Reject any post-source path outside `scripts/v2/v23-provenance.mjs`'s evidence-only allowlist. Use the live PR HEAD and exact PR-event runs; do not treat this addendum's historical run IDs as current evidence.

An earlier successful snapshot was PR HEAD `9b7b473beb996610ac17a745f92a3a28534442e7` (runs `41270050323`, `41270050295`, `41270050351`). Interim evidence commit `39de997c0732953d7462a4b44e4ecd0f549402c0` failed PR CI because a change to `docs/v2.3/p0-h-independent-review-packet.md` escaped the evidence-only allowlist. The failure record is `github-ci-run-412859.json`. The corrective commit restored that packet path; current passing PR HEAD at this addendum revision is `14df1d05c6397a25cfffd4903d00c9df3f697c61` (runs `41286249061`, `41286249033`, `41286249199`), recorded in `github-ci-run-412862.json`. A reviewer must still verify live HEAD and current checks independently.

## Required review scope

1. Untrusted archive limits and path handling, traversal, absolute paths, duplicate entries, links/reparse points, extraction boundaries, and TOCTOU behavior on Windows and Linux.
2. JavaScript/TypeScript parsing under malformed, deeply nested, oversized, and adversarial syntax; AST limits; dynamic imports; comment/string handling; and claims about source maps or cross-file semantics.
3. Ghidra/JDK process trust, argument construction, temp/output boundaries, timeout, environment, exit handling, output limits, cancellation, and link/reparse races.
4. Redaction across credentials, tokens, host paths, Unicode edge cases, logs, and generated reports.
5. MCP initialization and routes, trusted principal selection, task/session ownership, authorization propagation, and permission boundaries.
6. Behavior-comparator caller-supplied evidence, schemas, certainty labels, and limits on equivalence claims.
7. Evidence hash inventory, Git lineage, allowlist negative tests, CI self-validation, workflow triggers, and source/evidence separation.
8. Dependency, fixture, and binary/tool licensing and redistribution. In particular, inspect `p0-h-license-inventory.md`, npm pack dry-run evidence, the 11 M3 fixture paths (including two executable fixtures), Ghidra/JDK/Zig/TypeScript source and notice obligations, final package members, and final SBOM. Do not infer legal permission from package metadata alone.

## Reproduction entry points

Run from a clean checkout of the manifest source and its exact evidence descendant:

- `node scripts/v2/validate-v23-acceptance.mjs`
- `node --test tests/v23-provenance.test.mjs tests/v23-release-gate.test.mjs tests/docs-consistency.test.mjs`
- `node scripts/v2/v23-release-gate.mjs --check-pr`
- `node scripts/v2/v23-release-gate.mjs --release` (must fail closed while any required evidence is absent)
- `actionlint .github/workflows/ci.yml .github/workflows/v2.3-main-gate.yml`

For package review, inspect and reproduce the exact archive, complete member manifest, and SBOM hashes in `candidate-package-*.json`; the recorded package drill uses isolated copied test data and is not a formal installer or user-profile migration test. Do not use production user data or the V2.2.0 installation for destructive reproduction.

## Finding and retest record

The reviewer must independently record reviewer identity and role, date, reviewed source/evidence SHAs, tools and versions, exact commands, input fixture hashes, findings with severity and impact, repair commits, and exact-SHA retest outcomes. Obtain the reviewer's own signed statement through an authorized external process. Until then, P0-3 remains BLOCKED.
