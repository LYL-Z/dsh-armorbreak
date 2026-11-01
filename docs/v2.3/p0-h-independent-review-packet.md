# P0-H independent security review packet

Status: prepared for an independent reviewer; **not an independent audit**. The implementation agent authored this packet. No reviewer has accepted it and no AI output is represented as human certification. Release remains `NOT_READY`.

## Scope and materials

Review the exact source SHA `b39f2285f3bc05301d2989d6a66fc1e641af7b96` named by the V2.3 acceptance manifest, then inspect the evidence-only commits through PR HEAD `9b7b473beb996610ac17a745f92a3a28534442e7` separately. The three PR-event workflows passed on that PR HEAD: exact-head `41270050323`, V2.3 main/release gate `41270050295`, and inherited CI `41270050351`. Compare source S to frozen M0 baseline `66ec0017af4b9d636f09e45f7cf55eed060512ac`; inspect the S-to-evidence diff and verify it contains only permitted evidence/documentation paths. The real package drill is bound to test candidate source `7a78aef15e59f16f71b192089dcb82a81e811fb5`; it is not the final main/tag package. Do not infer safety from this packet, test pass counts, or README statements. The review should cover:

1. Untrusted archives, archive entry count/expanded-size limits, path normalization, absolute paths, traversal, duplicate names, hard links/symlinks, reparse points, and extraction root containment.
2. Archive read/write TOCTOU, directory replacement races, handle-relative APIs and fallback behavior on Windows and Linux.
3. JS/TS parser behavior on malformed, deeply nested, oversized, and adversarial syntax; AST traversal caps; dynamic imports, comments/strings, Unicode identifiers, and source-map claims.
4. Ghidra/JDK invocation: executable and project path trust, argument construction, temp/output boundaries, timeout, child environment, exit status, output size, cancellation, and symlink/reparse races.
5. Secret/credential redaction across reports, errors, command arguments, URLs, environment variables, MCP audit logs, and nested JSON.
6. MCP stdio/HTTP identities: authentication defaults, principal binding, session ownership, origin/host rules, approval boundaries, fixed workflow IDs, L0 ceiling, tool arguments, audit records, and denial behavior.
7. Behavior-comparison input provenance: who creates precomputed outcomes, path/schema/size validation, stale/forged records, source/binary hash binding, and whether language-specific comparator statements overclaim equivalence.
8. Evidence integrity: source/evidence commit ancestry, post-source allowlist, symlink/path traversal, old-SHA reuse, manifest generation, validator/workflow self-protection, report consistency, cryptographic signatures, GitHub check-run identity, and actual attestation subject/source verification.
9. Dependency/build/package contents and all license/NOTICE obligations, including excluded tests, fixtures and optional external tools.

## Source and command set

Run from a fresh checkout of the exact PR HEAD. Record OS/build, architecture, source S and evidence E Git SHAs, Node/npm/Python/Ghidra/JDK/Zig versions, command line, start/end time, exit code, and raw logs. Do not run target binaries. Commands:

```powershell
git status --short --branch
git rev-parse HEAD
git diff --stat 66ec0017af4b9d636f09e45f7cf55eed060512ac..b39f2285f3bc05301d2989d6a66fc1e641af7b96
git diff --name-status b39f2285f3bc05301d2989d6a66fc1e641af7b96..HEAD
npm ci --no-audit --no-fund
node --test --test-concurrency=1
npm run typecheck
node scripts/v2/validate-v23-acceptance.mjs
node scripts/v2/check-docs-consistency.mjs
node scripts/v2/v23-release-gate.mjs --check-pr
node scripts/v2/build-release.mjs --out dist --evidence dist/release-build.json --no-portable-evidence
node scripts/v2/v23-real-package-drill.mjs
```

Focused boundary tests and source map:

- Archive/path and migration: `tests/program-intelligence-artifact.test.mjs`, `tests/path-boundary.test.mjs`, `tests/migration-path-boundary.test.mjs`, `tests/migration-faults.test.mjs`, `tests/migration-v2.test.mjs`, `tests/safe-evidence-file.test.mjs`.
- JS/TS parsing: `tests/program-intelligence-source.test.mjs`, `lib/analyzers/source/manifest.js`, `lib/analyzers/source/symbols.js`.
- External process: `tests/binary.test.mjs`, `tests/native-program-ir-fixtures.test.mjs`, `tests/external-adapters.test.mjs`, `packages/core/src/externalTools.js`, `lib/analyzers/binary/programIr.js`, `scripts/ghidra/ExportSummary.java`.
- Redaction: `tests/evidence-redaction.test.mjs`, `lib/evidence/redact.js`.
- MCP identity/authority: `tests/mcp-http-auth-default.test.mjs`, `tests/mcp-http-origin-authority.test.mjs`, `tests/mcp-server.test.mjs`, `tests/approval-authority.test.mjs`, `packages/mcp-server/`.
- Behavior comparator: `tests/rebuild.test.mjs`, `lib/analyzers/rebuild/manifest.js`.
- Manifest and provenance: `tests/v23-provenance.test.mjs`, `tests/v23-release-gate.test.mjs`, `scripts/v2/validate-v23-acceptance.mjs`, `scripts/v2/v23-provenance.mjs`, `scripts/v2/v23-release-gate.mjs`.

The command list is a reproducibility starting point; it is not evidence that an independent reviewer ran these commands. The reviewer should add targeted adversarial cases and report both accepted and rejected inputs.

## Current developer-observed findings and disposition

This is a developer-prepared triage list, not an independent confirmation. The reviewer must reproduce, reject, or amend every item against the final commit.

| ID | Severity | Observation | Fix / retest evidence | Remaining independent work |
|---|---|---|---|---|
| D-01 | P1 | Release gate formerly required `P0-H=IN_PROGRESS` and report `NOT_READY` even in release mode | Split PR and release contracts; transition tests in `tests/v23-release-gate.test.mjs` | Reviewer must inspect alternative states and workflow caller behavior |
| D-02 | P1 | Authorization record was designed to compare its embedded commit with its containing tagged commit, creating self-reference | Detached signed claims bind source `S` and evidence/tag commit `E`; protocol in `release-provenance-protocol.md`; local temporary-commit/signature exercise required | Reviewer must verify trusted-key provisioning, canonicalization, revocation and GitHub attestation policies |
| D-03 | P1 | Release readiness could be asserted by JSON `status: PASS` strings | Gate now requires reviewer/maintainer signatures, recomputed hashes, live GitHub CI lookup, and live `gh attestation verify` | Must test with real independent keys, exact-main run, candidate package and genuine GitHub attestation |
| D-04 | P1 | Historical run `41027505694` at `ed3d6f9…` failed before creating a job; actionlint reproduced the malformed workflow scalar. Run `41267019541` at `fd0f3fc…` created jobs but both Windows matrices failed. | Source commit `b39f228…` sets runner-local TEMP/TMP in the V2.3 main gate and full checkout history in inherited CI; actionlint passes. Actual PR-event runs `41270050295`, `41270050323`, and `41270050351` all pass on PR HEAD `9b7b473…`, including Node 22/24 Windows/Ubuntu. Evidence: `evidence/p0-h/github-ci-run-412700.json` and the GitHub run URLs in acceptance-report §8. | The old zero-job root cause remains an actionlint reproduction because GitHub returned no logs. Main-only candidate/attestation and tag jobs intentionally did not run on a Draft PR; verify branch protections and exact-main CI separately. |
| D-05 | P1 | The previous rollback record used synthetic data and installer-state transitions; it did not exercise a package. | Real Windows drill passed on source snapshot `7a78aef15e59f16f71b192089dcb82a81e811fb5`, archive SHA-256 `cb9e9edef5fd677adbdee97e521f09a457505bee805db319719c206c579590fc`, complete member manifest and SBOM evidence. It downloaded the published V2.2.0 asset read-only, created isolated test task/report/config data, extracted and started the candidate, verified CLI history reads, MCP initialization/session/principal isolation, current-user ACLs, workspace denial, injected corruption, selected V2.2 for rollback, and matched task/config/report hashes. Evidence: `evidence/p0-h/real-package-upgrade-rollback.json`, `candidate-package-7a78aef.json`, and linked manifest/SBOM. | This used isolated test data, not user data; deployment was archive extraction, not an OS installer/updater. Independent reviewer should reproduce and inspect the redacted record and exact artifact/SBOM. |
| D-06 | P2 | Preliminary review is same-agent AI-authored and cannot certify human independence | This packet preserves that distinction | Independent reviewer identity, signed findings and retest remain open |
| D-07 | P2 | Optional binary/tool redistribution conditions are not established by package metadata alone. The observed 551-file archive includes no executable/library/archive binary or test fixture; the TypeScript 5.9.3 dependency is declared but not bundled. | Updated `p0-h-license-inventory.md` records current archive/SBOM/member-manifest hashes, package and npm boundaries, optional tool adapters, and missing nested package license declarations. | Reviewer must confirm first-party provenance, MIT scope/notices, exact external-tool obligations, TypeScript/npm redistribution, and inspect the final exact-main artifact. |

## Required reviewer return record

The independent reviewer should save a signed report containing reviewer identity and organization, independence/conflict statement, exact source and evidence SHAs, package and SBOM SHA-256, tools/versions/method, paths and commands inspected, findings with severity and reproducible steps, rejected/accepted cases, fixed commit IDs, retest result, residual risks, and explicit conclusion. The report must not say “certified” unless the reviewer is legally entitled and authorized to make that claim. The release gate accepts only the configured independent reviewer trust keys; repository authors cannot self-assign that trust identity.
