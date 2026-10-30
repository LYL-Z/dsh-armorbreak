# P0-H independent security review packet

Status: prepared for an independent reviewer; **not an independent audit**. The implementation agent authored this packet. No reviewer has accepted it and no AI output is represented as human certification. Release remains `NOT_READY`.

## Scope and materials

Review the exact PR source SHA and final evidence SHA named in the V2.3 acceptance manifest. Compare the source commit to frozen M0 baseline `66ec0017af4b9d636f09e45f7cf55eed060512ac`; inspect the final source-to-evidence diff separately. Do not infer safety from this packet, test pass counts, or README statements. The review should cover:

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

Run from a fresh checkout of the exact PR HEAD. Record OS/build, architecture, Git SHA, Node/npm/Python/Ghidra/JDK/Zig versions, command line, start/end time, exit code, and raw logs. Do not run target binaries. Commands:

```powershell
git status --short --branch
git rev-parse HEAD
git diff --stat 66ec0017af4b9d636f09e45f7cf55eed060512ac..HEAD
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

- Archive/path and migration: `tests/archive-inventory.test.mjs`, `tests/old-data-migration.test.mjs`, `tests/migration-*`, `tests/safe-evidence-file.test.mjs`.
- JS/TS parsing: `tests/js-ts-analysis.test.mjs`, `packages/core/src/sourceAnalysis.js`.
- External process: `tests/external-tools.test.mjs`, `tests/native-program-ir.test.mjs`, `packages/core/src/externalTools.js`.
- Redaction: `tests/redaction.test.mjs`, `lib/evidence/redact.js`.
- MCP identity/authority: `tests/mcp-http-auth-default.test.mjs`, `tests/mcp-http-origin-authority.test.mjs`, `tests/mcp-server.test.mjs`, `tests/approval-authority.test.mjs`, `packages/mcp-server/`.
- Behavior comparator: `tests/behavior-compare.test.mjs`, `packages/core/src/behaviorCompare.js`.
- Manifest and provenance: `tests/v23-provenance.test.mjs`, `tests/v23-release-gate.test.mjs`, `scripts/v2/validate-v23-acceptance.mjs`, `scripts/v2/v23-provenance.mjs`, `scripts/v2/v23-release-gate.mjs`.

The command list is a reproducibility starting point; it is not evidence that an independent reviewer ran these commands. The reviewer should add targeted adversarial cases and report both accepted and rejected inputs.

## Current developer-observed findings and disposition

This is a developer-prepared triage list, not an independent confirmation. The reviewer must reproduce, reject, or amend every item against the final commit.

| ID | Severity | Observation | Fix / retest evidence | Remaining independent work |
|---|---|---|---|---|
| D-01 | P1 | Release gate formerly required `P0-H=IN_PROGRESS` and report `NOT_READY` even in release mode | Split PR and release contracts; transition tests in `tests/v23-release-gate.test.mjs` | Reviewer must inspect alternative states and workflow caller behavior |
| D-02 | P1 | Authorization record was designed to compare its embedded commit with its containing tagged commit, creating self-reference | Detached signed claims bind source `S` and evidence/tag commit `E`; protocol in `release-provenance-protocol.md`; local temporary-commit/signature exercise required | Reviewer must verify trusted-key provisioning, canonicalization, revocation and GitHub attestation policies |
| D-03 | P1 | Release readiness could be asserted by JSON `status: PASS` strings | Gate now requires reviewer/maintainer signatures, recomputed hashes, live GitHub CI lookup, and live `gh attestation verify` | Must test with real independent keys, exact-main run, candidate package and genuine GitHub attestation |
| D-04 | P1 | Dedicated workflow produced zero-job failures and its PR workflow was not successfully rerun at current HEAD | Workflow event contracts and job predicates are being separated; current zero-job run evidence is `evidence/p0-h/v23-main-gate-ci-attempt.json` | Root cause is not yet proven; actionlint and successful exact-head PR event remain required |
| D-05 | P1 | Existing rollback evidence uses synthetic task/report/config and installer state transitions; it is not a package deployment | A separate real candidate package drill is required; existing evidence remains unchanged and is not promoted | Complete Windows ACL/principal/workspace, MCP startup, data read, fault injection and byte-exact rollback observations |
| D-06 | P2 | Preliminary review is same-agent AI-authored and cannot certify human independence | This packet preserves that distinction | Independent reviewer identity, signed findings and retest remain open |
| D-07 | P2 | Optional binary/tool redistribution conditions are not established by package metadata alone | See `p0-h-license-inventory.md` | Reviewer must check vendor license texts/notices and final built artifact contents |

## Required reviewer return record

The independent reviewer should save a signed report containing reviewer identity and organization, independence/conflict statement, exact source and evidence SHAs, package and SBOM SHA-256, tools/versions/method, paths and commands inspected, findings with severity and reproducible steps, rejected/accepted cases, fixed commit IDs, retest result, residual risks, and explicit conclusion. The report must not say “certified” unless the reviewer is legally entitled and authorized to make that claim. The release gate accepts only the configured independent reviewer trust keys; repository authors cannot self-assign that trust identity.
