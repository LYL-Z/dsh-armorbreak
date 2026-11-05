# Independent security and license review handoff — source S

Status: developer-prepared review material only. No independent reviewer has completed this review. This document is not an audit, certification, or legal opinion. Release remains `NOT_READY`.

## Exact review objects

- Repository: `LYL-Z/dsh-armorbreak`, PR #25, source commit S: `5fdedae913da44f9ca6a2988e99583fef2127641`.
- Frozen baseline: `66ec0017af4b9d636f09e45f7cf55eed060512ac`.
- Review the source diff with `git diff --name-status 66ec0017af4b9d636f09e45f7cf55eed060512ac..5fdedae913da44f9ca6a2988e99583fef2127641`.
- The evidence commit E is generated after S and recorded by the GitHub PR/manifest history; review the actual PR head and acceptance manifest before starting. The evidence manifest does not include itself, avoiding a self-hash.
- Portable candidate: local test archive at `dist/armorbreak-portable-2.3.0-5fdedae.tar.gz` (not part of npm distribution), documented by `portable-cleanroom-5fdedae.json`; artifact SHA-256 `b038df453eb4ee1683679fb2173dcd7787e7358ba614ee1b8a1cf134d92a43c7`; 5,851,092 bytes; source S. Archive has no node_modules and requires the documented production dependency installation.
- npm dry run: `npm-package-5fdedae.json`; 675 listed package files, 0 test files, 0 M3 fixture paths, and no executable/binary fixture extensions. The JSON records all path/size/mode rows and the dry-run output digest. Reproduce from S with `npm pack --dry-run --json`.

## Required methods and scope

Use a fresh checkout of S, no developer `node_modules`, and a separate evidence checkout for E. Record operating system/build, architecture, Git/Node/npm and tool versions, commands, exit codes, raw outputs, and SHA-256. Run the commands in `p0-h-independent-review-packet.md`, replacing obsolete candidate assumptions with the exact object hashes above. Also run:

```powershell
node --test --test-concurrency=1
npm run typecheck
npm pack --dry-run --json
node scripts/v2/validate-v23-acceptance.mjs
node scripts/v2/v23-release-gate.mjs --check-pr
```

Inspect archive extraction against traversal, duplicate entries, hard links, symlinks/reparse points, TOCTOU and size/count limits; JS/TS parser resource caps and malformed/deep inputs; Ghidra/JDK executable, arguments, environment, timeout and output bounds; credential redaction; MCP authentication, trusted principal/session/workspace ownership and approval rules; caller-supplied behavior-comparison provenance; and evidence/workflow self-verification, signatures and exact-source binding. Do not execute included test samples as programs.

## Distribution and license objects

- Portable archive: only the exact archive SHA above and its generated complete member manifest/SBOM from the test candidate. No `node_modules`, native analysis tool, or M3 fixture is in the archive.
- npm package: package name/version `dsh-armorbreak@2.3.0`, path inventory in `npm-package-5fdedae.json`; source rules are `package.json` plus `docs/v2.3/evidence/m3/fixtures/.npmignore`. Confirm excluded fixtures remain in the repository and are absent from the package.
- TypeScript `5.9.3` is a runtime dependency installed separately after extracting the portable archive; its upstream package declares Apache-2.0. Review the exact lock graph and notices for the npm distribution path.
- Root source declares MIT and includes `LICENSE` and `NOTICE`. Nested first-party package manifests have incomplete license metadata and require provenance/scope review.
- Ghidra, JDK, Zig, TShark/Wireshark, JADX, Syft, Semgrep and Trivy are adapters or optional external tools; they are not bundled in the candidate. Review exact upstream versions, terms and third-party notices if the product later distributes any of them. Repository binary fixtures are test-only, excluded from the portable and npm packages; their source/generation and license provenance still require reviewer inspection.

## Developer-prepared risk register (not independent findings)

| ID | Severity | Area | Current state / evidence | Required reviewer disposition |
|---|---|---|---|---|
| D-01 | P1 | PR/main/release state contracts | S separates PR, exact-main candidate and final release modes; tests cover transition and exact SHA. | Reproduce all three contracts and missing-claim fail-closed behavior; inspect workflow callers. |
| D-02 | P1 | Evidence and CI integrity | Provenance tests cover validator/workflow tampering, allowlist expansion and stale SHA; new S binds the gate/workflow changes. | Inspect source-to-evidence ancestry, source allowlist and exact GitHub check identities. |
| D-03 | P1 | Portable TS dependency | Clean-room run installed TypeScript 5.9.3 outside the worktree; JS and TS `source.symbols` completed. | Confirm the new installation contract is clear and npm dependency notices are complete. |
| D-04 | P1 | Principal/session/workspace boundary | Prior package drill covers one principal and session boundaries; this turn did not perform a second Windows logon. | Conduct a real second-account test and verify private evidence denial, session non-transfer and ACL-preserving rollback. |
| D-05 | P1 | Upgrade/rollback | Prior real archive deployment drill is tied to an earlier candidate source/archive; it is not evidence for S's rebuilt artifact. | Re-run the deployment drill using the exact S archive before considering closure. |
| D-06 | P1 | Independent security/license review | No external human reviewer has signed or accepted this handoff. | Reviewer records identity, independence/conflicts, exact SHA, method, severity, fixes and retest; never substitute AI self-review. |
| D-07 | P1 | Maintainer/release controls | No exact-main run, final tag artifact/SBOM attestation, trusted external signatures, branch protection confirmation, or maintainer release authorization is claimed here. | Verify via repository controls and exact objects; maintain NOT_READY until all are real. |
| D-08 | P2 | Workflow aggregate status | In clean-room `CrossLanguageSourceReview`, task state was COMPLETED and the `source.symbols` step was DONE, but returned aggregate `stepsDone` was 0. | Reproduce and determine whether this counter is advisory or indicates a result accounting defect; do not cite it as a completed-step count. |

## Known unverified boundaries

Second Windows principal isolation and ACL rollback, OS-integrated updater support scope, independent human security review, independent license conclusion, exact-main CI/provenance, final release artifact/SBOM and GitHub attestation, trusted reviewer/maintainer key custody, and maintainer release authorization remain unverified. Do not mark any of them PASS based on this packet.
