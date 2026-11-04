# V2.3.0 release review policy

Effective 2026-11-04 for PR #25, the repository owner has explicitly selected **Owner-Approved Self-Reviewed Release**. This supersedes V2.3-only contract text that required an independent human security and license reviewer. It does not modify V2.2.0 policy, Tag, Release, or assets.

## Roles and assurance

- Security and license review are performed by the implementation agent and recorded as `IMPLEMENTER_AI_SELF_REVIEW`.
- `Independent human review = NOT_PERFORMED`. No report, key, signature, credential, or test is presented as belonging to an independent reviewer.
- The owner accepts the additional residual risk of release without independent human review. The signed-in GitHub owner event for the exact protected `v2.3.0` tag is used as the platform-recorded release authorization event. It is not a cryptographic proof of a human's physical action or an Ed25519 owner signature.
- The review remains evidence-driven: source and package SHA binding, test logs, risk findings, license sources, CI checks, package/SBOM hashes, real rollback evidence, and GitHub OIDC attestation remain mandatory.

## Supported release boundary

V2.3.0 Stable supports the verified core, bounded program-intelligence routes documented in the compatibility matrix, and Portable/manual or npm installation. It does not include an OS-integrated updater. The HTTP MCP server is a single-principal service per process; multi-principal service mode is rejected. Shared OS accounts, shared state directories, and cross-account isolation are outside the supported deployment contract.

Ghidra-backed analysis invokes an external native parser over untrusted binaries. It is classified L1 and requires the existing per-task trusted approval path. This does not sandbox Ghidra; users should run it only on data and hosts they are authorized to analyze.

The product is not a universal decompiler or program-cracking system. Source symbol analysis is bounded to local JavaScript/TypeScript structure; behavior comparison evaluates supplied finite cases; other languages and semantic completeness are not implied.

## Release decision contract

PR and main source trees keep structured `releaseState: NOT_READY`, allowing historical reports to remain intact and avoiding edits after the exact-main build. Main requires P0-H candidate engineering evidence marked `COMPLETE`, exact SHA CI, and the candidate build/provenance path. The exact `v2.3.0` tag workflow may emit external `READY` only after it verifies the owner event, exact-main run and package attestation, self-review/license reports, and a Windows deployment/rollback against the exact main package. The detached envelope is OIDC-attested by the pinned V2.3 workflow; it is not committed into the tree whose SHA it references.

No Stable claim is made by passing PR or main candidate checks. The release must remain `NOT_READY` if any required evidence is missing or mismatched.
