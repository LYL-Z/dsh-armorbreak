# Native local plugin review (Draft)

Partial PC-MARKET-010 and DECL-PURGE-COMMUNITY-2df8f428. Stacked on maintenance
PR #42. Sources studied, not copied or executed:
kingcharleslzy-ai/dsh-purge@411f98c676e5ff5f400df78316c9bd056416a46d
market/h3-video.json, market/validate.mjs, scripts/build-market.mjs. Original
snapshot remains mmparko/dsh-purge@033e6bd1e0f101352b39075ecd0d758ffef26b76.
No third-party market packages, UI, prompts or dependency payloads are imported.

Create armorbreak-plugin.json in an authorized package directory. Its native
schema is armorbreak.plugin-catalog/v1, with plugins containing id, version,
source {repository, commit}, license, dependencies [{id, version}], permissions,
platforms, channel, enabled and files [{path, sha256}]. Commit must be full
lowercase 40-hex; files use SHA-256. Repository is credential-free HTTPS on
GitHub/GitLab without query, fragment or subpath. Versions and dependencies are
exact versions, not ranges. Channels stable/preview are metadata, never trust.

Permissions: workspace.read (L0), sandbox.execute (L1), host.modify (L2),
credential.attack (L3, always DENIED). A declaration never grants Core rights.
Platforms win32/linux/darwin are requested targets, not platform verification.
enabled is requested state; actual loadedState remains UNKNOWN and executable
is always false. Cycles, missing dependencies, version conflicts, unknown
permissions, install hooks, unsafe paths and case-colliding files are refused.

    node packages/cli/index.js plugin verify --root ABS_DIRECTORY --json

Or use MCP armorbreak_analyze {capability:"plugin.verify", target:ABS_DIRECTORY}.
The single Core policy/audit/evidence/report path authorizes bounded filesystem
reads. Hashes of actual listed files are checked. There is no network fetching,
plugin loading, enable/disable side effect or installation endpoint.

Reuse: existing CatalogCollector canonicalizes source identities without
claiming behavior-equivalent plugins. Existing assessComponent evaluates license
claims, distinct from legal rights. rightsState stays UNVERIFIED_NOT_IMPORTED.
Existing TransactionalInstaller remains the future controlled activation backend.
This report does not establish signature validity, whole-archive closure,
dependency code safety, legal clearance or real-host compatibility. Upstream
format-1 conversion, marketplace publishing, auto-update and runtime lifecycle
are still unimplemented.

Seven regression tests exercise metadata semantics plus actual Core/MCP/CLI
local-file verification, corruption and junction refusal. All inputs are
self-authored inert fixtures; no upstream installer or network test runs.

## Review correction: independent status contracts

metadataShapeValid means parsing and schema validation only. riskClassificationEligible
means the requested risk is not L3; it is not a Core grant. licenseClaimRecognized
is an allowlist check on a self-declaration, not rights verification.
localFilesVerified becomes true only after all listed bytes match. It does not
prove full archive closure. sourceAuthenticated, rightsVerified, policyEligible,
activationAuthorized and releaseEligible remain false. corePolicyState is
NOT_EVALUATED (or DENIED for L3). No caller metadata can set these states.
Diagnostics reports trust-unverified separately from risk-denied. CLI/MCP and UI
render these same Core results. No installer or loader consumes a self-claim as
authorization; no legal rights are granted by these technical checks.
