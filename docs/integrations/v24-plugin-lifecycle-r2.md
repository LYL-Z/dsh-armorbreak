# Plugin lifecycle R2: closure, scoped attestations and inert staging

`plugin verify --root ABS --closure --json` and generic MCP
`armorbreak_analyze(capability="plugin.verify", options={closure:true})` check
the complete bounded package file set. Use a dedicated package directory inside
the authorized workspace: targeting the workspace itself includes Core's own
`.armorbreak` output and will fail closure verification. The default listed-file
review remains available and retains its explicitly narrower status.

Strict Core inventory includes hidden files and normally skipped dependency or
build directories. Unknown files, case/path ownership collisions, symbolic links,
junctions, read failures, cancellation and entry/depth limits fail closed.
All declared payload hashes and manifest identity are reread and checked. This
is a repeated-read snapshot, not an atomic filesystem freeze or a writable
installation authorization. Closure results include the data-only catalog so
downstream reviewers can recompute metadata and policy rather than trust copied
boolean fields.

Trusted host code imports `createPluginReviewer` and
`pluginAttestationPayload` from `lib/catalog/pluginLifecycle.js`. Public keys,
repository allowlists and separate source/rights roles are supplied by trusted
host configuration. Keys in candidate catalogs or receipt objects cannot become
trust roots. Ed25519 assertions bind closure, canonical manifest, repository,
commit, package ID/version and license claim. Rights receipts are explicitly
scoped to review and synthetic staging. They do not grant production install,
activation or redistribution. A signature authenticates an attester assertion;
independent legal ownership and repository-server verification remain separate.
There are no production keys or receipt-issuing UI/MCP endpoints in this change.

Trusted host code imports `planSyntheticPluginUpdate` from
`packages/core/src/syntheticPlugin.js` and passes Core-bounded directory inputs,
the configured reviewer, receipts, operator and session. It verifies closure,
captures at most 64 KiB of inert encoded bundle data, and creates a fresh random
lab. Its returned `lab.apply(plan.planId, trustedApprovalProvider)` and
`lab.rollback(...)` use the existing single-use Core approval and journal path.
Both operations require separate approvals. No caller-selected destination is
accepted. This stages an encoded bundle in `packages.txt`; it neither extracts
nor loads plugin code. Restart recovery uses the existing sealed lab manifest
and `reopenSyntheticMaintenance`; no new automatic lease expiry or repair is
introduced. Windows power-loss durability remains unverified.

Tests exercise real Core/MCP, a separate CLI process, persisted JSON artifact,
hidden/build/dependency files, missing files, links, excess depth, forged keys,
modified identity/policy, separate receipts, denial, dependency order, approved
staging, injected failure and exact-byte rollback. Test signing keys are ephemeral
and memory-only. Real DSH activation, update downloads/proxies, repository API
authentication, full upstream updater equivalence and macOS are NOT_TESTED.

Feature references: `PO-CLI-001`, `PC-TRANSACTION-007`, `PC-UPDATE-008`.
Only a native local integrity and synthetic staging subset of the updater family
is implemented. No feature is promoted to INTEGRATED_VERIFIED.
Upstream behavioral reference: community `lib/update-integrity.js` at
`411f98c676e5ff5f400df78316c9bd056416a46d`, complete-file-set and per-file
integrity checks. ArmorBreak is an original bounded SHA-256 implementation with
pinned scoped attestations; it does not import or execute that updater.
