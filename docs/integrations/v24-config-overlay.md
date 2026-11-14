# Native configuration layers (Draft)

Stacked on host-health PR #40. Partial PO-PROMPT-002 and
PC-COMMUNITY-OP-6d1861f9; no complete upstream equivalence claimed.

Independent implementation informed by the feature inventory and fixed research
snapshots: mmparko/dsh-purge@033e6bd1e0f101352b39075ecd0d758ffef26b76
lib/rules.js and presets/; kingcharleslzy-ai/dsh-purge@411f98c676e5ff5f400df78316c9bd056416a46d
lib/preset-diagnostic.js and lib/redteam/settings.js. No prompt, preset payload,
upstream source or UI copied. Unresolved upstream rights remain NOT_IMPORTED.

Create a local JSON data bundle in an authorized workspace:

    {"schema":"armorbreak.config-overlay/v1","base":{"future":true,"enabled":true},"profiles":[{"id":"readonly","values":{"enabled":false}}],"selectedProfile":"readonly","overlays":[],"conflictPolicy":"reject"}

Call with configured ARMORBREAK_STATE_ROOT / ARMORBREAK_WORKSPACE:

    node packages/cli/index.js config preview --bundle ABS_BUNDLE --json

Or call MCP armorbreak_config_preview({bundle: ABS_BUNDLE}), or the existing
armorbreak_analyze tool with capability configuration.preview. All paths use
the sole Core L0 policy, task/report and audit chain. No apply endpoint exists.

Object layers recursively merge, arrays replace, explicit false/empty/null values
survive, unknown fields survive. Duplicate layer IDs and unsafe prototype keys
are refused. Conflict policy defaults to reject; explicit last-wins resolves the
preview, not write approval. Unselected profiles do not execute. Template strings
remain opaque data. No configuration value grants permissions to Core.

The in-memory resolveConfig API returns the effective configuration. CLI/MCP and
persisted reports expose only call-local field/layer ordinals, operations and conflict counts. They omit raw values, field names, caller labels and all secret-derived input/config/value digests. Core suppresses targetSha256 for this sensitive-input capability. Structure and equality/change information remain observable; this is not a zero-leakage encrypted UI.
snapshotConfig/restoreConfigSnapshot are private in-memory data APIs, never exported as preview evidence. They provide deterministic JSON serialization
and integrity-checked in-memory restoration; they do not write host files or
provide encrypted backups. Native data-only JSON/YAML/Cordis/Purge conversion is
documented in `../v2.4/configuration-format-lifecycle.md`. A separate trusted-host
module composes JSON/YAML preview with approved fresh synthetic transactions;
see `../v2.4/synthetic-maintenance.md`. Real host application, profile persistence
UI and real-host compatibility remain unimplemented or unverified.

Tests: node --test tests/config-overlay.test.mjs (8 tests). The initial missing
traceId fixture failure and corrected run are preserved in external evidence.
