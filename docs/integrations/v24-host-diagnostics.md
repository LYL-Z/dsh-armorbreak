# Composite host disk diagnostics (Draft)

Partial PC-HOST-DIAG-006 / PC-COMMUNITY-OP-21f962bb. Stacked on Workbench PR #44.
Reuses PR #32 profile/anchor inspectors and the new Core health/config/plugin
implementations. No upstream diagnostic or patch execution is imported.
Research references: mmparko/dsh-purge@033e6bd1e0f101352b39075ecd0d758ffef26b76
and Community@411f98c676e5ff5f400df78316c9bd056416a46d, including
lib/host-layout.js and lib/preset-diagnostic.js. Native implementation is original.

Create armorbreak-host-diagnostics.json inside a single authorized directory:

    {"schema":"armorbreak.host-diagnostics-request/v1","resources":"resources","expectedVersion":"1.2.3","profile":"web","anchors":{"target":"host.js","spec":"anchors.json"},"configurationBundle":"config.json"}

resources is required. expectedVersion, profile, anchors, configurationBundle
and pluginRoot are optional. Each path is a strict relative path inside the
Core-selected directory. profile is a validated profile name under profiles/.
anchors.json uses the existing armorbreak.anchor-spec/v1 literal-count schema.
The configuration and plugin formats are described in the other v2.4 documents.

    node packages/cli/index.js host diagnostics --root ABS_DIRECTORY --json

MCP armorbreak_analyze {capability:"host.diagnostics", target:ABS_DIRECTORY},
or the Workbench Native Core panel, uses the same capability. Every content
read is authorized by the single Core reader. The old standalone inspectors
remain backward-compatible read-only APIs; this new composite entry has tasks,
reports, audit and principal/workspace boundaries.

Output omits raw paths, configuration values and source/anchor snippets. Counts
matching expectations never authorize a patch. Disk/profile/configuration
observations are distinct from process/runtime/feature, which remain UNKNOWN.
Missing profile, version mismatch, anchor drift and configuration conflicts
produce REVIEW_REQUIRED with bounded recovery guidance. Missing optional checks
are NOT_REQUESTED. No active probe, model session, network call, process scan,
host write or automatic recovery occurs. No real DSH compatibility is claimed.

The existing standalone file readers now allocate a bounded buffer before reads,
rather than allowing an unbounded read of a concurrently growing file. Core
callbacks retain their workspace checks; no arbitrary executable hook exists.

Tests: four new composite tests plus eight legacy inspector/anchor tests pass.
They exercise real filesystem fixtures, Core reports, generic MCP, independent
CLI, secret redaction, conflicts, invalid UTF-8, path traversal and junction
refusal. Actual host/version/platform acceptance is separate and still pending.
