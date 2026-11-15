# Desktop host health (Draft)

Depends on PR #39 at 4750380249e4cf0e3bee36a263f39598b744fe16, itself stacked on #32.
This independently written increment addresses part of PC-HOST-DIAG-006 and
PC-COMMUNITY-OP-21f962bb. Neither broad feature is fully migrated.

Functional research sources: mmparko/dsh-purge@033e6bd1e0f101352b39075ecd0d758ffef26b76
lib/surface.js; kingcharleslzy-ai/dsh-purge@411f98c676e5ff5f400df78316c9bd056416a46d
lib/host-layout.js, lib/next-host.js, lib/preset-diagnostic.js. No source, prompts,
UI bundles or third-party dependencies are imported; upstream redistribution rights
remain separate from this implementation's MIT license. No behavioral equivalence
to a complete upstream diagnostic suite is asserted.

Set ARMORBREAK_STATE_ROOT to an isolated state directory and ARMORBREAK_WORKSPACE
to the explicitly authorized installation copy or fixture root. Then call:

    node packages/cli/index.js host health --resources ABS_RESOURCES --expected-version 1.2.3 --json

The equivalent MCP tool is armorbreak_host_health({resources, expectedVersion?});
armorbreak_analyze({capability: "host.health", target: ABS_RESOURCES}) and the
existing SDK use the same Core registry, workspace policy, task store, evidence,
report, principal and session isolation. Analyze responses now include bounded
capability data in addition to existing task/report references.

Expected version is a caller requirement, not an approved compatibility list.
Disk inspection can produce DETECTED_ON_DISK or UNKNOWN. PROCESS_OBSERVED,
RUNTIME_VERIFIED and FEATURE_VERIFIED are never inferred. ASAR-only installations
remain UNKNOWN; no code is executed, no process is scanned and no host is modified.
The old host layout / inspect CLI commands remain legacy standalone diagnostics;
they are not claimed as Core-integrated endpoints by this increment.

Tests: node --test tests/dsh-runtime-layout.test.mjs tests/host-health.test.mjs.
Windows junction and Linux symlink checks are actual filesystem fixtures, not
real DSH host acceptance. The local initial symbolic-link privilege failures
are preserved in the external evidence package. Existing release evidence is
unchanged; ordinary feature CI may still fail frozen release validation until
the separately reviewed CI migration is authorized and integrated.
