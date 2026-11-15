# Maintenance preflight (Draft)

Stacked on configuration PR #41. Partial PC-TRANSACTION-007 and
PC-COMMUNITY-OP-89121dc9; no complete host updater or backup equivalence claimed.

Independent implementation of explicit source-hash planning, informed by
kingcharleslzy-ai/dsh-purge@411f98c676e5ff5f400df78316c9bd056416a46d
lib/backup.js and lib/update.js. These upstream sources are not imported or
executed; uncertain redistribution rights remain NOT_IMPORTED. The existing
ArmorBreak TransactionalInstaller and ApprovalAuthority are reused in isolated
regression fixtures, not replaced by another package manager.

In an authorized workspace directory, create armorbreak-maintenance.json:

    {"schema":"armorbreak.maintenance-request/v1","operation":"update","files":[{"path":"config.json","expectedSha256":"ACTUAL_SOURCE_SHA256","candidateSha256":"PROPOSED_CONTENT_SHA256"}]}

Use 64 lowercase hex characters for both hashes. Operations are backup, update
or uninstall-check. One to 64 explicit relative source files are accepted;
duplicate case-insensitive paths, traversal, ADS, reserved names and extra hooks
are rejected. Inputs and each file are limited to 1 MiB. Core reads every file
within the authorized directory and rejects junctions escaping it.

    node packages/cli/index.js maintenance plan --root ABS_DIRECTORY --json

MCP: armorbreak_analyze with capability maintenance.plan and target ABS_DIRECTORY.
ARMORBREAK_STATE_ROOT / ARMORBREAK_WORKSPACE and the normal principal are required.
The same Core policy, task, evidence, audit and report chain applies. No options
can enable writes. Output is PREFLIGHT_ONLY, executable=false; paths are hashed
in the report. The plan is deterministic for the same complete bytes.

No backup, download, network request, host update, uninstall or host rollback is
performed. A separately reviewed, target-scoped L2 executor, durable verified
backup, revalidation at commit time and real host/platform testing are still
required. A read-only preflight is not a safe write authorization or a TOCTOU
guarantee for a future executor.

Tests: node --test tests/maintenance-preflight.test.mjs. Includes actual Core,
independent CLI, generic MCP, drift/unsafe path/junction refusal, and an inert
fixture using the existing installer: unapproved activation refused, staged
corruption refused, upgrade then byte-exact active-pointer rollback. It never
touches a real DSH installation. The initial fixture lacked component commit and
digest; that failure is preserved and the fixture now satisfies the unchanged
supply-chain gate.
