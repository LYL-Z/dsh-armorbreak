# Live Core Workbench panel (Draft)

Partial PC-SETTINGS-009. Stacked on local-plugin PR #43. Independent extension
of the existing ArmorBreak Workbench, informed by Community settings/diagnostic
inventory at 411f98c676e5ff5f400df78316c9bd056416a46d. No upstream UI code,
assets or red-team settings are copied. It is a local web panel, not a DSH
embedded panel or a claim of live host integration.

    node workbench/server.mjs --port 8799 --workspace ABS_WORKSPACE --state-root ABS_ISOLATED_STATE

Open http://127.0.0.1:8799 and select Native Core. Supply the explicit file or
directory for host.health, configuration.preview, maintenance.plan or
plugin.verify. These are the existing Core L0 implementations and return actual
task IDs, data and evidence IDs. No second task store, policy engine, privileged
executor or approval endpoint is introduced. Without both startup paths the
native panel is disabled; historical acceptance views remain available.

The server fixes the principal and workspace at launch, rejects caller
principal/approval/apply/options injection and limits concurrent work to one
request. Loopback and exact Host/Origin checks, a per-process random session
token, strict request schema, 4096-byte body bound, CSP and no-store responses
protect the local UI surface. Tokens are not persisted. Target authorization
is exclusively the Core's responsibility. Error responses omit raw paths and
input data. Preview outputs contain hashes, not raw configuration values.
The local OS account and local processes remain trusted; this token is not a
multiuser authentication system. No remote binding is permitted.

Archived compatibility/provider/readiness records are explicitly historical;
they are not current process observations. UNKNOWN/UNVERIFIED/NOT_TESTED do not
receive a success badge. Requested plugin enablement does not load code. Host
modification and approval/rollback execution are unavailable from this UI.

Six actual HTTP regression tests (including two existing Workbench tests) cover
Core data and evidence persistence, unchanged inputs, workspace escape, origin,
token/session restart boundaries, malformed/oversized requests, privilege
injection and disabled state. Browser/desktop automation could not initialize
in this environment (kernel assets path missing); actual click/visual
acceptance remains NOT_TESTED. No live DSH host or production data was used.
