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
input data. Configuration previews omit guessable input/value/name digests as well as raw values.
The CSRF token is available to ANY local HTTP client, including another OS user.
It is NOT authentication. The startup workspace must contain only data suitable
for this shared local surface. Do not attach production secrets, L2 capabilities,
host writers or approval callbacks. The Core engine independently rejects non-L0
analysis; exact allowlisted operations and workspace checks remain enforced.
A second unauthenticated HTTP connection is tested, but an actual second Windows
account remains NOT_TESTED; these are not equivalent tests. No remote binding is permitted.

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

## Current browser verification

`scripts/native-panel-browser-e2e.mjs` drives real headless Chromium against
the running HTTP server: tab selection, form input/submission, Core task and
evidence response, confidential preview rendering, scope-denial rendering and
button recovery. Supply ARMORBREAK_PLAYWRIGHT_MODULE pointing at an existing
Playwright index.mjs; the script never downloads dependencies. This optional
browser test is not part of inherited GitHub CI. The current implementation run
passed on Chromium 156.0.8078.4. Native desktop helper initialization failed and
its log is retained. A second Windows account and DSH embedding remain NOT_TESTED.
